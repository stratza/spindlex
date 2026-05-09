"""Unit tests for spindlex/transport/channel.py to boost coverage."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import ChannelException
from spindlex.protocol.constants import DEFAULT_WINDOW_SIZE
from spindlex.protocol.utils import write_boolean, write_string, write_uint32
from spindlex.transport.channel import Channel


def _make_channel(
    closed=False, eof_sent=False, remote_id=1, remote_window=65536, remote_max_pkt=32768
):
    transport = MagicMock()
    transport.active = True
    transport._server_mode = False
    transport._server_interface = None
    transport._kex_thread = None
    ch = Channel(transport, 0)
    ch._closed = closed
    ch._eof_sent = eof_sent
    ch._remote_channel_id = remote_id
    ch._remote_window_size = remote_window
    ch._remote_max_packet_size = remote_max_pkt
    ch._local_window_size = DEFAULT_WINDOW_SIZE
    return ch


# ---- Properties ----


class TestChannelProperties:
    def test_closed(self):
        ch = _make_channel(closed=True)
        assert ch.closed is True

    def test_channel_id(self):
        ch = _make_channel()
        assert ch.channel_id == 0

    def test_eof_received(self):
        ch = _make_channel()
        assert ch.eof_received is False
        ch._eof_received = True
        assert ch.eof_received is True

    def test_settimeout_gettimeout(self):
        ch = _make_channel()
        ch.settimeout(5.0)
        assert ch.gettimeout() == 5.0

    def test_get_exit_status_none(self):
        ch = _make_channel()
        assert ch.get_exit_status() == -1

    def test_get_exit_status_set(self):
        ch = _make_channel()
        ch._exit_status = 0
        assert ch.get_exit_status() == 0

    def test_get_exit_signal_none(self):
        ch = _make_channel()
        assert ch.get_exit_signal() is None

    def test_context_manager(self):
        ch = _make_channel()
        with ch:
            pass
        assert ch.closed is True

    def test_shutdown(self):
        ch = _make_channel()
        ch.shutdown(0)
        assert ch.closed is True


# ---- send ----


class TestChannelSend:
    def test_send_empty(self):
        ch = _make_channel()
        assert ch.send(b"") == 0

    def test_send_string(self):
        ch = _make_channel()
        sent = ch.send("hello")
        assert sent == 5
        ch._transport._send_channel_data.assert_called_once()

    def test_send_bytes(self):
        ch = _make_channel()
        sent = ch.send(b"hello")
        assert sent == 5

    def test_send_closed_raises(self):
        ch = _make_channel(closed=True)
        with pytest.raises(ChannelException, match="closed"):
            ch.send(b"data")

    def test_send_eof_sent_raises(self):
        ch = _make_channel(eof_sent=True)
        with pytest.raises(ChannelException, match="EOF already sent"):
            ch.send(b"data")

    def test_send_no_remote_id_raises(self):
        ch = _make_channel()
        ch._remote_channel_id = None
        with pytest.raises(ChannelException, match="not properly opened"):
            ch.send(b"data")

    def test_send_respects_window_size(self):
        ch = _make_channel(remote_window=5)
        sent = ch.send(b"x" * 100)
        assert sent == 5

    def test_send_respects_max_packet(self):
        ch = _make_channel(remote_max_pkt=3)
        sent = ch.send(b"x" * 100)
        assert sent == 3

    def test_send_transport_error(self):
        ch = _make_channel()
        ch._transport._send_channel_data.side_effect = Exception("fail")
        with pytest.raises(ChannelException, match="Failed to send"):
            ch.send(b"data")


# ---- sendall ----


class TestChannelSendall:
    def test_sendall_string(self):
        ch = _make_channel()
        ch.sendall("hello")
        assert ch._transport._send_channel_data.call_count >= 1

    def test_sendall_all_data(self):
        ch = _make_channel(remote_window=100, remote_max_pkt=2)
        ch.sendall(b"abcd")
        # Should have been called multiple times
        assert ch._transport._send_channel_data.call_count == 2


# ---- recv ----


class TestChannelRecv:
    def test_recv_zero(self):
        ch = _make_channel()
        assert ch.recv(0) == b""

    def test_recv_from_buffer(self):
        ch = _make_channel()
        ch._recv_buffer.append(b"hello world")
        data = ch.recv(5)
        assert data == b"hello"
        # Remainder should be in buffer
        assert len(ch._recv_buffer) == 1

    def test_recv_full_chunk(self):
        ch = _make_channel()
        ch._recv_buffer.append(b"hi")
        data = ch.recv(100)
        assert data == b"hi"

    def test_recv_eof(self):
        ch = _make_channel()
        ch._eof_received = True
        assert ch.recv(100) == b""

    def test_recv_transport_inactive(self):
        ch = _make_channel()
        ch._transport.active = False
        assert ch.recv(100) == b""

    def test_recv_timeout(self):
        ch = _make_channel()
        ch._timeout = 0.01
        ch._transport._pump = MagicMock()
        with pytest.raises(ChannelException, match="Timeout"):
            ch.recv(100)


# ---- recv_exactly ----


class TestChannelRecvExactly:
    def test_recv_exactly_success(self):
        ch = _make_channel()
        ch._recv_buffer.append(b"hello")
        ch._recv_buffer.append(b"world")
        data = ch.recv_exactly(10)
        assert data == b"helloworld"

    def test_recv_exactly_closed(self):
        ch = _make_channel()
        ch._eof_received = True
        with pytest.raises(ChannelException, match="Connection closed"):
            ch.recv_exactly(10)


# ---- recv_stderr ----


class TestChannelRecvStderr:
    def test_recv_stderr_zero(self):
        ch = _make_channel()
        assert ch.recv_stderr(0) == b""

    def test_recv_stderr_from_buffer(self):
        ch = _make_channel()
        ch._stderr_buffer.append(b"err data")
        data = ch.recv_stderr(4)
        assert data == b"err "

    def test_recv_stderr_full_chunk(self):
        ch = _make_channel()
        ch._stderr_buffer.append(b"err")
        data = ch.recv_stderr(100)
        assert data == b"err"

    def test_recv_stderr_eof(self):
        ch = _make_channel()
        ch._eof_received = True
        assert ch.recv_stderr(100) == b""

    def test_recv_stderr_closed_raises(self):
        ch = _make_channel(closed=True)
        with pytest.raises(ChannelException, match="closed"):
            ch.recv_stderr(100)


# ---- exec_command ----


class TestChannelExecCommand:
    def test_exec_empty_raises(self):
        ch = _make_channel()
        with pytest.raises(ChannelException, match="empty"):
            ch.exec_command("")

    def test_exec_success(self):
        ch = _make_channel()
        ch._request_success = True
        ch._request_event.set()
        # Patch send_channel_request to set success directly
        with patch.object(ch, "send_channel_request", return_value=True):
            ch.exec_command("ls")

    def test_exec_failure(self):
        ch = _make_channel()
        with patch.object(ch, "send_channel_request", return_value=False):
            with pytest.raises(ChannelException, match="Failed to execute"):
                ch.exec_command("bad")


# ---- invoke_shell ----


class TestChannelInvokeShell:
    def test_invoke_shell_success(self):
        ch = _make_channel()
        with patch.object(ch, "send_channel_request", return_value=True):
            ch.invoke_shell()

    def test_invoke_shell_failure(self):
        ch = _make_channel()
        with patch.object(ch, "send_channel_request", return_value=False):
            with pytest.raises(ChannelException, match="Failed to invoke shell"):
                ch.invoke_shell()


# ---- invoke_subsystem ----


class TestChannelInvokeSubsystem:
    def test_invoke_empty_raises(self):
        ch = _make_channel()
        with pytest.raises(ChannelException, match="empty"):
            ch.invoke_subsystem("")

    def test_invoke_success(self):
        ch = _make_channel()
        with patch.object(ch, "send_channel_request", return_value=True):
            ch.invoke_subsystem("sftp")

    def test_invoke_failure(self):
        ch = _make_channel()
        with patch.object(ch, "send_channel_request", return_value=False):
            with pytest.raises(ChannelException, match="Failed to invoke subsystem"):
                ch.invoke_subsystem("sftp")


# ---- request_pty ----


class TestChannelRequestPty:
    def test_pty_success(self):
        ch = _make_channel()
        with patch.object(ch, "send_channel_request", return_value=True):
            ch.request_pty()

    def test_pty_failure(self):
        ch = _make_channel()
        with patch.object(ch, "send_channel_request", return_value=False):
            with pytest.raises(ChannelException, match="Failed to request PTY"):
                ch.request_pty()


# ---- send_exit_status ----


class TestChannelSendExitStatus:
    def test_send_exit_status(self):
        ch = _make_channel()
        with patch.object(ch, "send_channel_request", return_value=True):
            ch.send_exit_status(0)


# ---- send_channel_request ----


class TestChannelSendChannelRequest:
    def test_closed_raises(self):
        ch = _make_channel(closed=True)
        with pytest.raises(ChannelException, match="closed"):
            ch.send_channel_request("exec")

    def test_no_remote_id_raises(self):
        ch = _make_channel()
        ch._remote_channel_id = None
        with pytest.raises(ChannelException, match="not properly opened"):
            ch.send_channel_request("exec")

    def test_no_reply(self):
        ch = _make_channel()
        result = ch.send_channel_request("exec", want_reply=False, data=b"ls")
        assert result is True

    def test_transport_error(self):
        ch = _make_channel()
        ch._transport._send_channel_request.side_effect = Exception("fail")
        with pytest.raises(ChannelException, match="Failed to send"):
            ch.send_channel_request("exec")


# ---- send_eof ----


class TestChannelSendEof:
    def test_send_eof_closed_raises(self):
        ch = _make_channel(closed=True)
        with pytest.raises(ChannelException, match="closed"):
            ch.send_eof()

    def test_send_eof_already_sent(self):
        ch = _make_channel(eof_sent=True)
        ch.send_eof()  # should just return

    def test_send_eof_no_remote_id(self):
        ch = _make_channel()
        ch._remote_channel_id = None
        with pytest.raises(ChannelException, match="not properly opened"):
            ch.send_eof()

    def test_send_eof_success(self):
        ch = _make_channel()
        ch.send_eof()
        ch._transport._send_channel_eof.assert_called_once()
        assert ch._eof_sent is True

    def test_send_eof_error(self):
        ch = _make_channel()
        ch._transport._send_channel_eof.side_effect = Exception("fail")
        with pytest.raises(ChannelException, match="Failed to send EOF"):
            ch.send_eof()


# ---- Internal handlers ----


class TestChannelHandlers:
    def test_handle_data(self):
        ch = _make_channel()
        ch._handle_data(b"test")
        assert ch._recv_buffer[0] == b"test"

    def test_handle_data_closed_ignored(self):
        ch = _make_channel(closed=True)
        ch._handle_data(b"test")
        assert len(ch._recv_buffer) == 0

    def test_handle_extended_data_stderr(self):
        ch = _make_channel()
        ch._handle_extended_data(1, b"err")
        assert ch._stderr_buffer[0] == b"err"

    def test_handle_extended_data_non_stderr_ignored(self):
        ch = _make_channel()
        ch._handle_extended_data(2, b"other")
        assert len(ch._stderr_buffer) == 0

    def test_handle_eof(self):
        ch = _make_channel()
        ch._handle_eof()
        assert ch._eof_received is True

    def test_handle_close(self):
        ch = _make_channel()
        ch._handle_close()
        assert ch._closed is True

    def test_handle_window_adjust(self):
        ch = _make_channel(remote_window=100)
        ch._handle_window_adjust(50)
        assert ch._remote_window_size == 150

    def test_handle_request_success(self):
        ch = _make_channel()
        ch._handle_request_success()
        assert ch._request_success is True

    def test_handle_request_failure(self):
        ch = _make_channel()
        ch._handle_request_failure()
        assert ch._request_success is False

    def test_handle_exit_status(self):
        ch = _make_channel()
        ch._handle_exit_status(42)
        assert ch._exit_status == 42


# ---- _handle_request ----


class TestHandleRequest:
    def test_exit_status(self):
        ch = _make_channel()
        data = write_uint32(0)
        assert ch._handle_request("exit-status", data) is True
        assert ch._exit_status == 0

    def test_exit_signal(self):
        ch = _make_channel()
        data = write_string("TERM") + write_boolean(False)
        data += write_string("terminated") + write_string("")
        assert ch._handle_request("exit-signal", data) is True
        assert ch._exit_status == 128 + 15

    def test_exit_signal_with_sig_prefix(self):
        ch = _make_channel()
        data = write_string("SIGKILL") + write_boolean(True)
        data += write_string("killed") + write_string("")
        ch._handle_request("exit-signal", data)
        assert ch._exit_status == 128 + 9

    def test_exit_signal_short_data(self):
        ch = _make_channel()
        assert ch._handle_request("exit-signal", b"ab") is True

    def test_unknown_request_not_server(self):
        ch = _make_channel()
        assert ch._handle_request("unknown", b"") is False

    def test_shell_request_server_mode(self):
        ch = _make_channel()
        ch._transport._server_mode = True
        server = MagicMock()
        server.check_channel_shell_request.return_value = True
        ch._transport._server_interface = server
        assert ch._handle_request("shell", b"") is True

    def test_exec_request_server_mode(self):
        ch = _make_channel()
        ch._transport._server_mode = True
        server = MagicMock()
        server.check_channel_exec_request.return_value = True
        ch._transport._server_interface = server
        data = write_string("ls -la")
        assert ch._handle_request("exec", data) is True

    def test_subsystem_request_server_mode(self):
        ch = _make_channel()
        ch._transport._server_mode = True
        server = MagicMock()
        server.check_channel_subsystem_request.return_value = True
        ch._transport._server_interface = server
        data = write_string("sftp")
        assert ch._handle_request("subsystem", data) is True

    def test_pty_request_server_mode(self):
        ch = _make_channel()
        ch._transport._server_mode = True
        server = MagicMock()
        server.check_channel_pty_request.return_value = True
        ch._transport._server_interface = server
        data = write_string("xterm")
        data += write_uint32(80) + write_uint32(24)
        data += write_uint32(0) + write_uint32(0)
        data += write_string(b"")
        assert ch._handle_request("pty-req", data) is True

    def test_window_change_server_mode(self):
        ch = _make_channel()
        ch._transport._server_mode = True
        server = MagicMock()
        server.check_channel_window_change_request.return_value = True
        ch._transport._server_interface = server
        data = write_uint32(120) + write_uint32(40)
        data += write_uint32(0) + write_uint32(0)
        assert ch._handle_request("window-change", data) is True

    def test_env_request_server_mode(self):
        ch = _make_channel()
        ch._transport._server_mode = True
        server = MagicMock()
        server.check_channel_env_request.return_value = True
        ch._transport._server_interface = server
        data = write_string("TERM") + write_string("xterm")
        assert ch._handle_request("env", data) is True

    def test_x11_request_server_mode(self):
        ch = _make_channel()
        ch._transport._server_mode = True
        server = MagicMock()
        server.check_channel_x11_request.return_value = True
        ch._transport._server_interface = server
        data = write_boolean(True)
        data += write_string("MIT-MAGIC-COOKIE-1")
        data += write_string(b"cookie")
        data += write_uint32(0)
        assert ch._handle_request("x11-req", data) is True

    def test_unknown_request_server_mode(self):
        ch = _make_channel()
        ch._transport._server_mode = True
        ch._transport._server_interface = MagicMock()
        assert ch._handle_request("unknown-type", b"") is False


# ---- _handle_exit_signal ----


class TestHandleExitSignal:
    def test_exit_signal_known(self):
        ch = _make_channel()
        ch._handle_exit_signal("TERM", False, "terminated", "")
        assert ch._exit_status == 128 + 15
        sig_info = ch.get_exit_signal()
        assert sig_info is not None
        assert sig_info["signal_name"] == "TERM"

    def test_exit_signal_unknown(self):
        ch = _make_channel()
        ch._handle_exit_signal("CUSTOM", False, "custom", "")
        assert ch._exit_status == 128  # 128 + 0

    def test_exit_signal_sig_prefix(self):
        ch = _make_channel()
        ch._handle_exit_signal("SIGINT", False, "", "")
        assert ch._exit_status == 128 + 2


# ---- _adjust_window ----


class TestAdjustWindow:
    def test_adjust_no_send(self):
        ch = _make_channel()
        ch._local_window_size = DEFAULT_WINDOW_SIZE
        ch._adjust_window(10)
        # Window still above half, no adjust sent
        ch._transport._send_channel_window_adjust.assert_not_called()

    def test_adjust_triggers_send(self):
        ch = _make_channel()
        ch._local_window_size = DEFAULT_WINDOW_SIZE // 4
        ch._adjust_window(10)
        ch._transport._send_channel_window_adjust.assert_called_once()
