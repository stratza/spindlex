"""
Unit tests for spindlex/transport/channel.py

All tests are mock-based — no real SSH connections are made.
asyncio_mode = "auto" is configured in pyproject.toml / pytest.ini, so no
individual @pytest.mark.asyncio decorator is needed.
"""

from __future__ import annotations

from collections import deque
from unittest.mock import MagicMock

import pytest

from spindlex.exceptions import ChannelException
from spindlex.transport.channel import Channel

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_channel(
    *,
    remote_window: int = 1024 * 1024,
    remote_max_packet: int = 32768,
    active: bool = True,
) -> tuple[Channel, MagicMock]:
    """Return a Channel wired to a MagicMock transport, ready to use."""
    transport = MagicMock()
    transport._server_mode = False
    transport._server_interface = None
    transport.active = active
    transport._kex_thread = None  # no background thread by default

    channel = Channel(transport, channel_id=1)
    channel._remote_channel_id = 2
    channel._remote_window_size = remote_window
    channel._remote_max_packet_size = remote_max_packet
    return channel, transport


# ---------------------------------------------------------------------------
# __init__ / basic properties
# ---------------------------------------------------------------------------


class TestChannelInit:
    def test_channel_id_property(self):
        ch, _ = make_channel()
        assert ch.channel_id == 1

    def test_closed_initially_false(self):
        ch, _ = make_channel()
        assert ch.closed is False

    def test_eof_received_initially_false(self):
        ch, _ = make_channel()
        assert ch.eof_received is False

    def test_exit_status_initially_minus_one(self):
        ch, _ = make_channel()
        assert ch.get_exit_status() == -1

    def test_recv_buffer_is_deque(self):
        ch, _ = make_channel()
        assert isinstance(ch._recv_buffer, deque)

    def test_stderr_buffer_is_deque(self):
        ch, _ = make_channel()
        assert isinstance(ch._stderr_buffer, deque)

    def test_settimeout_gettimeout_roundtrip(self):
        ch, _ = make_channel()
        ch.settimeout(5.0)
        assert ch.gettimeout() == 5.0

    def test_settimeout_none(self):
        ch, _ = make_channel()
        ch.settimeout(None)
        assert ch.gettimeout() is None


# ---------------------------------------------------------------------------
# send()
# ---------------------------------------------------------------------------


class TestChannelSend:
    def test_send_bytes_returns_byte_count(self):
        ch, transport = make_channel()
        result = ch.send(b"hello")
        assert result == 5
        transport._send_channel_data.assert_called_once_with(1, b"hello")

    def test_send_string_converts_to_bytes(self):
        ch, transport = make_channel()
        result = ch.send("hi")
        assert result == 2
        transport._send_channel_data.assert_called_once_with(1, b"hi")

    def test_send_empty_returns_zero(self):
        ch, transport = make_channel()
        result = ch.send(b"")
        assert result == 0
        transport._send_channel_data.assert_not_called()

    def test_send_on_closed_channel_raises(self):
        ch, _ = make_channel()
        ch._closed = True
        with pytest.raises(ChannelException, match="closed"):
            ch.send(b"data")

    def test_send_with_eof_sent_raises(self):
        ch, _ = make_channel()
        ch._eof_sent = True
        with pytest.raises(ChannelException, match="EOF"):
            ch.send(b"data")

    def test_send_without_remote_channel_id_raises(self):
        ch, _ = make_channel()
        ch._remote_channel_id = None
        with pytest.raises(ChannelException, match="not properly opened"):
            ch.send(b"data")

    def test_send_limited_by_remote_window(self):
        ch, transport = make_channel(remote_window=4, remote_max_packet=32768)
        result = ch.send(b"hello")  # 5 bytes but window only 4
        assert result == 4
        transport._send_channel_data.assert_called_once_with(1, b"hell")

    def test_send_limited_by_max_packet_size(self):
        ch, transport = make_channel(remote_window=1024, remote_max_packet=3)
        result = ch.send(b"hello")
        assert result == 3
        transport._send_channel_data.assert_called_once_with(1, b"hel")

    def test_send_decrements_remote_window(self):
        ch, _ = make_channel(remote_window=100)
        ch.send(b"test")  # 4 bytes
        assert ch._remote_window_size == 96

    def test_send_transport_error_raises_channel_exception(self):
        ch, transport = make_channel()
        transport._send_channel_data.side_effect = OSError("boom")
        with pytest.raises(ChannelException, match="Failed to send data"):
            ch.send(b"data")

    def test_send_zero_window_triggers_close_detection(self):
        """If window is 0 and channel closes while waiting, raises."""
        ch, transport = make_channel(remote_window=0)

        # Make pump set _closed so the wait loop exits
        def pump_side_effect():
            ch._closed = True
            ch._window_event.set()

        transport._pump.side_effect = pump_side_effect
        with pytest.raises(ChannelException):
            ch.send(b"data", timeout=1.0)


# ---------------------------------------------------------------------------
# sendall()
# ---------------------------------------------------------------------------


class TestChannelSendAll:
    def test_sendall_sends_all_bytes(self):
        ch, transport = make_channel(remote_max_packet=3)
        ch.sendall(b"hello")
        # 5 bytes / packet of 3 → two calls: 3 + 2
        assert transport._send_channel_data.call_count == 2

    def test_sendall_string_input(self):
        ch, transport = make_channel()
        ch.sendall("hi there")
        transport._send_channel_data.assert_called()

    def test_sendall_empty_data_no_calls(self):
        ch, transport = make_channel()
        # send() returns 0 for empty; sendall loop never calls _send_channel_data
        ch.sendall(b"")
        transport._send_channel_data.assert_not_called()


# ---------------------------------------------------------------------------
# recv()
# ---------------------------------------------------------------------------


class TestChannelRecv:
    def test_recv_zero_or_negative_returns_empty(self):
        ch, _ = make_channel()
        assert ch.recv(0) == b""
        assert ch.recv(-1) == b""

    def test_recv_data_from_buffer(self):
        ch, _ = make_channel()
        ch._recv_buffer.append(b"hello world")
        result = ch.recv(5)
        assert result == b"hello"
        # Remainder should stay in buffer
        assert ch._recv_buffer[0] == b" world"

    def test_recv_entire_chunk_when_smaller_than_nbytes(self):
        ch, _ = make_channel()
        ch._recv_buffer.append(b"hi")
        result = ch.recv(100)
        assert result == b"hi"
        assert len(ch._recv_buffer) == 0

    def test_recv_eof_returns_empty_when_buffer_empty(self):
        ch, _ = make_channel()
        ch._eof_received = True
        result = ch.recv(10)
        assert result == b""

    def test_recv_inactive_transport_returns_empty(self):
        ch, transport = make_channel()
        transport.active = False
        result = ch.recv(10)
        assert result == b""

    def test_recv_adjusts_window(self):
        ch, transport = make_channel()
        ch._recv_buffer.append(b"abc")
        ch.recv(3)
        transport._send_channel_window_adjust.assert_called()

    def test_recv_timeout_raises(self):
        ch, transport = make_channel()
        ch._timeout = 0.01
        # transport._pump does nothing → buffer stays empty → timeout fires
        transport._pump.return_value = None
        with pytest.raises(ChannelException, match="Timeout"):
            ch.recv(10)


# ---------------------------------------------------------------------------
# recv_exactly()
# ---------------------------------------------------------------------------


class TestChannelRecvExactly:
    def test_recv_exactly_combines_chunks(self):
        ch, _ = make_channel()
        ch._recv_buffer.append(b"ab")
        ch._recv_buffer.append(b"cde")
        result = ch.recv_exactly(4)
        assert result == b"abcd"

    def test_recv_exactly_raises_if_channel_closes_early(self):
        ch, transport = make_channel()
        # EOF immediately — recv returns b"" on first call
        ch._eof_received = True
        with pytest.raises(ChannelException, match="closed"):
            ch.recv_exactly(10)


# ---------------------------------------------------------------------------
# recv_stderr()
# ---------------------------------------------------------------------------


class TestChannelRecvStderr:
    def test_recv_stderr_returns_empty_for_nonpositive(self):
        ch, _ = make_channel()
        assert ch.recv_stderr(0) == b""

    def test_recv_stderr_data_from_buffer(self):
        ch, _ = make_channel()
        ch._stderr_buffer.append(b"error output")
        result = ch.recv_stderr(5)
        assert result == b"error"

    def test_recv_stderr_eof_returns_empty(self):
        ch, _ = make_channel()
        ch._eof_received = True
        result = ch.recv_stderr(10)
        assert result == b""

    def test_recv_stderr_closed_raises(self):
        ch, _ = make_channel()
        ch._closed = True
        with pytest.raises(ChannelException, match="closed"):
            ch.recv_stderr(10)

    def test_recv_stderr_splits_large_chunk(self):
        ch, _ = make_channel()
        ch._stderr_buffer.append(b"abcdef")
        result = ch.recv_stderr(3)
        assert result == b"abc"
        assert ch._stderr_buffer[0] == b"def"


# ---------------------------------------------------------------------------
# exec_command / invoke_shell / invoke_subsystem / request_pty
# ---------------------------------------------------------------------------


class TestChannelRequests:
    def _make_success_channel(self):
        ch, transport = make_channel()

        # Simulate send_channel_request → transport drives _handle_request_success
        def pump():
            ch._handle_request_success()

        transport._pump.side_effect = pump
        return ch, transport

    def test_exec_command_empty_raises(self):
        ch, _ = make_channel()
        with pytest.raises(ChannelException, match="empty"):
            ch.exec_command("")

    def test_exec_command_sends_request(self):
        ch, transport = make_channel()
        ch._request_success = True  # pre-set so we don't need pump
        # Patch send_channel_request to set success immediately
        ch._request_success = None

        # Drive via pump side effect
        def pump():
            ch._handle_request_success()

        transport._pump.side_effect = pump
        ch.exec_command("ls -la")
        transport._send_channel_request.assert_called()
        args = transport._send_channel_request.call_args[0]
        assert args[1] == "exec"
        assert args[2] is True  # want_reply

    def test_exec_command_failure_raises(self):
        ch, transport = make_channel()

        def pump():
            ch._handle_request_failure()

        transport._pump.side_effect = pump
        with pytest.raises(ChannelException, match="Failed to execute"):
            ch.exec_command("bad-cmd")

    def test_invoke_shell_sends_request(self):
        ch, transport = make_channel()

        def pump():
            ch._handle_request_success()

        transport._pump.side_effect = pump
        ch.invoke_shell()
        args = transport._send_channel_request.call_args[0]
        assert args[1] == "shell"

    def test_invoke_shell_failure_raises(self):
        ch, transport = make_channel()

        def pump():
            ch._handle_request_failure()

        transport._pump.side_effect = pump
        with pytest.raises(ChannelException, match="Failed to invoke shell"):
            ch.invoke_shell()

    def test_invoke_subsystem_empty_raises(self):
        ch, _ = make_channel()
        with pytest.raises(ChannelException, match="empty"):
            ch.invoke_subsystem("")

    def test_invoke_subsystem_success(self):
        ch, transport = make_channel()

        def pump():
            ch._handle_request_success()

        transport._pump.side_effect = pump
        ch.invoke_subsystem("sftp")
        args = transport._send_channel_request.call_args[0]
        assert args[1] == "subsystem"

    def test_invoke_subsystem_failure_raises(self):
        ch, transport = make_channel()

        def pump():
            ch._handle_request_failure()

        transport._pump.side_effect = pump
        with pytest.raises(ChannelException, match="Failed to invoke subsystem"):
            ch.invoke_subsystem("sftp")

    def test_request_pty_success(self):
        ch, transport = make_channel()

        def pump():
            ch._handle_request_success()

        transport._pump.side_effect = pump
        ch.request_pty("xterm", 80, 24)
        args = transport._send_channel_request.call_args[0]
        assert args[1] == "pty-req"

    def test_request_pty_failure_raises(self):
        ch, transport = make_channel()

        def pump():
            ch._handle_request_failure()

        transport._pump.side_effect = pump
        with pytest.raises(ChannelException, match="Failed to request PTY"):
            ch.request_pty()


# ---------------------------------------------------------------------------
# send_exit_status / send_eof
# ---------------------------------------------------------------------------


class TestChannelEofAndExit:
    def test_send_exit_status_sends_correct_request(self):
        ch, transport = make_channel()
        from spindlex.protocol.utils import write_uint32

        ch.send_exit_status(0)
        transport._send_channel_request.assert_called_once_with(
            1, "exit-status", False, write_uint32(0)
        )

    def test_send_exit_status_nonzero(self):
        ch, transport = make_channel()
        from spindlex.protocol.utils import write_uint32

        ch.send_exit_status(127)
        transport._send_channel_request.assert_called_once_with(
            1, "exit-status", False, write_uint32(127)
        )

    def test_send_eof_calls_transport(self):
        ch, transport = make_channel()
        ch.send_eof()
        transport._send_channel_eof.assert_called_once_with(1)
        assert ch._eof_sent is True

    def test_send_eof_twice_is_idempotent(self):
        ch, transport = make_channel()
        ch.send_eof()
        ch.send_eof()  # second call should be a no-op
        transport._send_channel_eof.assert_called_once()

    def test_send_eof_on_closed_raises(self):
        ch, _ = make_channel()
        ch._closed = True
        with pytest.raises(ChannelException, match="closed"):
            ch.send_eof()

    def test_send_eof_without_remote_channel_id_raises(self):
        ch, _ = make_channel()
        ch._remote_channel_id = None
        with pytest.raises(ChannelException, match="not properly opened"):
            ch.send_eof()


# ---------------------------------------------------------------------------
# close()
# ---------------------------------------------------------------------------


class TestChannelClose:
    def test_close_sets_closed_flag(self):
        ch, _ = make_channel()
        ch.close()
        assert ch.closed is True

    def test_close_calls_transport_close_channel(self):
        ch, transport = make_channel()
        ch.close()
        transport._close_channel.assert_called_once_with(1)

    def test_close_twice_only_calls_transport_once(self):
        ch, transport = make_channel()
        ch.close()
        ch.close()
        transport._close_channel.assert_called_once()

    def test_context_manager_closes_on_exit(self):
        ch, transport = make_channel()
        with ch:
            pass
        assert ch.closed is True
        transport._close_channel.assert_called_once()

    def test_shutdown_delegates_to_close(self):
        ch, transport = make_channel()
        ch.shutdown(0)
        assert ch.closed is True


# ---------------------------------------------------------------------------
# _handle_* internal callbacks
# ---------------------------------------------------------------------------


class TestChannelHandlers:
    def test_handle_data_appends_to_recv_buffer(self):
        ch, _ = make_channel()
        ch._handle_data(b"chunk")
        assert ch._recv_buffer[0] == b"chunk"

    def test_handle_data_sets_data_event(self):
        ch, _ = make_channel()
        ch._handle_data(b"x")
        assert ch._data_event.is_set()

    def test_handle_data_noop_when_closed(self):
        ch, _ = make_channel()
        ch._closed = True
        ch._handle_data(b"ignored")
        assert len(ch._recv_buffer) == 0

    def test_handle_extended_data_type1_goes_to_stderr(self):
        ch, _ = make_channel()
        ch._handle_extended_data(1, b"err")
        assert ch._stderr_buffer[0] == b"err"

    def test_handle_extended_data_type0_ignored(self):
        ch, _ = make_channel()
        ch._handle_extended_data(0, b"data")
        assert len(ch._stderr_buffer) == 0

    def test_handle_eof_sets_flag_and_event(self):
        ch, _ = make_channel()
        ch._handle_eof()
        assert ch._eof_received is True
        assert ch._data_event.is_set()

    def test_handle_close_sets_closed_and_events(self):
        ch, _ = make_channel()
        ch._handle_close()
        assert ch._closed is True
        assert ch._data_event.is_set()
        assert ch._window_event.is_set()

    def test_handle_window_adjust_increases_window(self):
        ch, _ = make_channel()
        initial = ch._remote_window_size
        ch._handle_window_adjust(8192)
        assert ch._remote_window_size == initial + 8192
        assert ch._window_event.is_set()

    def test_handle_request_success_sets_flag(self):
        ch, _ = make_channel()
        ch._handle_request_success()
        assert ch._request_success is True
        assert ch._request_event.is_set()

    def test_handle_request_failure_sets_flag(self):
        ch, _ = make_channel()
        ch._handle_request_failure()
        assert ch._request_success is False
        assert ch._request_event.is_set()

    def test_handle_exit_status_stores_value(self):
        ch, _ = make_channel()
        ch._handle_exit_status(42)
        assert ch._exit_status == 42
        assert ch.get_exit_status() == 42

    def test_handle_request_exit_status_type(self):
        """_handle_request with exit-status parses uint32 from data."""
        from spindlex.protocol.utils import write_uint32

        ch, _ = make_channel()
        ch._transport._server_mode = False
        data = write_uint32(99)
        result = ch._handle_request("exit-status", data)
        assert result is True
        assert ch._exit_status == 99

    def test_handle_request_unknown_returns_false_in_client_mode(self):
        ch, transport = make_channel()
        transport._server_mode = False
        result = ch._handle_request("unknown-type", b"")
        assert result is False

    def test_handle_exit_signal_maps_signal_name(self):
        ch, _ = make_channel()
        ch._handle_exit_signal("TERM", False, "", "en")
        # TERM → signal 15 → 128 + 15 = 143
        assert ch._exit_status == 143

    def test_handle_exit_signal_sig_prefix_stripped(self):
        ch, _ = make_channel()
        ch._handle_exit_signal("SIGKILL", False, "", "en")
        # KILL → 9 → 128 + 9 = 137
        assert ch._exit_status == 137

    def test_get_exit_signal_none_before_signal(self):
        ch, _ = make_channel()
        assert ch.get_exit_signal() is None

    def test_get_exit_signal_after_signal(self):
        ch, _ = make_channel()
        ch._handle_exit_signal("INT", True, "interrupted", "en")
        info = ch.get_exit_signal()
        assert info is not None
        assert info["signal_name"] == "INT"
        assert info["core_dumped"] is True


# ---------------------------------------------------------------------------
# send_channel_request (direct)
# ---------------------------------------------------------------------------


class TestSendChannelRequest:
    def test_no_reply_returns_true(self):
        ch, transport = make_channel()
        result = ch.send_channel_request("env", want_reply=False, data=b"")
        assert result is True

    def test_closed_channel_raises(self):
        ch, _ = make_channel()
        ch._closed = True
        with pytest.raises(ChannelException, match="closed"):
            ch.send_channel_request("shell", want_reply=True)

    def test_missing_remote_channel_id_raises(self):
        ch, _ = make_channel()
        ch._remote_channel_id = None
        with pytest.raises(ChannelException, match="not properly opened"):
            ch.send_channel_request("shell", want_reply=True)

    def test_transport_error_wrapped(self):
        ch, transport = make_channel()
        transport._send_channel_request.side_effect = RuntimeError("net error")
        with pytest.raises(ChannelException, match="Failed to send channel request"):
            ch.send_channel_request("shell", want_reply=False)


# ---------------------------------------------------------------------------
# recv_exit_status
# ---------------------------------------------------------------------------


class TestRecvExitStatus:
    def test_returns_exit_status_already_set(self):
        ch, _ = make_channel()
        ch._exit_status = 0
        result = ch.recv_exit_status()
        assert result == 0

    def test_pump_until_exit_status_set(self):
        ch, transport = make_channel()
        call_count = [0]

        def pump():
            call_count[0] += 1
            if call_count[0] >= 2:
                ch._exit_status = 3

        transport._pump.side_effect = pump
        result = ch.recv_exit_status()
        assert result == 3
