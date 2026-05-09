"""
Extended coverage tests for spindlex/transport/channel.py.
Targets remaining missed lines from coverage report.

Missed lines addressed:
  130     - send() timeout when window is 0 and elapsed >= timeout
  140-143 - socket.timeout and other exception in window wait loop
  158     - can_send <= 0 path
  189     - sendall() when send() returns <= 0
  249-254 - recv() with bg_thread: timeout-aware wait
  265     - recv() timeout while select finds no data quickly
  269-280 - recv() select with socket
  284-285 - recv() socket.timeout caught
  450-453 - recv_exit_status with bg_thread and timeout
  459-461 - recv_exit_status bg_thread no timeout
  464-465 - recv_exit_status bg_thread wait raises
  531     - send_channel_request: channel closed while waiting
  536-538 - send_channel_request: timeout waiting
  547-548 - send_channel_request with bg_thread + timeout
  554-556 - send_channel_request pump raises non-timeout error
  580-581 - send_eof: transport raises exception
  612-614 - recv_stderr: closed channel raises
  628-673 - recv_stderr timeout/bg_thread paths
  806-823 - _handle_request exit-signal
  832     - _handle_request: client mode returns False
  838-904 - _handle_request server-mode paths
"""

from __future__ import annotations

import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import ChannelException
from spindlex.transport.channel import Channel


def make_channel(
    *,
    remote_window: int = 1024 * 1024,
    remote_max_packet: int = 32768,
    active: bool = True,
) -> tuple[Channel, MagicMock]:
    transport = MagicMock()
    transport._server_mode = False
    transport._server_interface = None
    transport.active = active
    transport._kex_thread = None

    channel = Channel(transport, channel_id=1)
    channel._remote_channel_id = 2
    channel._remote_window_size = remote_window
    channel._remote_max_packet_size = remote_max_packet
    return channel, transport


# ---------------------------------------------------------------------------
# send() window-wait timeout path (line 130)
# ---------------------------------------------------------------------------


class TestChannelSendWindowTimeout:
    def test_send_timeout_when_window_zero(self):
        """When window is 0 and timeout=0, should immediately raise timeout."""
        ch, transport = make_channel(remote_window=0)
        # Pump does nothing → window stays 0 → timeout fires quickly
        transport._pump.return_value = None
        with pytest.raises(ChannelException, match="Timeout"):
            ch.send(b"data", timeout=0.0)

    def test_send_window_wait_socket_timeout_continues(self):
        """socket.timeout in pump is silently ignored (line 140-141)."""
        ch, transport = make_channel(remote_window=0)

        call_count = [0]

        def pump_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                raise socket.timeout("timed out")
            # Second call: open window and mark closed to exit
            ch._remote_window_size = 10
            ch._window_event.set()

        transport._pump.side_effect = pump_side_effect
        # Should send after the second pump opens the window
        result = ch.send(b"hello", timeout=5.0)
        assert result > 0

    def test_send_window_wait_other_exception_raises(self):
        """Non-socket.timeout exception in pump becomes ChannelException (lines 142-143)."""
        ch, transport = make_channel(remote_window=0)

        def pump_side_effect():
            raise RuntimeError("connection lost")

        transport._pump.side_effect = pump_side_effect
        with pytest.raises(ChannelException, match="Transport error during send"):
            ch.send(b"data", timeout=5.0)

    def test_send_can_send_zero_returns_zero(self):
        """When can_send == 0, send returns 0 (line 157-158)."""
        ch, transport = make_channel(remote_window=1024, remote_max_packet=0)
        result = ch.send(b"hello")
        assert result == 0


# ---------------------------------------------------------------------------
# sendall() when send returns <= 0 (line 189)
# ---------------------------------------------------------------------------


class TestChannelSendallFailure:
    def test_sendall_raises_when_send_returns_zero(self):
        """If send() returns 0 (non-empty data), sendall() raises."""
        ch, transport = make_channel(remote_window=1024, remote_max_packet=0)
        # send() will return 0 because max_packet=0 → can_send=0
        with pytest.raises(ChannelException, match="Failed to send data"):
            ch.sendall(b"non-empty")


# ---------------------------------------------------------------------------
# recv() bg_thread path (lines 249-254)
# ---------------------------------------------------------------------------


class TestChannelRecvBgThread:
    def test_recv_with_bg_thread_waits_then_gets_data(self):
        """bg_thread path: wait on _data_event, then data arrives."""
        ch, transport = make_channel()
        # Simulate a background thread
        transport._kex_thread = MagicMock()

        def add_data():
            time.sleep(0.02)
            ch._handle_data(b"from_bg_thread")

        t = threading.Thread(target=add_data, daemon=True)
        t.start()
        result = ch.recv(20)
        assert result == b"from_bg_thread"
        t.join(timeout=1.0)

    def test_recv_with_bg_thread_timeout(self):
        """bg_thread + timeout: raises ChannelException on timeout."""
        ch, transport = make_channel()
        transport._kex_thread = MagicMock()
        ch._timeout = 0.05  # very short
        with pytest.raises(ChannelException, match="Timeout"):
            ch.recv(10)


# ---------------------------------------------------------------------------
# recv() timeout with select (lines 265, 269-280)
# ---------------------------------------------------------------------------


class TestChannelRecvSelectPath:
    def test_recv_timeout_with_socket_select_no_data(self):
        """When socket has no data ready, select returns empty → continue loop."""
        ch, transport = make_channel()
        ch._timeout = 0.05

        # Give transport a fake socket that select can use
        fake_sock = MagicMock()
        transport._socket = fake_sock
        transport._packet_buffer = b""

        # select returns empty readable list → no data, loop continues until timeout
        with patch("select.select", return_value=([], [], [])):
            with pytest.raises(ChannelException, match="Timeout"):
                ch.recv(10)

    def test_recv_select_exception_falls_through_to_pump(self):
        """select() raises exception → falls through to _pump() (lines 279-280)."""
        ch, transport = make_channel()
        ch._timeout = 2.0

        fake_sock = MagicMock()
        transport._socket = fake_sock
        transport._packet_buffer = b""

        call_count = [0]

        def select_side_effect(*args, **kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                raise OSError("select failed")
            # On second iteration there's no socket, so it doesn't reach select
            return ([], [], [])

        def pump_side_effect():
            ch._handle_data(b"arrived")

        transport._pump.side_effect = pump_side_effect

        with patch("select.select", side_effect=select_side_effect):
            result = ch.recv(10)
        assert result == b"arrived"

    def test_recv_socket_timeout_exception_continues(self):
        """socket.timeout from _pump() is caught, loop continues (lines 284-285)."""
        ch, transport = make_channel()
        ch._timeout = 2.0

        call_count = [0]

        def pump_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                raise socket.timeout("timed out")
            # Second call delivers data
            ch._handle_data(b"data_after_timeout")

        transport._pump.side_effect = pump_side_effect
        result = ch.recv(20)
        assert result == b"data_after_timeout"


# ---------------------------------------------------------------------------
# recv_exit_status with background thread (lines 450-465)
# ---------------------------------------------------------------------------


class TestRecvExitStatusBgThread:
    def test_recv_exit_status_bg_thread_returns_when_event_fires(self):
        """With bg_thread, waits on event then returns exit status."""
        ch, transport = make_channel()
        transport._kex_thread = MagicMock()

        def set_exit_status():
            time.sleep(0.02)
            ch._handle_exit_status(0)

        t = threading.Thread(target=set_exit_status, daemon=True)
        t.start()
        result = ch.recv_exit_status()
        assert result == 0
        t.join(timeout=1.0)

    def test_recv_exit_status_bg_thread_timeout(self):
        """With bg_thread + timeout, raises ChannelException if no exit status."""
        ch, transport = make_channel()
        transport._kex_thread = MagicMock()

        with pytest.raises(ChannelException, match="Timeout"):
            ch.recv_exit_status(timeout=0.05)


# ---------------------------------------------------------------------------
# send_channel_request closed/timeout/bg_thread paths
# ---------------------------------------------------------------------------


class TestSendChannelRequestPaths:
    def test_channel_closed_while_waiting_raises(self):
        """Channel becomes closed while waiting for request reply (line 531)."""
        ch, transport = make_channel()

        def pump():
            ch._closed = True
            ch._request_event.set()

        transport._pump.side_effect = pump

        with pytest.raises(ChannelException, match="closed"):
            ch.send_channel_request("shell", want_reply=True)

    def test_timeout_waiting_for_request_reply(self):
        """Timeout while waiting for channel request response (lines 536-538)."""
        ch, transport = make_channel()
        ch._timeout = 0.05
        transport._pump.return_value = None

        with pytest.raises(ChannelException, match="Timeout"):
            ch.send_channel_request("shell", want_reply=True)

    def test_bg_thread_request_with_timeout(self):
        """bg_thread: request_event.wait() with timeout (lines 547-548)."""
        ch, transport = make_channel()
        transport._kex_thread = MagicMock()
        ch._timeout = 0.05

        with pytest.raises(ChannelException, match="Timeout"):
            ch.send_channel_request("shell", want_reply=True)

    def test_pump_raises_non_timeout_error(self):
        """Non-timeout exception from pump is wrapped (lines 554-556)."""
        ch, transport = make_channel()

        def pump():
            raise RuntimeError("transport broken")

        transport._pump.side_effect = pump

        with pytest.raises(ChannelException, match="Transport error during request"):
            ch.send_channel_request("shell", want_reply=True)

    def test_pump_raises_timeout_is_ignored(self):
        """Exception with 'timeout' in message is silently ignored."""
        ch, transport = make_channel()

        call_count = [0]

        def pump():
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception("socket timeout occurred")
            ch._handle_request_success()

        transport._pump.side_effect = pump
        result = ch.send_channel_request("shell", want_reply=True)
        assert result is True


# ---------------------------------------------------------------------------
# send_eof transport exception path (lines 580-581)
# ---------------------------------------------------------------------------


class TestSendEofTransportError:
    def test_send_eof_transport_raises(self):
        """Transport exception during send_eof is wrapped (lines 580-581)."""
        ch, transport = make_channel()
        transport._send_channel_eof.side_effect = OSError("network error")
        with pytest.raises(ChannelException, match="Failed to send EOF"):
            ch.send_eof()


# ---------------------------------------------------------------------------
# recv_stderr paths (lines 612-614, 628-673)
# ---------------------------------------------------------------------------


class TestRecvStderrExtended:
    def test_recv_stderr_timeout_raises(self):
        """Timeout while waiting for stderr data raises ChannelException."""
        ch, transport = make_channel()
        ch._timeout = 0.05
        transport._pump.return_value = None

        with pytest.raises(ChannelException, match="Timeout"):
            ch.recv_stderr(10)

    def test_recv_stderr_bg_thread_waits_for_data(self):
        """With bg_thread, recv_stderr waits on event."""
        ch, transport = make_channel()
        transport._kex_thread = MagicMock()

        def add_stderr():
            time.sleep(0.02)
            ch._handle_extended_data(1, b"error output")

        t = threading.Thread(target=add_stderr, daemon=True)
        t.start()
        result = ch.recv_stderr(50)
        assert result == b"error output"
        t.join(timeout=1.0)

    def test_recv_stderr_bg_thread_timeout(self):
        """With bg_thread + timeout, raises ChannelException on timeout."""
        ch, transport = make_channel()
        transport._kex_thread = MagicMock()
        ch._timeout = 0.05

        with pytest.raises(ChannelException, match="Timeout"):
            ch.recv_stderr(10)

    def test_recv_stderr_with_socket_select(self):
        """recv_stderr uses select when socket is available."""
        ch, transport = make_channel()
        ch._timeout = 2.0
        fake_sock = MagicMock()
        transport._socket = fake_sock
        transport._packet_buffer = b""

        call_count = [0]

        def pump_side_effect():
            call_count[0] += 1
            if call_count[0] >= 1:
                ch._handle_extended_data(1, b"stderr_data")

        transport._pump.side_effect = pump_side_effect

        with patch("select.select", return_value=([fake_sock], [], [])):
            result = ch.recv_stderr(50)
        assert result == b"stderr_data"

    def test_recv_stderr_select_no_data_continues(self):
        """select() returning empty causes loop to continue until timeout."""
        ch, transport = make_channel()
        ch._timeout = 0.05
        fake_sock = MagicMock()
        transport._socket = fake_sock
        transport._packet_buffer = b""

        with patch("select.select", return_value=([], [], [])):
            with pytest.raises(ChannelException, match="Timeout"):
                ch.recv_stderr(10)

    def test_recv_stderr_socket_timeout_continues(self):
        """Exception whose str() contains 'timeout' is caught and loop continues."""
        ch, transport = make_channel()
        ch._timeout = 2.0

        call_count = [0]

        def pump_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                # Use an exception whose str() contains 'timeout' to be caught
                raise Exception("socket timeout occurred")
            ch._handle_extended_data(1, b"late_stderr")

        transport._pump.side_effect = pump_side_effect
        result = ch.recv_stderr(20)
        assert result == b"late_stderr"

    def test_recv_stderr_non_timeout_exception_reraises(self):
        """Non-timeout exception from pump is re-raised."""
        ch, transport = make_channel()
        ch._timeout = 5.0

        def pump_side_effect():
            raise RuntimeError("hard failure")

        transport._pump.side_effect = pump_side_effect

        with pytest.raises(RuntimeError, match="hard failure"):
            ch.recv_stderr(10)


# ---------------------------------------------------------------------------
# _handle_request paths (lines 806-823, 832, 838-904)
# ---------------------------------------------------------------------------


class TestHandleRequestPaths:
    def _build_exit_signal_data(self, signal_name: str) -> bytes:
        """Build a minimal exit-signal data payload."""
        from spindlex.protocol.utils import write_string

        data = bytearray()
        sig_bytes = signal_name.encode("utf-8")
        data.extend(write_string(sig_bytes))  # signal name
        data.append(0)  # core_dumped = False
        data.extend(write_string(b""))  # error message
        data.extend(write_string(b"en"))  # language tag
        return bytes(data)

    def test_handle_request_exit_signal(self):
        """_handle_request handles exit-signal type (lines 806-823)."""
        ch, transport = make_channel()
        data = self._build_exit_signal_data("TERM")
        result = ch._handle_request("exit-signal", data)
        assert result is True
        assert ch._exit_status == 143  # 128 + 15

    def test_handle_request_exit_signal_empty_data_returns_true(self):
        """exit-signal with len < 4 still returns True (line 806)."""
        ch, transport = make_channel()
        result = ch._handle_request("exit-signal", b"\x00\x00")
        assert result is True

    def test_handle_request_unknown_client_mode_returns_false(self):
        """Unknown type in client mode returns False (line 832)."""
        ch, transport = make_channel()
        transport._server_mode = False
        result = ch._handle_request("unknown-type", b"")
        assert result is False

    def test_handle_request_server_mode_shell(self):
        """Server mode shell request calls server interface (line 832)."""
        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        server_iface.check_channel_shell_request.return_value = True
        transport._server_interface = server_iface

        result = ch._handle_request("shell", b"")
        assert result is True
        server_iface.check_channel_shell_request.assert_called_once_with(ch)

    def test_handle_request_server_mode_exec(self):
        """Server mode exec request (lines 834-836)."""
        from spindlex.protocol.utils import write_string

        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        server_iface.check_channel_exec_request.return_value = True
        transport._server_interface = server_iface

        data = write_string(b"ls -la")
        result = ch._handle_request("exec", data)
        assert result is True
        server_iface.check_channel_exec_request.assert_called_once()

    def test_handle_request_server_mode_subsystem(self):
        """Server mode subsystem request (lines 838-841)."""
        from spindlex.protocol.utils import write_string

        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        server_iface.check_channel_subsystem_request.return_value = True
        transport._server_interface = server_iface

        data = write_string(b"sftp")
        result = ch._handle_request("subsystem", data)
        assert result is True
        server_iface.check_channel_subsystem_request.assert_called_once()

    def test_handle_request_server_mode_pty_req(self):
        """Server mode pty-req request (lines 843-857)."""
        from spindlex.protocol.utils import write_string, write_uint32

        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        server_iface.check_channel_pty_request.return_value = True
        transport._server_interface = server_iface

        data = bytearray()
        data.extend(write_string(b"xterm"))
        data.extend(write_uint32(80))
        data.extend(write_uint32(24))
        data.extend(write_uint32(0))
        data.extend(write_uint32(0))
        data.extend(write_string(b""))
        result = ch._handle_request("pty-req", bytes(data))
        assert result is True

    def test_handle_request_server_mode_window_change(self):
        """Server mode window-change request (lines 859-870)."""
        from spindlex.protocol.utils import write_uint32

        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        server_iface.check_channel_window_change_request.return_value = True
        transport._server_interface = server_iface

        data = bytearray()
        data.extend(write_uint32(100))
        data.extend(write_uint32(40))
        data.extend(write_uint32(0))
        data.extend(write_uint32(0))
        result = ch._handle_request("window-change", bytes(data))
        assert result is True

    def test_handle_request_server_mode_env(self):
        """Server mode env request (lines 872-879)."""
        from spindlex.protocol.utils import write_string

        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        server_iface.check_channel_env_request.return_value = True
        transport._server_interface = server_iface

        data = bytearray()
        data.extend(write_string(b"TERM"))
        data.extend(write_string(b"xterm"))
        result = ch._handle_request("env", bytes(data))
        assert result is True

    def test_handle_request_server_mode_x11_req(self):
        """Server mode x11-req request (lines 881-898)."""
        from spindlex.protocol.utils import write_string, write_uint32

        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        server_iface.check_channel_x11_request.return_value = True
        transport._server_interface = server_iface

        data = bytearray()
        data.append(0)  # single_connection = False
        data.extend(write_string(b"MIT-MAGIC-COOKIE-1"))
        data.extend(write_string(b"abcdef1234567890"))
        data.extend(write_uint32(0))
        result = ch._handle_request("x11-req", bytes(data))
        assert result is True

    def test_handle_request_server_mode_unknown_returns_false(self):
        """Unknown type in server mode returns False (line 901)."""
        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        transport._server_interface = server_iface

        result = ch._handle_request("totally-unknown", b"")
        assert result is False

    def test_handle_request_server_mode_exception_returns_false(self):
        """Exception in server handler returns False (lines 903-904)."""
        ch, transport = make_channel()
        transport._server_mode = True
        server_iface = MagicMock()
        server_iface.check_channel_shell_request.side_effect = RuntimeError("boom")
        transport._server_interface = server_iface

        result = ch._handle_request("shell", b"")
        assert result is False
