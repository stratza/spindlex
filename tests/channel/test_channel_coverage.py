"""
Extended coverage tests for transport/channel.py.
Covers: EOF handling, stderr, window adjust, channel request callbacks,
send_eof, recv_stderr, exec_command, invoke_shell, request_pty,
recv_exit_status, send_exit_status, and close.
"""

from unittest.mock import MagicMock

import pytest

from spindlex.exceptions import ChannelException
from spindlex.transport.channel import Channel

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_transport():
    t = MagicMock()
    t.active = True
    t._server_mode = False
    return t


@pytest.fixture
def channel(mock_transport):
    c = Channel(mock_transport, channel_id=5)
    c._remote_channel_id = 50
    c._remote_window_size = 8192
    c._remote_max_packet_size = 4096
    c._local_window_size = 8192
    return c


# ---------------------------------------------------------------------------
# settimeout / gettimeout
# ---------------------------------------------------------------------------


class TestTimeoutAccessors:
    def test_set_and_get_timeout(self, channel):
        channel.settimeout(5.0)
        assert channel.gettimeout() == 5.0

    def test_default_timeout_is_none(self, channel):
        assert channel.gettimeout() is None

    def test_set_none_timeout(self, channel):
        channel.settimeout(None)
        assert channel.gettimeout() is None


# ---------------------------------------------------------------------------
# send / send_eof
# ---------------------------------------------------------------------------


class TestSendEOF:
    def test_send_eof_sends_once(self, channel, mock_transport):
        channel.send_eof()
        mock_transport._send_channel_eof.assert_called_once_with(5)
        assert channel._eof_sent

    def test_send_eof_idempotent(self, channel, mock_transport):
        channel.send_eof()
        channel.send_eof()  # second call should be no-op
        mock_transport._send_channel_eof.assert_called_once()

    def test_send_eof_on_closed_raises(self, channel):
        channel._closed = True
        with pytest.raises(ChannelException, match="closed"):
            channel.send_eof()

    def test_send_eof_not_opened_raises(self, channel):
        channel._remote_channel_id = None
        with pytest.raises(ChannelException, match="not properly opened"):
            channel.send_eof()

    def test_send_eof_transport_error_raises(self, channel, mock_transport):
        mock_transport._send_channel_eof.side_effect = RuntimeError("sock error")
        with pytest.raises(ChannelException, match="Failed to send EOF"):
            channel.send_eof()

    def test_send_string_data(self, channel, mock_transport):
        result = channel.send("hello")
        assert result == 5
        mock_transport._send_channel_data.assert_called_once_with(5, b"hello")

    def test_send_empty_data_returns_zero(self, channel):
        result = channel.send(b"")
        assert result == 0

    def test_send_on_eof_sent_raises(self, channel):
        channel._eof_sent = True
        with pytest.raises(ChannelException, match="EOF already sent"):
            channel.send(b"data")


# ---------------------------------------------------------------------------
# recv_stderr
# ---------------------------------------------------------------------------


class TestRecvStderr:
    def test_recv_stderr_from_buffer(self, channel):
        channel._stderr_buffer.append(b"err data")
        result = channel.recv_stderr(100)
        assert result == b"err data"

    def test_recv_stderr_zero_returns_empty(self, channel):
        assert channel.recv_stderr(0) == b""

    def test_recv_stderr_split(self, channel):
        channel._stderr_buffer.append(b"long error message")
        result = channel.recv_stderr(4)
        assert result == b"long"
        # remainder stays in buffer
        assert channel._stderr_buffer[0] == b" error message"

    def test_recv_stderr_after_eof(self, channel):
        channel._eof_received = True
        result = channel.recv_stderr(10)
        assert result == b""

    def test_recv_stderr_timeout_raises(self, channel, mock_transport):
        mock_transport._pump.return_value = None
        channel.settimeout(0.05)
        with pytest.raises(ChannelException, match="Timeout receiving stderr data"):
            channel.recv_stderr(10)

    def test_recv_stderr_closed_raises(self, channel):
        channel._closed = True
        with pytest.raises(ChannelException, match="closed"):
            channel.recv_stderr(10)


# ---------------------------------------------------------------------------
# recv
# ---------------------------------------------------------------------------


class TestRecv:
    def test_recv_from_buffer(self, channel):
        channel._handle_data(b"hello world")
        result = channel.recv(5)
        assert result == b"hello"

    def test_recv_all_available(self, channel):
        channel._handle_data(b"hi")
        result = channel.recv(100)
        assert result == b"hi"

    def test_recv_zero_returns_empty(self, channel):
        assert channel.recv(0) == b""

    def test_recv_eof_returns_empty(self, channel):
        channel._eof_received = True
        result = channel.recv(10)
        assert result == b""

    def test_recv_splits_chunk(self, channel):
        channel._handle_data(b"abcdef")
        r1 = channel.recv(3)
        assert r1 == b"abc"
        r2 = channel.recv(10)
        assert r2 == b"def"


# ---------------------------------------------------------------------------
# recv_exactly
# ---------------------------------------------------------------------------


class TestRecvExactly:
    def test_recv_exactly_success(self, channel):
        channel._handle_data(b"exactdata")
        result = channel.recv_exactly(4)
        assert result == b"exac"

    def test_recv_exactly_eof_raises(self, channel):
        channel._eof_received = True
        with pytest.raises(ChannelException, match="Connection closed"):
            channel.recv_exactly(5)


# ---------------------------------------------------------------------------
# exec_command, invoke_shell, invoke_subsystem
# ---------------------------------------------------------------------------


class TestChannelRequests:
    def _make_channel_with_immediate_success(self, mock_transport):
        c = Channel(mock_transport, channel_id=7)
        c._remote_channel_id = 70
        c._remote_window_size = 8192
        c._remote_max_packet_size = 4096

        # Simulate immediate request success by setting state in send_channel_request
        def fake_send_request(channel_id, req_type, want_reply, data=b""):
            if want_reply:
                c._request_success = True
                c._request_event.set()

        mock_transport._send_channel_request.side_effect = fake_send_request
        return c

    def test_exec_command_success(self, mock_transport):
        c = self._make_channel_with_immediate_success(mock_transport)
        c.exec_command("echo hello")
        mock_transport._send_channel_request.assert_called()

    def test_exec_command_empty_raises(self, channel):
        with pytest.raises(ChannelException, match="cannot be empty"):
            channel.exec_command("")

    def test_invoke_shell_success(self, mock_transport):
        c = self._make_channel_with_immediate_success(mock_transport)
        c.invoke_shell()
        args = mock_transport._send_channel_request.call_args[0]
        assert args[1] == "shell"

    def test_invoke_subsystem_success(self, mock_transport):
        c = self._make_channel_with_immediate_success(mock_transport)
        c.invoke_subsystem("sftp")
        args = mock_transport._send_channel_request.call_args[0]
        assert args[1] == "subsystem"

    def test_invoke_subsystem_empty_raises(self, channel):
        with pytest.raises(ChannelException, match="cannot be empty"):
            channel.invoke_subsystem("")

    def test_request_pty_success(self, mock_transport):
        c = self._make_channel_with_immediate_success(mock_transport)
        c.request_pty(term="xterm", width=80, height=24)
        args = mock_transport._send_channel_request.call_args[0]
        assert args[1] == "pty-req"

    def test_send_channel_request_no_reply(self, channel, mock_transport):
        result = channel.send_channel_request("env", want_reply=False, data=b"x")
        assert result is True
        mock_transport._send_channel_request.assert_called_with(5, "env", False, b"x")

    def test_send_channel_request_closed_raises(self, channel):
        channel._closed = True
        with pytest.raises(ChannelException, match="closed"):
            channel.send_channel_request("exec", want_reply=True)


# ---------------------------------------------------------------------------
# exit status
# ---------------------------------------------------------------------------


class TestExitStatus:
    def test_get_exit_status_default(self, channel):
        assert channel.get_exit_status() == -1

    def test_get_exit_status_set(self, channel):
        channel._handle_exit_status(42)
        assert channel.get_exit_status() == 42

    def test_recv_exit_status_when_already_set(self, channel, mock_transport):
        channel._exit_status = 0
        assert channel.recv_exit_status() == 0
        mock_transport._pump.assert_not_called()

    def test_recv_exit_status_polls(self, channel, mock_transport):
        # Set exit status after first pump call
        call_count = [0]

        def pump_side_effect():
            call_count[0] += 1
            if call_count[0] >= 2:
                channel._exit_status = 99

        mock_transport._pump.side_effect = pump_side_effect
        result = channel.recv_exit_status()
        assert result == 99

    def test_send_exit_status(self, channel, mock_transport):
        channel.send_exit_status(0)
        mock_transport._send_channel_request.assert_called()
        call_args = mock_transport._send_channel_request.call_args[0]
        assert call_args[1] == "exit-status"


# ---------------------------------------------------------------------------
# Internal handlers
# ---------------------------------------------------------------------------


class TestInternalHandlers:
    def test_handle_data(self, channel):
        channel._handle_data(b"incoming")
        assert channel._recv_buffer[0] == b"incoming"
        assert channel._data_event.is_set()

    def test_handle_data_ignores_closed(self, channel):
        channel._closed = True
        channel._handle_data(b"ignored")
        assert len(channel._recv_buffer) == 0

    def test_handle_extended_data_stderr(self, channel):
        channel._handle_extended_data(1, b"stderr")
        assert channel._stderr_buffer[0] == b"stderr"
        assert channel._data_event.is_set()

    def test_handle_extended_data_non_stderr_ignored(self, channel):
        channel._handle_extended_data(2, b"other")
        assert len(channel._stderr_buffer) == 0

    def test_handle_eof(self, channel):
        channel._handle_eof()
        assert channel._eof_received
        assert channel._data_event.is_set()

    def test_handle_close(self, channel):
        channel._handle_close()
        assert channel._closed
        assert channel._data_event.is_set()
        assert channel._window_event.is_set()

    def test_handle_window_adjust(self, channel):
        old = channel._remote_window_size
        channel._handle_window_adjust(1024)
        assert channel._remote_window_size == old + 1024
        assert channel._window_event.is_set()

    def test_handle_request_success(self, channel):
        channel._handle_request_success()
        assert channel._request_success is True
        assert channel._request_event.is_set()

    def test_handle_request_failure(self, channel):
        channel._handle_request_failure()
        assert channel._request_success is False
        assert channel._request_event.is_set()

    def test_handle_exit_status(self, channel):
        channel._handle_exit_status(7)
        assert channel._exit_status == 7


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


class TestClose:
    def test_close_calls_transport(self, channel, mock_transport):
        channel.close()
        assert channel._closed
        mock_transport._close_channel.assert_called_once_with(5)

    def test_close_idempotent(self, channel, mock_transport):
        channel.close()
        channel.close()
        mock_transport._close_channel.assert_called_once()

    def test_context_manager_closes(self, channel, mock_transport):
        with channel as c:
            assert c is channel
        assert channel._closed
        mock_transport._close_channel.assert_called_once_with(5)

    def test_context_manager_closes_on_exception(self, channel, mock_transport):
        with pytest.raises(RuntimeError):
            with channel:
                raise RuntimeError("boom")
        assert channel._closed
        mock_transport._close_channel.assert_called_once_with(5)

    def test_adjust_window_triggers_window_adjust(self, channel, mock_transport):
        # Force local_window_size to be low to trigger adjust
        channel._local_window_size = 100  # well below DEFAULT_WINDOW_SIZE // 2
        channel._adjust_window(50)
        mock_transport._send_channel_window_adjust.assert_called()
