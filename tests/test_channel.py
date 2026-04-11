from unittest.mock import MagicMock, patch

import pytest
from spindlex.exceptions import ChannelException
from spindlex.protocol.constants import *
from spindlex.transport.channel import Channel


@pytest.fixture
def mock_transport():
    transport = MagicMock()
    transport._server_mode = False
    return transport


@pytest.fixture
def channel(mock_transport):
    c = Channel(mock_transport, 1)
    c._remote_channel_id = 10
    c._remote_window_size = 1000
    c._remote_max_packet_size = 500
    return c


def test_channel_send(channel, mock_transport):
    # Test normal send
    res = channel.send(b"hello")
    assert res == 5
    mock_transport._send_channel_data.assert_called_with(1, b"hello")
    assert channel._remote_window_size == 995

    # Test window limit
    channel._remote_window_size = 3
    res = channel.send(b"hello")
    assert res == 3
    mock_transport._send_channel_data.assert_called_with(1, b"hel")

    # Test max packet size limit
    channel._remote_window_size = 1000
    channel._remote_max_packet_size = 2
    res = channel.send(b"hello")
    assert res == 2
    mock_transport._send_channel_data.assert_called_with(1, b"he")


def test_channel_send_errors(channel):
    channel._closed = True
    with pytest.raises(ChannelException, match="closed"):
        channel.send(b"data")

    channel._closed = False
    channel._remote_channel_id = None
    with pytest.raises(ChannelException, match="not properly opened"):
        channel.send(b"data")


def test_channel_recv(channel, mock_transport):
    # Fill buffer
    channel._handle_data(b"chunk1")
    channel._handle_data(b"chunk2")

    assert channel.recv(3) == b"chu"
    assert channel.recv(10) == b"nk1"
    assert channel.recv(10) == b"chunk2"

    # Test EOF
    channel._handle_eof()
    assert channel.recv(10) == b""


def test_channel_recv_timeout(channel, mock_transport):
    channel.settimeout(0.1)
    # Mock transport._recv_message to do nothing
    with pytest.raises(ChannelException, match="Timeout"):
        channel.recv(10)


def test_channel_exec_command(channel):
    with patch.object(channel, "send_channel_request") as mock_req:
        mock_req.return_value = True
        channel.exec_command("ls")
        assert mock_req.called


def test_channel_invoke_shell_subsystem(channel):
    with patch.object(channel, "send_channel_request") as mock_req:
        mock_req.return_value = True
        channel.invoke_shell()
        channel.invoke_subsystem("sftp")
        assert mock_req.call_count == 2


def test_channel_request_pty(channel):
    with patch.object(channel, "send_channel_request") as mock_req:
        mock_req.return_value = True
        channel.request_pty()
        assert mock_req.called


def test_channel_send_eof_close(channel, mock_transport):
    channel.send_eof()
    mock_transport._send_channel_eof.assert_called_with(1)
    assert channel._eof_sent

    channel.close()
    mock_transport._close_channel.assert_called_with(1)
    assert channel.closed


def test_channel_handle_extended_data(channel):
    channel._handle_extended_data(1, b"stderr data")
    assert channel.recv_stderr(100) == b"stderr data"


def test_channel_handle_exit_status(channel):
    channel._handle_exit_status(42)
    assert channel.get_exit_status() == 42


def test_channel_handle_request_client_mode(channel, mock_transport):
    # Client mode, should reject most requests
    assert channel._handle_request("shell", b"") is False
    assert channel._handle_request("exit-status", b"") is True


def test_channel_handle_request_server_mode(channel, mock_transport):
    mock_transport._server_mode = True
    mock_server = MagicMock()
    mock_transport._server_interface = mock_server

    mock_server.check_channel_shell_request.return_value = True
    assert channel._handle_request("shell", b"") is True

    mock_server.check_channel_exec_request.return_value = False
    assert channel._handle_request("exec", b"\x00\x00\x00\x02ls") is False
