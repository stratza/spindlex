import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import (
    AuthenticationException,
    ProtocolException,
    TransportException,
)
from spindlex.protocol.constants import *
from spindlex.protocol.messages import (
    ChannelCloseMessage,
    ChannelDataMessage,
    ChannelOpenConfirmationMessage,
    ChannelOpenFailureMessage,
    KexInitMessage,
    Message,
    ServiceAcceptMessage,
    UserAuthFailureMessage,
    UserAuthSuccessMessage,
)
from spindlex.transport.transport import Transport


@pytest.fixture
def mock_socket():
    sock = MagicMock(spec=socket.socket)
    sock.gettimeout.return_value = 30
    return sock


def test_handshake_client(mock_socket):
    transport = Transport(mock_socket)

    # Mock receiving server version
    mock_socket.recv.side_effect = [bytes([b]) for b in b"SSH-2.0-OpenSSH_8.0\r\n"]

    transport._do_handshake()

    assert transport._server_version == "SSH-2.0-OpenSSH_8.0"
    # Check that client version was sent
    sent_data = b"".join(call[0][0] for call in mock_socket.sendall.call_args_list)
    assert sent_data.startswith(b"SSH-2.0-spindlex")


def test_handshake_server(mock_socket):
    transport = Transport(mock_socket)
    transport._server_mode = True

    # Mock receiving client version
    mock_socket.recv.side_effect = [bytes([b]) for b in b"SSH-2.0-TestClient\n"]

    transport._do_handshake()

    assert transport._server_version == "SSH-2.0-TestClient"
    # Check that server version was sent (server sends first in _do_handshake logic if server_mode)
    sent_data = b"".join(call[0][0] for call in mock_socket.sendall.call_args_list)
    assert sent_data.startswith(b"SSH-2.0-spindlex")


def test_handshake_timeout(mock_socket):
    transport = Transport(mock_socket)
    mock_socket.recv.side_effect = socket.timeout()

    with pytest.raises(TransportException, match="Timeout"):
        transport._do_handshake()


def test_handshake_invalid_version(mock_socket):
    transport = Transport(mock_socket)
    mock_socket.recv.side_effect = [bytes([b]) for b in b"INVALID\r\n"]

    with pytest.raises(ProtocolException, match="Invalid version string"):
        transport._do_handshake()


def test_auth_password_success(mock_socket):
    transport = Transport(mock_socket)
    transport._active = True

    # Mock _expect_message
    with patch.object(transport, "_expect_message") as mock_expect:
        # First call for ServiceRequest response
        mock_expect.side_effect = [
            ServiceAcceptMessage(SERVICE_USERAUTH),
            UserAuthSuccessMessage(),
        ]

        result = transport.auth_password("alice", "password")

        assert result is True
        assert transport.authenticated is True


def test_auth_password_failure(mock_socket):
    transport = Transport(mock_socket)
    transport._active = True

    with patch.object(transport, "_expect_message") as mock_expect:
        mock_expect.side_effect = [
            ServiceAcceptMessage(SERVICE_USERAUTH),
            UserAuthFailureMessage(authentications=["password"]),
        ]

        result = transport.auth_password("alice", "wrong")
        assert result is False
        assert not transport.authenticated


def test_build_packet_unencrypted():
    transport = Transport(MagicMock())
    payload = b"hello world"
    packet = transport._build_packet(payload)

    # Packet length (4) + padding length (1) + payload (11) + padding (min 4) = 20
    # Must be multiple of 8. Next multiple is 24.
    assert len(packet) % 8 == 0
    packet_len = struct.unpack(">I", packet[:4])[0]
    assert packet_len == len(packet) - 4
    assert packet[4] >= 4  # padding length


def test_recv_bytes_full(mock_socket):
    transport = Transport(mock_socket)
    mock_socket.recv.side_effect = [b"abc", b"def"]

    data = transport._recv_bytes(6)
    assert data == b"abcdef"


def test_recv_bytes_closed(mock_socket):
    transport = Transport(mock_socket)
    mock_socket.recv.return_value = b""

    with pytest.raises(TransportException, match="Connection closed"):
        transport._recv_bytes(5)


def test_start_client_failure(mock_socket):
    transport = Transport(mock_socket)
    # Trigger an exception during handshake
    mock_socket.recv.side_effect = Exception("Generic error")

    with pytest.raises(TransportException, match="Handshake failed"):
        transport.start_client()

    assert not transport.active


def test_open_channel_session_success(mock_socket):
    transport = Transport(mock_socket)
    transport._active = True
    transport._authenticated = True

    with patch.object(transport, "_expect_message") as mock_expect:
        mock_expect.return_value = ChannelOpenConfirmationMessage(
            recipient_channel=0,
            sender_channel=10,
            initial_window_size=1024,
            maximum_packet_size=512,
        )

        channel = transport.open_channel("session")

        assert channel._remote_channel_id == 10
        assert channel._remote_window_size == 1024
        assert transport._channels[0] == channel


def test_open_channel_failure(mock_socket):
    transport = Transport(mock_socket)
    transport._active = True
    transport._authenticated = True

    with patch.object(transport, "_expect_message") as mock_expect:
        mock_expect.return_value = ChannelOpenFailureMessage(
            recipient_channel=0,
            reason_code=SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
            description="No session for you",
        )

        with pytest.raises(TransportException, match="Channel open failed"):
            transport.open_channel("session")


def test_global_request_success(mock_socket):
    transport = Transport(mock_socket)
    transport._active = True

    with patch.object(transport, "_expect_message") as mock_expect:
        mock_expect.return_value = Message(MSG_REQUEST_SUCCESS)

        result = transport._send_global_request("test-request", want_reply=True)
        assert result is True


def test_handle_channel_data(mock_socket):
    transport = Transport(mock_socket)
    channel = MagicMock()
    transport._channels[1] = channel

    msg = ChannelDataMessage(recipient_channel=1, data=b"hi")
    transport._handle_channel_message(msg)

    channel._handle_data.assert_called_with(b"hi")


def test_handle_channel_close(mock_socket):
    transport = Transport(mock_socket)
    channel = MagicMock()
    channel.recipient_channel = 1
    transport._channels[1] = channel

    msg = ChannelCloseMessage(recipient_channel=1)
    transport._handle_channel_message(msg)

    channel._handle_close.assert_called()
    assert 1 not in transport._channels
