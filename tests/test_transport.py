import socket
from unittest.mock import MagicMock

import pytest
from spindlex.protocol.messages import Message
from spindlex.transport.transport import Transport


@pytest.fixture
def mock_socket():
    sock = MagicMock(spec=socket.socket)
    return sock


def test_transport_init(mock_socket):
    transport = Transport(mock_socket)
    assert transport._socket == mock_socket
    assert not transport.active


def test_transport_send_message(mock_socket):
    transport = Transport(mock_socket)
    transport._active = True  # Mocking active state

    msg = Message(90)  # MSG_CHANNEL_OPEN
    msg.add_string(b"session")

    transport._send_message(msg)

    # Check that socket.sendall was called
    assert mock_socket.sendall.called
    # Unencrypted message starts with length (4 bytes) + padding length (1 byte)
    sent_data = mock_socket.sendall.call_args[0][0]
    assert len(sent_data) >= 5


def test_transport_close(mock_socket):
    transport = Transport(mock_socket)
    transport._active = True

    transport.close()
    assert not transport.active
    assert mock_socket.close.called
