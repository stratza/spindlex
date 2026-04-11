import socket
from unittest.mock import MagicMock, patch

import pytest
from spindlex.exceptions import TransportException
from spindlex.protocol.constants import MSG_KEXINIT
from spindlex.transport.transport import Transport


@pytest.fixture
def mock_socket():
    sock = MagicMock(spec=socket.socket)
    sock.gettimeout.return_value = 10.0
    return sock


def test_recv_bytes_buffering(mock_socket):
    transport = Transport(mock_socket)
    mock_socket.recv.return_value = b"0123456789"
    data1 = transport._recv_bytes(2)
    assert data1 == b"01"
    assert transport._packet_buffer == b"23456789"
    assert mock_socket.recv.call_count == 1
    data2 = transport._recv_bytes(3)
    assert data2 == b"234"
    assert transport._packet_buffer == b"56789"
    mock_socket.recv.return_value = b"ABC"
    data3 = transport._recv_bytes(8)
    assert data3 == b"56789ABC"
    assert transport._packet_buffer == b""


def test_recv_version_with_buffering(mock_socket):
    transport = Transport(mock_socket)
    mock_socket.recv.return_value = b"SSH-2.0-Test\r\nNEXT_DATA"
    transport._recv_version()
    assert transport._server_version == "SSH-2.0-Test"
    assert transport._packet_buffer == b"NEXT_DATA"


def test_recv_version_multi_packet(mock_socket):
    transport = Transport(mock_socket)
    mock_socket.recv.side_effect = [b"SSH-", b"2.0-", b"Test\n"]
    transport._recv_version()
    assert transport._server_version == "SSH-2.0-Test"


def test_recv_bytes_timeout_recovery(mock_socket):
    transport = Transport(mock_socket)
    mock_socket.recv.side_effect = [b"PARTIAL", socket.timeout()]
    with pytest.raises(TransportException, match="Timeout receiving data"):
        transport._recv_bytes(10)
    assert transport._packet_buffer == b"PARTIAL"


def test_transport_set_timeout(mock_socket):
    transport = Transport(mock_socket)
    transport.set_timeout(10.5)
    mock_socket.settimeout.assert_called_with(10.5)
    # mock_socket.gettimeout() was 10.0 initially, but mock_socket.gettimeout()
    # should ideally return 10.5 after settimeout if it's a real socket.
    # For MagicMock we need to update the return value.
    mock_socket.gettimeout.return_value = 10.5
    assert transport.get_timeout() == 10.5


def test_expect_message_timeout(mock_socket):
    transport = Transport(mock_socket)
    transport._active = True
    # Mock _read_message to simulate timeout
    with patch.object(transport, "_read_message") as mock_read:
        mock_read.side_effect = TransportException("Timeout")
        with pytest.raises(TransportException, match="Timeout"):
            transport._expect_message(MSG_KEXINIT)


def test_read_message_error_handling(mock_socket):
    transport = Transport(mock_socket)
    # Mock _recv_bytes to fail during packet length read
    mock_socket.recv.side_effect = Exception("Unrecoverable error")
    with pytest.raises(
        TransportException, match="Failed to receive message: Unrecoverable error"
    ):
        transport._read_message()
