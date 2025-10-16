"""
Tests for SSH transport layer functionality.
"""

import socket
import threading
import time
from unittest.mock import Mock, MagicMock, patch
import pytest

from ssh_library.transport.transport import Transport
from ssh_library.transport.channel import Channel
from ssh_library.exceptions import TransportException, AuthenticationException, ProtocolException
from ssh_library.protocol.constants import *
from ssh_library.protocol.messages import *


class MockSocket:
    """Mock socket for testing transport functionality."""
    
    def __init__(self):
        self.sent_data = bytearray()
        self.recv_data = bytearray()
        self.recv_offset = 0
        self.timeout = None
        self.closed = False
    
    def sendall(self, data):
        if self.closed:
            raise socket.error("Socket closed")
        self.sent_data.extend(data)
    
    def recv(self, size):
        if self.closed:
            raise socket.error("Socket closed")
        
        if self.recv_offset >= len(self.recv_data):
            if self.timeout is not None and self.timeout > 0:
                raise socket.timeout("Timeout")
            return b""
        
        end_offset = min(self.recv_offset + size, len(self.recv_data))
        data = bytes(self.recv_data[self.recv_offset:end_offset])
        self.recv_offset = end_offset
        return data
    
    def settimeout(self, timeout):
        self.timeout = timeout
    
    def gettimeout(self):
        return self.timeout
    
    def close(self):
        self.closed = True
    
    def add_recv_data(self, data):
        """Add data to be received."""
        self.recv_data.extend(data)
    
    def get_sent_data(self):
        """Get all sent data."""
        return bytes(self.sent_data)
    
    def clear_sent_data(self):
        """Clear sent data buffer."""
        self.sent_data.clear()


class TestTransportBasic:
    """Test basic transport functionality."""
    
    def test_transport_creation(self):
        """Test creating transport instance."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        assert transport._socket is mock_socket
        assert not transport.active
        assert not transport.server_mode
        assert not transport.authenticated
        assert transport.session_id is None
    
    def test_transport_close(self):
        """Test transport close functionality."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Add a mock channel
        mock_channel = Mock()
        transport._channels[1] = mock_channel
        
        transport.close()
        
        assert not transport.active
        assert mock_socket.closed
        assert len(transport._channels) == 0
        mock_channel.close.assert_called_once()
    
    def test_transport_properties(self):
        """Test transport properties."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Test initial state
        assert not transport.active
        assert not transport.server_mode
        assert not transport.authenticated
        assert transport.session_id is None
        
        # Modify state
        transport._active = True
        transport._server_mode = True
        transport._authenticated = True
        transport._session_id = b"test_session"
        
        assert transport.active
        assert transport.server_mode
        assert transport.authenticated
        assert transport.session_id == b"test_session"


class TestTransportHandshake:
    """Test SSH handshake functionality."""
    
    def test_send_version(self):
        """Test sending SSH version string."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        transport._send_version()
        
        sent_data = mock_socket.get_sent_data()
        assert sent_data.startswith(b"SSH-2.0-")
        assert sent_data.endswith(b"\r\n")
    
    def test_recv_version_valid(self):
        """Test receiving valid SSH version string."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Add valid version string to receive buffer
        version_line = "SSH-2.0-OpenSSH_8.0\r\n"
        mock_socket.add_recv_data(version_line.encode())
        
        transport._recv_version()
        
        assert transport._server_version == "SSH-2.0-OpenSSH_8.0"
    
    def test_recv_version_invalid_protocol(self):
        """Test receiving invalid protocol version."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Add invalid version string
        version_line = "SSH-1.5-OldSSH\r\n"
        mock_socket.add_recv_data(version_line.encode())
        
        with pytest.raises(ProtocolException, match="Unsupported protocol version"):
            transport._recv_version()
    
    def test_recv_version_malformed(self):
        """Test receiving malformed version string."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Add malformed version string
        version_line = "NOT-SSH\r\n"
        mock_socket.add_recv_data(version_line.encode())
        
        with pytest.raises(ProtocolException, match="Invalid version string"):
            transport._recv_version()
    
    def test_recv_version_timeout(self):
        """Test version receive timeout."""
        mock_socket = MockSocket()
        mock_socket.timeout = 0.1  # Short timeout
        transport = Transport(mock_socket)
        
        # Don't add any data - should timeout
        with pytest.raises(TransportException, match="Timeout during version exchange"):
            transport._recv_version()
    
    def test_recv_version_too_long(self):
        """Test receiving overly long version string."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Add very long version string
        long_version = "SSH-2.0-" + "A" * 300 + "\r\n"
        mock_socket.add_recv_data(long_version.encode())
        
        with pytest.raises(ProtocolException, match="Version line too long"):
            transport._recv_version()


class TestTransportPacketHandling:
    """Test SSH packet handling functionality."""
    
    def test_build_packet(self):
        """Test building SSH packet from payload."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        payload = b"test payload"
        packet = transport._build_packet(payload)
        
        # Check packet structure
        assert len(packet) >= len(payload) + 5  # length + padding_length + payload + padding
        
        # Check packet length field
        packet_length = struct.unpack(">I", packet[:4])[0]
        assert packet_length == len(packet) - 4
        
        # Check padding length
        padding_length = packet[4]
        assert padding_length >= MIN_PADDING_SIZE
    
    def test_recv_bytes(self):
        """Test receiving exact number of bytes."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        test_data = b"Hello, World!"
        mock_socket.add_recv_data(test_data)
        
        received = transport._recv_bytes(len(test_data))
        assert received == test_data
    
    def test_recv_bytes_partial(self):
        """Test receiving bytes in multiple chunks."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Override recv to return data in chunks
        original_recv = mock_socket.recv
        call_count = 0
        
        def chunked_recv(size):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return b"Hello"
            elif call_count == 2:
                return b", Wor"
            else:
                return b"ld!"
        
        mock_socket.recv = chunked_recv
        
        received = transport._recv_bytes(13)
        assert received == b"Hello, World!"
    
    def test_recv_bytes_connection_closed(self):
        """Test handling connection close during receive."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Mock recv to return empty bytes (connection closed)
        mock_socket.recv = lambda size: b""
        
        with pytest.raises(TransportException, match="Connection closed unexpectedly"):
            transport._recv_bytes(10)
    
    def test_send_message(self):
        """Test sending SSH message."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Create a simple message
        msg = Message(MSG_IGNORE)
        msg.add_string("test")
        
        transport._send_message(msg)
        
        # Check that data was sent
        sent_data = mock_socket.get_sent_data()
        assert len(sent_data) > 0
        
        # Check sequence number was incremented
        assert transport._sequence_number_out == 1


class TestTransportAuthentication:
    """Test authentication functionality."""
    
    def setup_method(self):
        """Set up test transport with mocked handshake."""
        self.mock_socket = MockSocket()
        self.transport = Transport(self.mock_socket)
        
        # Mock the transport as active and handshake complete
        self.transport._active = True
        self.transport._session_id = b"test_session_id"
    
    def test_auth_password_not_active(self):
        """Test password auth when transport not active."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        with pytest.raises(AuthenticationException, match="Transport not active"):
            transport.auth_password("user", "pass")
    
    def test_auth_password_already_authenticated(self):
        """Test password auth when already authenticated."""
        self.transport._authenticated = True
        
        result = self.transport.auth_password("user", "pass")
        assert result is True
    
    def test_build_password_auth_data(self):
        """Test building password authentication data."""
        data = self.transport._build_password_auth_data("secret")
        
        # Should contain: boolean(False) + string("secret")
        assert len(data) > 5  # At least boolean + string length + "secret"
        assert data[0] == 0  # False boolean
    
    def test_auth_publickey_not_active(self):
        """Test public key auth when transport not active."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        mock_key = Mock()
        with pytest.raises(AuthenticationException, match="Transport not active"):
            transport.auth_publickey("user", mock_key)
    
    def test_auth_publickey_already_authenticated(self):
        """Test public key auth when already authenticated."""
        self.transport._authenticated = True
        
        mock_key = Mock()
        result = self.transport.auth_publickey("user", mock_key)
        assert result is True
    
    def test_build_publickey_query_data(self):
        """Test building public key query data."""
        mock_key = Mock()
        mock_key.get_name.return_value = "ssh-ed25519"
        mock_key.get_public_key_bytes.return_value = b"public_key_data"
        
        data = self.transport._build_publickey_query_data(mock_key)
        
        # Should contain: boolean(False) + algorithm name + public key
        assert len(data) > 10
        assert data[0] == 0  # False boolean
    
    def test_build_signature_data(self):
        """Test building signature data for public key auth."""
        mock_key = Mock()
        mock_key.get_name.return_value = "ssh-ed25519"
        mock_key.get_public_key_bytes.return_value = b"public_key_data"
        
        data = self.transport._build_signature_data("testuser", mock_key)
        
        # Should contain session_id + MSG_USERAUTH_REQUEST + username + service + method + ...
        assert len(data) > 20
        assert b"test_session_id" in data
        assert b"testuser" in data
    
    def test_auth_keyboard_interactive_not_active(self):
        """Test keyboard-interactive auth when transport not active."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        handler = Mock()
        with pytest.raises(AuthenticationException, match="Transport not active"):
            transport.auth_keyboard_interactive("user", handler)
    
    def test_build_keyboard_interactive_data(self):
        """Test building keyboard-interactive auth data."""
        data = self.transport._build_keyboard_interactive_data()
        
        # Should contain: string("") + string("") for language and submethods
        assert len(data) == 8  # Two empty strings = 4 bytes each
    
    def test_build_info_response(self):
        """Test building keyboard-interactive info response."""
        responses = ["answer1", "answer2"]
        msg = self.transport._build_info_response(responses)
        
        assert msg.msg_type == MSG_USERAUTH_INFO_RESPONSE
        # Message should contain count + responses


class TestTransportChannels:
    """Test channel management functionality."""
    
    def setup_method(self):
        """Set up test transport."""
        self.mock_socket = MockSocket()
        self.transport = Transport(self.mock_socket)
        
        # Mock the transport as active and authenticated
        self.transport._active = True
        self.transport._authenticated = True
    
    def test_open_channel_not_active(self):
        """Test opening channel when transport not active."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        with pytest.raises(TransportException, match="Transport not active"):
            transport.open_channel("session")
    
    def test_open_channel_not_authenticated(self):
        """Test opening channel when not authenticated."""
        self.transport._authenticated = False
        
        with pytest.raises(TransportException, match="Transport not authenticated"):
            self.transport.open_channel("session")
    
    def test_build_direct_tcpip_data(self):
        """Test building direct-tcpip channel data."""
        dest_addr = ("example.com", 80)
        data = self.transport._build_direct_tcpip_data(dest_addr)
        
        # Should contain: dest_host + dest_port + orig_ip + orig_port
        assert len(data) > 10
        assert b"example.com" in data
    
    def test_close_channel(self):
        """Test closing a channel."""
        # Create a mock channel
        mock_channel = Mock()
        mock_channel.closed = False
        mock_channel._remote_channel_id = 1
        
        self.transport._channels[0] = mock_channel
        
        self.transport._close_channel(0)
        
        # Channel should be removed from dict
        assert 0 not in self.transport._channels
    
    def test_close_nonexistent_channel(self):
        """Test closing a non-existent channel."""
        # Should not raise an exception
        self.transport._close_channel(999)
    
    def test_send_channel_data(self):
        """Test sending data through channel."""
        # Create a mock channel
        mock_channel = Mock()
        mock_channel._remote_channel_id = 1
        mock_channel._remote_window_size = 1000
        mock_channel._remote_max_packet_size = 500
        
        self.transport._channels[0] = mock_channel
        
        test_data = b"Hello, World!"
        self.transport._send_channel_data(0, test_data)
        
        # Check that window size was updated
        assert mock_channel._remote_window_size == 1000 - len(test_data)
    
    def test_send_channel_data_window_exceeded(self):
        """Test sending data when window size exceeded."""
        mock_channel = Mock()
        mock_channel._remote_channel_id = 1
        mock_channel._remote_window_size = 5  # Small window
        mock_channel._remote_max_packet_size = 500
        
        self.transport._channels[0] = mock_channel
        
        test_data = b"This is too much data"
        with pytest.raises(TransportException, match="Remote window size exceeded"):
            self.transport._send_channel_data(0, test_data)
    
    def test_send_channel_data_packet_size_exceeded(self):
        """Test sending data when max packet size exceeded."""
        mock_channel = Mock()
        mock_channel._remote_channel_id = 1
        mock_channel._remote_window_size = 1000
        mock_channel._remote_max_packet_size = 5  # Small packet size
        
        self.transport._channels[0] = mock_channel
        
        test_data = b"This is too much data"
        with pytest.raises(TransportException, match="Remote max packet size exceeded"):
            self.transport._send_channel_data(0, test_data)
    
    def test_send_channel_data_nonexistent_channel(self):
        """Test sending data to non-existent channel."""
        with pytest.raises(TransportException, match="Channel .* not found"):
            self.transport._send_channel_data(999, b"data")
    
    def test_send_channel_window_adjust(self):
        """Test sending channel window adjust."""
        mock_channel = Mock()
        mock_channel._remote_channel_id = 1
        mock_channel._local_window_size = 1000
        
        self.transport._channels[0] = mock_channel
        
        self.transport._send_channel_window_adjust(0, 500)
        
        # Check that local window size was updated
        assert mock_channel._local_window_size == 1500
    
    def test_handle_channel_data(self):
        """Test handling incoming channel data."""
        mock_channel = Mock()
        self.transport._channels[1] = mock_channel
        
        data_msg = ChannelDataMessage(1, b"test data")
        self.transport._handle_channel_data(data_msg)
        
        mock_channel._handle_data.assert_called_once_with(b"test data")
    
    def test_handle_channel_close(self):
        """Test handling channel close message."""
        mock_channel = Mock()
        self.transport._channels[1] = mock_channel
        
        close_msg = ChannelCloseMessage(1)
        self.transport._handle_channel_close(close_msg)
        
        mock_channel._handle_close.assert_called_once()
        assert 1 not in self.transport._channels


class TestTransportKex:
    """Test key exchange functionality."""
    
    def test_send_kexinit(self):
        """Test sending KEXINIT message."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        transport._send_kexinit()
        
        # Check that data was sent
        sent_data = mock_socket.get_sent_data()
        assert len(sent_data) > 0
    
    def test_start_kex_already_in_progress(self):
        """Test starting KEX when already in progress."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        transport._kex_in_progress = True
        
        with pytest.raises(TransportException, match="Key exchange already in progress"):
            transport._start_kex()


class TestTransportIntegration:
    """Integration tests for transport functionality."""
    
    def test_transport_lifecycle(self):
        """Test complete transport lifecycle."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Test initial state
        assert not transport.active
        assert not transport.authenticated
        
        # Test close
        transport.close()
        assert not transport.active
        assert mock_socket.closed
    
    def test_channel_lifecycle(self):
        """Test channel lifecycle within transport."""
        mock_socket = MockSocket()
        transport = Transport(mock_socket)
        
        # Set up transport state
        transport._active = True
        transport._authenticated = True
        
        # Test channel management
        assert len(transport._channels) == 0
        
        # Mock channel creation (would normally go through open_channel)
        mock_channel = Mock()
        transport._channels[1] = mock_channel
        
        assert len(transport._channels) == 1
        
        # Test channel cleanup on transport close
        transport.close()
        assert len(transport._channels) == 0
        mock_channel.close.assert_called_once()