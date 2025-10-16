"""
Tests for SSH Server Implementation

Tests server authentication, authorization, channel management,
and multi-client connection handling.
"""

import socket
import threading
import time
import unittest
from unittest.mock import Mock, patch, MagicMock

from ssh_library.server.ssh_server import SSHServer, SSHServerManager
from ssh_library.transport.transport import Transport
from ssh_library.transport.channel import Channel
from ssh_library.crypto.pkey import Ed25519Key
from ssh_library.exceptions import TransportException, AuthenticationException
from ssh_library.protocol.constants import (
    AUTH_SUCCESSFUL, AUTH_FAILED, AUTH_PARTIAL,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE, CHANNEL_SESSION
)


class TestSSHServer(unittest.TestCase):
    """Test SSH server base class functionality."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.server = SSHServer()
        self.mock_key = Mock(spec=Ed25519Key)
        self.mock_transport = Mock(spec=Transport)
        self.mock_channel = Mock(spec=Channel)
    
    def test_server_initialization(self):
        """Test SSH server initialization."""
        self.assertIsNone(self.server.get_server_key())
        self.assertEqual(len(self.server._authenticated_users), 0)
    
    def test_set_get_server_key(self):
        """Test server key management."""
        self.server.set_server_key(self.mock_key)
        self.assertEqual(self.server.get_server_key(), self.mock_key)
    
    def test_start_server_without_key(self):
        """Test starting server without setting server key."""
        mock_socket = Mock(spec=socket.socket)
        
        with self.assertRaises(TransportException) as cm:
            self.server.start_server(mock_socket)
        
        self.assertIn("Server key must be set", str(cm.exception))
    
    @patch('ssh_library.server.ssh_server.Transport')
    def test_start_server_with_key(self, mock_transport_class):
        """Test starting server with server key set."""
        mock_socket = Mock(spec=socket.socket)
        mock_transport_instance = Mock(spec=Transport)
        mock_transport_class.return_value = mock_transport_instance
        
        self.server.set_server_key(self.mock_key)
        
        result = self.server.start_server(mock_socket, timeout=30.0)
        
        mock_transport_class.assert_called_once_with(mock_socket)
        mock_transport_instance.start_server.assert_called_once_with(self.mock_key, 30.0)
        mock_transport_instance.set_server_interface.assert_called_once_with(self.server)
        self.assertEqual(result, mock_transport_instance)
    
    def test_check_auth_password_default(self):
        """Test default password authentication (should fail)."""
        result = self.server.check_auth_password("testuser", "testpass")
        self.assertEqual(result, AUTH_FAILED)
    
    def test_check_auth_publickey_default(self):
        """Test default public key authentication (should fail)."""
        result = self.server.check_auth_publickey("testuser", self.mock_key)
        self.assertEqual(result, AUTH_FAILED)
    
    def test_check_auth_keyboard_interactive_default(self):
        """Test default keyboard-interactive authentication (should fail)."""
        result = self.server.check_auth_keyboard_interactive("testuser", "")
        self.assertEqual(result, AUTH_FAILED)
    
    def test_get_allowed_auths_default(self):
        """Test default allowed authentication methods."""
        auths = self.server.get_allowed_auths("testuser")
        self.assertEqual(auths, ["password", "publickey"])
    
    def test_check_channel_request_session(self):
        """Test channel request for session type."""
        result = self.server.check_channel_request(CHANNEL_SESSION, 1)
        self.assertEqual(result, 0)  # SSH_OPEN_CONNECT_SUCCESS
    
    def test_check_channel_request_unknown(self):
        """Test channel request for unknown type."""
        result = self.server.check_channel_request("unknown-type", 1)
        self.assertEqual(result, SSH_OPEN_UNKNOWN_CHANNEL_TYPE)
    
    def test_check_channel_exec_request_default(self):
        """Test default exec request handling (should reject)."""
        result = self.server.check_channel_exec_request(self.mock_channel, b"ls -la")
        self.assertFalse(result)
    
    def test_check_channel_shell_request_default(self):
        """Test default shell request handling (should reject)."""
        result = self.server.check_channel_shell_request(self.mock_channel)
        self.assertFalse(result)
    
    def test_check_channel_subsystem_request_default(self):
        """Test default subsystem request handling (should reject)."""
        result = self.server.check_channel_subsystem_request(self.mock_channel, "sftp")
        self.assertFalse(result)
    
    def test_check_channel_pty_request_default(self):
        """Test default PTY request handling (should allow)."""
        result = self.server.check_channel_pty_request(
            self.mock_channel, "xterm", 80, 24, 640, 480, b""
        )
        self.assertTrue(result)
    
    def test_get_banner_default(self):
        """Test default banner (should be None)."""
        banner = self.server.get_banner()
        self.assertIsNone(banner)
    
    def test_check_global_request_default(self):
        """Test default global request handling (should reject)."""
        result = self.server.check_global_request("tcpip-forward", Mock())
        self.assertFalse(result)
    
    def test_on_authentication_successful(self):
        """Test authentication success callback."""
        self.server.on_authentication_successful("testuser", "password")
        self.assertTrue(self.server._authenticated_users.get("testuser", False))
    
    def test_is_channel_authorized(self):
        """Test channel authorization check."""
        # User not authenticated
        result = self.server.is_channel_authorized(self.mock_channel, "testuser")
        self.assertFalse(result)
        
        # User authenticated
        self.server.on_authentication_successful("testuser", "password")
        result = self.server.is_channel_authorized(self.mock_channel, "testuser")
        self.assertTrue(result)


class TestSSHServerManager(unittest.TestCase):
    """Test SSH server manager for multi-client connections."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_server = Mock(spec=SSHServer)
        self.mock_key = Mock(spec=Ed25519Key)
        self.server_manager = SSHServerManager(
            self.mock_server, self.mock_key, "127.0.0.1", 0  # Use port 0 for testing
        )
    
    def test_server_manager_initialization(self):
        """Test server manager initialization."""
        self.assertEqual(self.server_manager._server_interface, self.mock_server)
        self.assertEqual(self.server_manager._server_key, self.mock_key)
        self.assertEqual(self.server_manager._bind_address, "127.0.0.1")
        self.assertEqual(self.server_manager._port, 0)
        self.assertFalse(self.server_manager.is_running())
        self.assertEqual(self.server_manager.get_connection_count(), 0)
    
    def test_set_max_connections(self):
        """Test setting maximum connections."""
        self.server_manager.set_max_connections(50)
        self.assertEqual(self.server_manager._max_connections, 50)
    
    def test_set_connection_timeout(self):
        """Test setting connection timeout."""
        self.server_manager.set_connection_timeout(60.0)
        self.assertEqual(self.server_manager._connection_timeout, 60.0)
    
    def test_set_auth_timeout(self):
        """Test setting authentication timeout."""
        self.server_manager.set_auth_timeout(45.0)
        self.assertEqual(self.server_manager._auth_timeout, 45.0)
    
    @patch('socket.socket')
    def test_start_server_success(self, mock_socket_class):
        """Test successful server start."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        
        # Mock socket operations
        mock_socket.bind.return_value = None
        mock_socket.listen.return_value = None
        
        self.server_manager.start_server()
        
        self.assertTrue(self.server_manager.is_running())
        mock_socket.setsockopt.assert_called()
        mock_socket.bind.assert_called_once_with(("127.0.0.1", 0))
        mock_socket.listen.assert_called_once_with(5)
    
    @patch('socket.socket')
    def test_start_server_already_running(self, mock_socket_class):
        """Test starting server when already running."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_socket.bind.return_value = None
        mock_socket.listen.return_value = None
        
        # Start server first time
        self.server_manager.start_server()
        
        # Try to start again
        with self.assertRaises(TransportException) as cm:
            self.server_manager.start_server()
        
        self.assertIn("already running", str(cm.exception))
    
    @patch('socket.socket')
    def test_start_server_bind_failure(self, mock_socket_class):
        """Test server start with bind failure."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_socket.bind.side_effect = OSError("Address already in use")
        
        with self.assertRaises(TransportException) as cm:
            self.server_manager.start_server()
        
        self.assertIn("Failed to start SSH server", str(cm.exception))
        self.assertFalse(self.server_manager.is_running())
    
    @patch('socket.socket')
    def test_stop_server(self, mock_socket_class):
        """Test stopping server."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket
        mock_socket.bind.return_value = None
        mock_socket.listen.return_value = None
        
        # Start server
        self.server_manager.start_server()
        self.assertTrue(self.server_manager.is_running())
        
        # Stop server
        self.server_manager.stop_server()
        self.assertFalse(self.server_manager.is_running())
        mock_socket.close.assert_called()
    
    def test_stop_server_not_running(self):
        """Test stopping server when not running."""
        # Should not raise exception
        self.server_manager.stop_server()
        self.assertFalse(self.server_manager.is_running())
    
    def test_get_connection_stats(self):
        """Test getting connection statistics."""
        stats = self.server_manager.get_connection_stats()
        
        expected_keys = ["total_connections", "active_connections", 
                        "failed_connections", "max_connections"]
        for key in expected_keys:
            self.assertIn(key, stats)
        
        self.assertEqual(stats["total_connections"], 0)
        self.assertEqual(stats["active_connections"], 0)
        self.assertEqual(stats["failed_connections"], 0)
        self.assertEqual(stats["max_connections"], 100)
    
    def test_get_active_connections(self):
        """Test getting active connections list."""
        connections = self.server_manager.get_active_connections()
        self.assertEqual(connections, [])
    
    def test_close_connection_not_found(self):
        """Test closing non-existent connection."""
        result = self.server_manager.close_connection("nonexistent")
        self.assertFalse(result)


class CustomSSHServer(SSHServer):
    """Custom SSH server for testing overridden methods."""
    
    def __init__(self):
        super().__init__()
        self.auth_calls = []
        self.channel_calls = []
    
    def check_auth_password(self, username: str, password: str) -> int:
        """Custom password authentication."""
        self.auth_calls.append(("password", username, password))
        if username == "testuser" and password == "testpass":
            return AUTH_SUCCESSFUL
        return AUTH_FAILED
    
    def check_auth_publickey(self, username: str, key) -> int:
        """Custom public key authentication."""
        self.auth_calls.append(("publickey", username, key))
        if username == "keyuser":
            return AUTH_SUCCESSFUL
        return AUTH_FAILED
    
    def check_channel_exec_request(self, channel: Channel, command: bytes) -> bool:
        """Custom exec request handling."""
        self.channel_calls.append(("exec", channel, command))
        return command == b"echo hello"
    
    def check_channel_shell_request(self, channel: Channel) -> bool:
        """Custom shell request handling."""
        self.channel_calls.append(("shell", channel))
        return True
    
    def get_banner(self) -> str:
        """Custom banner."""
        return "Welcome to Test SSH Server"


class TestCustomSSHServer(unittest.TestCase):
    """Test custom SSH server implementation."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.server = CustomSSHServer()
        self.mock_channel = Mock(spec=Channel)
        self.mock_key = Mock(spec=Ed25519Key)
    
    def test_custom_password_auth_success(self):
        """Test custom password authentication success."""
        result = self.server.check_auth_password("testuser", "testpass")
        self.assertEqual(result, AUTH_SUCCESSFUL)
        self.assertIn(("password", "testuser", "testpass"), self.server.auth_calls)
    
    def test_custom_password_auth_failure(self):
        """Test custom password authentication failure."""
        result = self.server.check_auth_password("testuser", "wrongpass")
        self.assertEqual(result, AUTH_FAILED)
    
    def test_custom_publickey_auth_success(self):
        """Test custom public key authentication success."""
        result = self.server.check_auth_publickey("keyuser", self.mock_key)
        self.assertEqual(result, AUTH_SUCCESSFUL)
        self.assertIn(("publickey", "keyuser", self.mock_key), self.server.auth_calls)
    
    def test_custom_publickey_auth_failure(self):
        """Test custom public key authentication failure."""
        result = self.server.check_auth_publickey("testuser", self.mock_key)
        self.assertEqual(result, AUTH_FAILED)
    
    def test_custom_exec_request_allowed(self):
        """Test custom exec request handling - allowed command."""
        result = self.server.check_channel_exec_request(self.mock_channel, b"echo hello")
        self.assertTrue(result)
        self.assertIn(("exec", self.mock_channel, b"echo hello"), self.server.channel_calls)
    
    def test_custom_exec_request_denied(self):
        """Test custom exec request handling - denied command."""
        result = self.server.check_channel_exec_request(self.mock_channel, b"rm -rf /")
        self.assertFalse(result)
    
    def test_custom_shell_request(self):
        """Test custom shell request handling."""
        result = self.server.check_channel_shell_request(self.mock_channel)
        self.assertTrue(result)
        self.assertIn(("shell", self.mock_channel), self.server.channel_calls)
    
    def test_custom_banner(self):
        """Test custom banner."""
        banner = self.server.get_banner()
        self.assertEqual(banner, "Welcome to Test SSH Server")


if __name__ == '__main__':
    unittest.main()