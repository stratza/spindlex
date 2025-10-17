"""
Tests for SSH client functionality.
"""

import os
import socket
import tempfile
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest

from spindlex.client.ssh_client import ChannelFile, SSHClient
from spindlex.crypto.pkey import PKey
from spindlex.exceptions import (
    AuthenticationException,
    BadHostKeyException,
    ChannelException,
    SSHException,
    TransportException,
)
from spindlex.hostkeys.policy import AutoAddPolicy, RejectPolicy, WarningPolicy
from spindlex.hostkeys.storage import HostKeyStorage
from spindlex.transport.channel import Channel
from spindlex.transport.transport import Transport


class MockPKey(PKey):
    """Mock PKey for testing."""

    def __init__(self, algorithm="ssh-ed25519"):
        super().__init__()
        self._algorithm = algorithm
        self._key_data = b"mock_key_data"

    @property
    def algorithm_name(self) -> str:
        return self._algorithm

    def get_name(self) -> str:
        """Alias for algorithm_name for compatibility."""
        return self._algorithm

    def get_public_key_bytes(self) -> bytes:
        return self._key_data

    def get_fingerprint(self, hash_algorithm: str = "sha256") -> str:
        return f"SHA256:mock_fingerprint_{self._algorithm}"

    def load_private_key(self, key_data: bytes, password=None) -> None:
        pass

    def load_public_key(self, key_data: bytes) -> None:
        pass

    def sign(self, data: bytes) -> bytes:
        return b"mock_signature"

    def verify(self, signature: bytes, data: bytes) -> bool:
        return True

    def __eq__(self, other):
        """Override equality for testing."""
        if not isinstance(other, MockPKey):
            return False
        return self._algorithm == other._algorithm and self._key_data == other._key_data


class MockTransport:
    """Mock transport for testing SSH client."""

    def __init__(self):
        self.active = False
        self.authenticated = False
        self.closed = False
        self.channels = {}
        self.next_channel_id = 0

    def start_client(self, timeout=None):
        self.active = True

    def auth_password(self, username, password):
        if username == "testuser" and password == "testpass":
            self.authenticated = True
            return True
        return False

    def auth_publickey(self, username, key):
        if username == "testuser" and isinstance(key, MockPKey):
            self.authenticated = True
            return True
        return False

    def open_channel(self, kind, dest_addr=None):
        channel_id = self.next_channel_id
        self.next_channel_id += 1

        channel = Mock(spec=Channel)
        channel._channel_id = channel_id
        channel._remote_channel_id = channel_id
        channel.closed = False
        channel.exec_command = Mock()
        channel.invoke_shell = Mock()
        channel.request_pty = Mock()
        channel.send = Mock(return_value=10)
        channel.recv = Mock(return_value=b"test output")
        channel.recv_stderr = Mock(return_value=b"test error")

        self.channels[channel_id] = channel
        return channel

    def close(self):
        self.active = False
        self.authenticated = False
        self.closed = True


class TestSSHClient:
    """Test SSH client functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = SSHClient()
        self.mock_socket = Mock(spec=socket.socket)
        self.mock_transport = MockTransport()

    def test_init(self):
        """Test SSH client initialization."""
        client = SSHClient()
        assert client._transport is None
        assert client._hostname is None
        assert client._port == 22
        assert isinstance(client._host_key_policy, RejectPolicy)
        assert isinstance(client._host_key_storage, HostKeyStorage)

    def test_set_missing_host_key_policy(self):
        """Test setting host key policy."""
        policy = AutoAddPolicy()
        self.client.set_missing_host_key_policy(policy)
        assert self.client._host_key_policy is policy

    def test_set_host_key_storage(self):
        """Test setting host key storage."""
        storage = HostKeyStorage()
        self.client.set_host_key_storage(storage)
        assert self.client._host_key_storage is storage

    @patch("spindlex.client.ssh_client.socket.socket")
    @patch("spindlex.client.ssh_client.Transport")
    def test_connect_success_password_auth(
        self, mock_transport_class, mock_socket_class
    ):
        """Test successful connection with password authentication."""
        # Setup mocks
        mock_socket_class.return_value = self.mock_socket
        mock_transport_class.return_value = self.mock_transport

        # Use AutoAddPolicy to avoid host key rejection
        self.client.set_missing_host_key_policy(AutoAddPolicy())

        # Connect
        self.client.connect("testhost", 22, "testuser", "testpass")

        # Verify connection
        assert self.client._hostname == "testhost"
        assert self.client._port == 22
        assert self.client._transport is self.mock_transport
        assert self.mock_transport.active
        assert self.mock_transport.authenticated

    @patch("spindlex.client.ssh_client.socket.socket")
    @patch("spindlex.client.ssh_client.Transport")
    def test_connect_success_publickey_auth(
        self, mock_transport_class, mock_socket_class
    ):
        """Test successful connection with public key authentication."""
        # Setup mocks
        mock_socket_class.return_value = self.mock_socket
        mock_transport_class.return_value = self.mock_transport

        # Use AutoAddPolicy to avoid host key rejection
        self.client.set_missing_host_key_policy(AutoAddPolicy())

        key = MockPKey()

        # Connect
        self.client.connect("testhost", 22, "testuser", pkey=key)

        # Verify connection
        assert self.client._hostname == "testhost"
        assert self.client._port == 22
        assert self.client._transport is self.mock_transport
        assert self.mock_transport.active
        assert self.mock_transport.authenticated

    @patch("spindlex.client.ssh_client.socket.socket")
    def test_connect_socket_error(self, mock_socket_class):
        """Test connection failure due to socket error."""
        mock_socket = Mock()
        mock_socket.connect.side_effect = socket.error("Connection refused")
        mock_socket_class.return_value = mock_socket

        with pytest.raises(SSHException, match="Connection failed"):
            self.client.connect("testhost", 22, "testuser", "testpass")

    @patch("spindlex.client.ssh_client.socket.socket")
    @patch("spindlex.client.ssh_client.Transport")
    def test_connect_auth_failure(self, mock_transport_class, mock_socket_class):
        """Test connection failure due to authentication error."""
        # Setup mocks
        mock_socket_class.return_value = self.mock_socket
        mock_transport = MockTransport()
        mock_transport_class.return_value = mock_transport

        # Use AutoAddPolicy to avoid host key rejection
        self.client.set_missing_host_key_policy(AutoAddPolicy())

        with pytest.raises(AuthenticationException, match="Authentication failed"):
            self.client.connect("testhost", 22, "wronguser", "wrongpass")

    def test_connect_already_connected(self):
        """Test connecting when already connected."""
        self.client._transport = self.mock_transport
        self.mock_transport.active = True

        with pytest.raises(SSHException, match="Already connected"):
            self.client.connect("testhost", 22, "testuser", "testpass")

    def test_exec_command_success(self):
        """Test successful command execution."""
        # Setup connected client
        self.client._transport = self.mock_transport
        self.mock_transport.active = True
        self.mock_transport.authenticated = True

        # Execute command
        stdin, stdout, stderr = self.client.exec_command("ls -la")

        # Verify channel was opened and command executed
        assert len(self.mock_transport.channels) == 1
        channel = list(self.mock_transport.channels.values())[0]
        channel.exec_command.assert_called_once_with("ls -la")

        # Verify file objects
        assert isinstance(stdin, ChannelFile)
        assert isinstance(stdout, ChannelFile)
        assert isinstance(stderr, ChannelFile)

    def test_exec_command_not_connected(self):
        """Test command execution when not connected."""
        with pytest.raises(SSHException, match="Not connected"):
            self.client.exec_command("ls -la")

    def test_exec_command_empty_command(self):
        """Test command execution with empty command."""
        self.client._transport = self.mock_transport
        self.mock_transport.active = True
        self.mock_transport.authenticated = True

        with pytest.raises(SSHException, match="Command cannot be empty"):
            self.client.exec_command("")

    def test_invoke_shell_success(self):
        """Test successful shell invocation."""
        # Setup connected client
        self.client._transport = self.mock_transport
        self.mock_transport.active = True
        self.mock_transport.authenticated = True

        # Invoke shell
        channel = self.client.invoke_shell()

        # Verify channel was opened and shell invoked
        assert len(self.mock_transport.channels) == 1
        assert channel in self.mock_transport.channels.values()
        channel.request_pty.assert_called_once()
        channel.invoke_shell.assert_called_once()

    def test_invoke_shell_not_connected(self):
        """Test shell invocation when not connected."""
        with pytest.raises(SSHException, match="Not connected"):
            self.client.invoke_shell()

    def test_is_connected(self):
        """Test connection status checking."""
        # Not connected
        assert not self.client.is_connected()

        # Connected but not authenticated
        self.client._transport = self.mock_transport
        self.mock_transport.active = True
        self.mock_transport.authenticated = False
        assert not self.client.is_connected()

        # Connected and authenticated
        self.mock_transport.authenticated = True
        assert self.client.is_connected()

    def test_close(self):
        """Test connection closing."""
        self.client._transport = self.mock_transport
        self.client._hostname = "testhost"
        self.client._port = 2222

        self.client.close()

        assert self.client._transport is None
        assert self.client._hostname is None
        assert self.client._port == 22

    def test_context_manager(self):
        """Test SSH client as context manager."""
        with patch.object(self.client, "close") as mock_close:
            with self.client as client:
                assert client is self.client
            mock_close.assert_called_once()


class TestChannelFile:
    """Test ChannelFile functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_channel = Mock(spec=Channel)
        self.mock_channel.recv.return_value = b"test data"
        self.mock_channel.recv_stderr.return_value = b"error data"
        self.mock_channel.send.return_value = 10

    def test_read_stdout(self):
        """Test reading from stdout."""
        channel_file = ChannelFile(self.mock_channel, "r")
        data = channel_file.read(100)

        assert data == b"test data"
        self.mock_channel.recv.assert_called_once_with(100)

    def test_read_stderr(self):
        """Test reading from stderr."""
        channel_file = ChannelFile(self.mock_channel, "stderr")
        data = channel_file.read(100)

        assert data == b"error data"
        self.mock_channel.recv_stderr.assert_called_once_with(100)

    def test_write(self):
        """Test writing to stdin."""
        channel_file = ChannelFile(self.mock_channel, "w")
        bytes_written = channel_file.write(b"test input")

        assert bytes_written == 10
        self.mock_channel.send.assert_called_once_with(b"test input")

    def test_write_string(self):
        """Test writing string to stdin."""
        channel_file = ChannelFile(self.mock_channel, "w")
        bytes_written = channel_file.write("test input")

        assert bytes_written == 10
        self.mock_channel.send.assert_called_once_with(b"test input")

    def test_read_wrong_mode(self):
        """Test reading from write-only file."""
        channel_file = ChannelFile(self.mock_channel, "w")

        with pytest.raises(ValueError, match="File not opened for reading"):
            channel_file.read(100)

    def test_write_wrong_mode(self):
        """Test writing to read-only file."""
        channel_file = ChannelFile(self.mock_channel, "r")

        with pytest.raises(ValueError, match="File not opened for writing"):
            channel_file.write(b"test")

    def test_closed_file_operations(self):
        """Test operations on closed file."""
        channel_file = ChannelFile(self.mock_channel, "r")
        channel_file.close()

        with pytest.raises(ValueError, match="I/O operation on closed file"):
            channel_file.read(100)

        with pytest.raises(ValueError, match="I/O operation on closed file"):
            channel_file.write(b"test")

    def test_context_manager(self):
        """Test ChannelFile as context manager."""
        with ChannelFile(self.mock_channel, "r") as channel_file:
            assert not channel_file._closed
        assert channel_file._closed


class TestHostKeyPolicies:
    """Test host key policy functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = SSHClient()
        self.hostname = "testhost"
        self.key = MockPKey()

    def test_reject_policy(self):
        """Test RejectPolicy behavior."""
        policy = RejectPolicy()

        with pytest.raises(BadHostKeyException):
            policy.missing_host_key(self.client, self.hostname, self.key)

    def test_auto_add_policy(self):
        """Test AutoAddPolicy behavior."""
        policy = AutoAddPolicy()

        # Mock storage
        mock_storage = Mock()
        self.client._host_key_storage = mock_storage

        # Should not raise exception
        policy.missing_host_key(self.client, self.hostname, self.key)

        # Verify key was added
        mock_storage.add.assert_called_once_with(self.hostname, self.key)
        mock_storage.save.assert_called_once()

    def test_warning_policy(self):
        """Test WarningPolicy behavior."""
        policy = WarningPolicy()

        # Should not raise exception, just log warning
        with patch.object(policy._logger, "warning") as mock_warning:
            policy.missing_host_key(self.client, self.hostname, self.key)
            # Verify warning was logged
            mock_warning.assert_called_once()


class TestHostKeyStorage:
    """Test host key storage functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.temp_file = tempfile.NamedTemporaryFile(mode="w", delete=False)
        self.temp_file.close()
        self.storage = HostKeyStorage(self.temp_file.name)
        self.key = MockPKey()

    def teardown_method(self):
        """Clean up test fixtures."""
        try:
            os.unlink(self.temp_file.name)
        except:
            pass

    def test_add_and_get_key(self):
        """Test adding and retrieving host keys."""
        hostname = "testhost"

        # Add key
        self.storage.add(hostname, self.key)

        # Retrieve key
        retrieved_key = self.storage.get(hostname)
        assert retrieved_key is self.key

    def test_get_nonexistent_key(self):
        """Test retrieving non-existent host key."""
        result = self.storage.get("nonexistent")
        assert result is None

    def test_save_and_load(self):
        """Test saving and loading host keys."""
        hostname = "testhost"

        # Add key and save
        self.storage.add(hostname, self.key)
        self.storage.save()

        # Create new storage instance and load
        new_storage = HostKeyStorage(self.temp_file.name)

        # The load happens automatically in __init__
        # For this test, we'll just verify the file was created
        assert os.path.exists(self.temp_file.name)

        # Read file content to verify format
        with open(self.temp_file.name, "r") as f:
            content = f.read()
            assert hostname in content
            assert self.key.algorithm_name in content

    def test_remove_key(self):
        """Test removing host keys."""
        hostname = "testhost"

        # Add key
        self.storage.add(hostname, self.key)
        assert self.storage.get(hostname) is not None

        # Remove key
        result = self.storage.remove(hostname, self.key)
        assert result is True
        assert self.storage.get(hostname) is None

        # Try to remove non-existent key
        result = self.storage.remove(hostname, self.key)
        assert result is False

    def test_get_all_keys(self):
        """Test getting all keys for hostname."""
        hostname = "testhost"
        # Create a different key with different data to ensure they're not equal
        key2 = MockPKey("ssh-rsa")
        key2._key_data = b"different_key_data"

        # Add multiple keys
        self.storage.add(hostname, self.key)
        self.storage.add(hostname, key2)

        # Get all keys
        all_keys = self.storage.get_all(hostname)
        assert len(all_keys) == 2
        assert self.key in all_keys
        assert key2 in all_keys
