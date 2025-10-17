"""
Tests for Async SSH Client

Tests asynchronous SSH client functionality including connection management,
command execution, and SFTP operations.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest

from ssh_library.client.async_ssh_client import AsyncSSHClient
from ssh_library.exceptions import AuthenticationException, SSHException


class TestAsyncSSHClient:
    """Test async SSH client functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = AsyncSSHClient()

    def test_initialization(self):
        """Test async SSH client initialization."""
        assert self.client._transport is None
        assert self.client._hostname is None
        assert self.client._port == 22
        assert self.client._username is None
        assert not self.client._connected
        assert self.client._host_key_policy is not None

    @pytest.mark.asyncio
    async def test_connect_already_connected(self):
        """Test connecting when already connected."""
        self.client._connected = True

        with pytest.raises(SSHException, match="Already connected"):
            await self.client.connect("test.example.com")

    @pytest.mark.asyncio
    @patch("asyncio.open_connection")
    @patch("ssh_library.client.async_ssh_client.AsyncTransport")
    async def test_successful_connection(
        self, mock_transport_class, mock_open_connection
    ):
        """Test successful SSH connection."""
        # Setup mocks
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.get_extra_info.return_value = Mock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        mock_open_connection.return_value = (mock_reader, mock_writer)

        mock_transport = AsyncMock()
        mock_transport.start_client = AsyncMock()
        mock_transport.auth_password = AsyncMock(return_value=True)
        mock_transport_class.return_value = mock_transport

        # Test connection
        await self.client.connect(
            hostname="test.example.com",
            port=2222,
            username="testuser",
            password="testpass",
        )

        # Verify calls
        mock_open_connection.assert_called_once()
        mock_transport.start_client.assert_called_once()
        mock_transport.auth_password.assert_called_once_with("testuser", "testpass")

        # Verify state
        assert self.client._connected
        assert self.client._hostname == "test.example.com"
        assert self.client._port == 2222
        assert self.client._username == "testuser"

    @pytest.mark.asyncio
    @patch("asyncio.open_connection")
    @patch("ssh_library.client.async_ssh_client.AsyncTransport")
    async def test_connection_with_public_key(
        self, mock_transport_class, mock_open_connection
    ):
        """Test SSH connection with public key authentication."""
        # Setup mocks
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.get_extra_info.return_value = Mock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        mock_open_connection.return_value = (mock_reader, mock_writer)

        mock_transport = AsyncMock()
        mock_transport.start_client = AsyncMock()
        mock_transport.auth_publickey = AsyncMock(return_value=True)
        mock_transport_class.return_value = mock_transport

        mock_key = Mock()

        # Test connection
        await self.client.connect(
            hostname="test.example.com", username="testuser", pkey=mock_key
        )

        # Verify public key auth was called
        mock_transport.auth_publickey.assert_called_once_with("testuser", mock_key)
        assert self.client._connected

    @pytest.mark.asyncio
    @patch("asyncio.open_connection")
    @patch("ssh_library.client.async_ssh_client.AsyncTransport")
    async def test_connection_with_gssapi(
        self, mock_transport_class, mock_open_connection
    ):
        """Test SSH connection with GSSAPI authentication."""
        # Setup mocks
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_writer.get_extra_info.return_value = Mock()
        mock_writer.close = Mock()
        mock_writer.wait_closed = AsyncMock()

        mock_open_connection.return_value = (mock_reader, mock_writer)

        mock_transport = AsyncMock()
        mock_transport.start_client = AsyncMock()
        mock_transport.auth_gssapi = AsyncMock(return_value=True)
        mock_transport_class.return_value = mock_transport

        # Test connection
        await self.client.connect(
            hostname="test.example.com",
            username="testuser",
            gss_auth=True,
            gss_host="custom.example.com",
            gss_deleg_creds=True,
        )

        # Verify GSSAPI auth was called
        mock_transport.auth_gssapi.assert_called_once_with(
            "testuser", "custom.example.com", True
        )
        assert self.client._connected

    @pytest.mark.asyncio
    async def test_exec_command_not_connected(self):
        """Test executing command when not connected."""
        with pytest.raises(SSHException, match="Not connected"):
            await self.client.exec_command("ls")

    @pytest.mark.asyncio
    async def test_exec_command_success(self):
        """Test successful command execution."""
        # Setup connected client
        self.client._connected = True
        mock_transport = AsyncMock()
        mock_channel = AsyncMock()
        mock_channel.makefile = Mock(side_effect=lambda mode, bufsize: Mock())
        mock_transport.open_channel = AsyncMock(return_value=mock_channel)
        self.client._transport = mock_transport

        # Test command execution
        stdin, stdout, stderr = await self.client.exec_command("ls -la")

        # Verify calls
        mock_transport.open_channel.assert_called_once_with("session")
        mock_channel.exec_command.assert_called_once_with("ls -la")

        # Verify return values
        assert stdin is not None
        assert stdout is not None
        assert stderr is not None

    @pytest.mark.asyncio
    async def test_invoke_shell_success(self):
        """Test successful shell invocation."""
        # Setup connected client
        self.client._connected = True
        mock_transport = AsyncMock()
        mock_channel = AsyncMock()
        mock_transport.open_channel = AsyncMock(return_value=mock_channel)
        self.client._transport = mock_transport

        # Test shell invocation
        channel = await self.client.invoke_shell()

        # Verify calls
        mock_transport.open_channel.assert_called_once_with("session")
        mock_channel.invoke_shell.assert_called_once()

        assert channel == mock_channel

    @pytest.mark.asyncio
    @patch("ssh_library.client.async_ssh_client.AsyncSFTPClient")
    async def test_open_sftp_success(self, mock_sftp_class):
        """Test successful SFTP client opening."""
        # Setup connected client
        self.client._connected = True
        mock_transport = AsyncMock()
        mock_channel = AsyncMock()
        mock_transport.open_channel = AsyncMock(return_value=mock_channel)
        self.client._transport = mock_transport

        mock_sftp = AsyncMock()
        mock_sftp._initialize = AsyncMock()
        mock_sftp_class.return_value = mock_sftp

        # Test SFTP opening
        sftp_client = await self.client.open_sftp()

        # Verify calls
        mock_transport.open_channel.assert_called_once_with("session")
        mock_channel.invoke_subsystem.assert_called_once_with("sftp")
        mock_sftp_class.assert_called_once_with(mock_channel)
        mock_sftp._initialize.assert_called_once()

        assert sftp_client == mock_sftp

    @pytest.mark.asyncio
    async def test_close(self):
        """Test client close."""
        # Setup connected client
        self.client._connected = True
        mock_transport = AsyncMock()
        mock_transport.close = AsyncMock()
        self.client._transport = mock_transport
        self.client._hostname = "test.example.com"
        self.client._username = "testuser"

        # Test close
        await self.client.close()

        # Verify calls
        mock_transport.close.assert_called_once()

        # Verify state reset
        assert not self.client._connected
        assert self.client._transport is None
        assert self.client._hostname is None
        assert self.client._port == 22
        assert self.client._username is None

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager functionality."""
        mock_transport = AsyncMock()

        with patch.object(self.client, "close", new_callable=AsyncMock) as mock_close:
            async with self.client as client:
                assert client == self.client

            mock_close.assert_called_once()

    def test_properties(self):
        """Test client properties."""
        # Test initial state
        assert not self.client.connected
        assert self.client.hostname is None
        assert self.client.port == 22
        assert self.client.username is None

        # Test connected state
        self.client._connected = True
        self.client._transport = Mock()
        self.client._hostname = "test.example.com"
        self.client._port = 2222
        self.client._username = "testuser"

        assert self.client.connected
        assert self.client.hostname == "test.example.com"
        assert self.client.port == 2222
        assert self.client.username == "testuser"

    def test_set_missing_host_key_policy(self):
        """Test setting host key policy."""
        from ssh_library.hostkeys.policy import RejectPolicy

        policy = RejectPolicy()
        self.client.set_missing_host_key_policy(policy)

        assert self.client._host_key_policy == policy


class TestAsyncSFTPClient:
    """Test async SFTP client functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_channel = AsyncMock()

    @pytest.mark.asyncio
    async def test_sftp_initialization(self):
        """Test SFTP client initialization."""
        from ssh_library.client.async_sftp_client import AsyncSFTPClient

        sftp_client = AsyncSFTPClient(self.mock_channel)

        assert sftp_client._channel == self.mock_channel
        assert sftp_client._request_id == 0
        assert not sftp_client._initialized

    @pytest.mark.asyncio
    async def test_sftp_file_operations(self):
        """Test basic SFTP file operations."""
        from ssh_library.client.async_sftp_client import AsyncSFTPClient

        sftp_client = AsyncSFTPClient(self.mock_channel)
        sftp_client._initialized = True

        # Mock file operations
        with patch("builtins.open", create=True) as mock_open:
            mock_file = Mock()
            mock_file.read.return_value = b"test data"
            mock_file.write = Mock()
            mock_open.return_value.__enter__.return_value = mock_file

            # Mock SFTP file
            mock_sftp_file = AsyncMock()
            mock_sftp_file.read = AsyncMock(return_value=b"test data")
            mock_sftp_file.write = AsyncMock()
            mock_sftp_file.close = AsyncMock()

            with patch.object(sftp_client, "open", return_value=mock_sftp_file):
                # Test file download
                await sftp_client.get("/remote/file.txt", "/local/file.txt")

                # Test file upload
                await sftp_client.put("/local/file.txt", "/remote/file.txt")

        # Verify operations were called
        assert mock_sftp_file.read.called
        assert mock_sftp_file.write.called
        assert mock_sftp_file.close.called


class TestAsyncTransport:
    """Test async transport functionality."""

    @pytest.mark.asyncio
    async def test_async_transport_methods(self):
        """Test that async transport has required methods."""
        from ssh_library.transport.async_transport import AsyncTransport

        # Check async methods exist
        assert hasattr(AsyncTransport, "start_client")
        assert hasattr(AsyncTransport, "start_server")
        assert hasattr(AsyncTransport, "auth_password")
        assert hasattr(AsyncTransport, "auth_publickey")
        assert hasattr(AsyncTransport, "auth_gssapi")
        assert hasattr(AsyncTransport, "open_channel")
        assert hasattr(AsyncTransport, "close")

        # Check methods are coroutines
        import inspect

        assert inspect.iscoroutinefunction(AsyncTransport.start_client)
        assert inspect.iscoroutinefunction(AsyncTransport.auth_password)
        assert inspect.iscoroutinefunction(AsyncTransport.open_channel)


class TestAsyncChannel:
    """Test async channel functionality."""

    @pytest.mark.asyncio
    async def test_async_channel_methods(self):
        """Test that async channel has required methods."""
        from ssh_library.transport.async_channel import AsyncChannel

        # Check async methods exist
        assert hasattr(AsyncChannel, "send")
        assert hasattr(AsyncChannel, "recv")
        assert hasattr(AsyncChannel, "exec_command")
        assert hasattr(AsyncChannel, "invoke_shell")
        assert hasattr(AsyncChannel, "close")

        # Check methods are coroutines
        import inspect

        assert inspect.iscoroutinefunction(AsyncChannel.send)
        assert inspect.iscoroutinefunction(AsyncChannel.recv)
        assert inspect.iscoroutinefunction(AsyncChannel.exec_command)
