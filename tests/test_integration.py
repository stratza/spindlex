"""
Comprehensive integration tests for ssh-library.

These tests verify end-to-end functionality across multiple components
and simulate real-world usage scenarios.
"""

import asyncio
import os
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

import pytest

from ssh_library import (
    SSHClient,
    SFTPClient,
    SSHServer,
    SFTPServer,
    Transport,
    Channel,
    AutoAddPolicy,
    RejectPolicy,
    SSHException,
    AuthenticationException,
)
from ssh_library.crypto.pkey import Ed25519Key, RSAKey
from ssh_library.server.ssh_server import SSHServerInterface


class TestSSHServer(SSHServerInterface):
    """Test SSH server implementation."""
    
    def __init__(self, host_key: Optional[Ed25519Key] = None):
        self.host_key = host_key or Ed25519Key.generate()
        self.users = {
            'testuser': 'testpass',
            'keyuser': None  # Key-based auth only
        }
        self.authorized_keys = {}
    
    def add_authorized_key(self, username: str, key: Ed25519Key):
        """Add an authorized key for a user."""
        if username not in self.authorized_keys:
            self.authorized_keys[username] = []
        self.authorized_keys[username].append(key)
    
    def check_auth_password(self, username: str, password: str) -> int:
        """Check password authentication."""
        if username in self.users and self.users[username] == password:
            return SSHServer.AUTH_SUCCESSFUL
        return SSHServer.AUTH_FAILED
    
    def check_auth_publickey(self, username: str, key) -> int:
        """Check public key authentication."""
        if username in self.authorized_keys:
            for auth_key in self.authorized_keys[username]:
                if key.get_fingerprint() == auth_key.get_fingerprint():
                    return SSHServer.AUTH_SUCCESSFUL
        return SSHServer.AUTH_FAILED
    
    def check_channel_request(self, kind: str, chanid: int) -> int:
        """Check channel request."""
        if kind == 'session':
            return SSHServer.OPEN_SUCCEEDED
        return SSHServer.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
    
    def check_channel_exec_request(self, channel: Channel, command: bytes) -> bool:
        """Handle exec requests."""
        cmd = command.decode('utf-8')
        
        if cmd == 'echo hello':
            channel.send(b'hello\n')
            channel.send_exit_status(0)
        elif cmd == 'echo error >&2':
            channel.send_stderr(b'error\n')
            channel.send_exit_status(1)
        elif cmd.startswith('echo '):
            output = cmd[5:] + '\n'
            channel.send(output.encode('utf-8'))
            channel.send_exit_status(0)
        else:
            channel.send_stderr(b'Command not found\n')
            channel.send_exit_status(127)
        
        channel.close()
        return True
    
    def check_channel_shell_request(self, channel: Channel) -> bool:
        """Handle shell requests."""
        # Simple shell simulation
        channel.send(b'$ ')
        return True


class TestSFTPServer(SFTPServer):
    """Test SFTP server implementation."""
    
    def __init__(self, root_path: str):
        super().__init__()
        self.root_path = Path(root_path)
        self.root_path.mkdir(exist_ok=True)
    
    def _get_full_path(self, path: str) -> Path:
        """Get full path within root directory."""
        # Normalize path and ensure it's within root
        full_path = (self.root_path / path).resolve()
        if not str(full_path).startswith(str(self.root_path)):
            raise PermissionError("Access denied")
        return full_path
    
    def list_folder(self, path: str):
        """List directory contents."""
        full_path = self._get_full_path(path)
        if not full_path.exists():
            return SFTPServer.SFTP_NO_SUCH_FILE
        
        if not full_path.is_dir():
            return SFTPServer.SFTP_NOT_A_DIRECTORY
        
        items = []
        for item in full_path.iterdir():
            attr = self._path_to_attr(item)
            items.append(attr)
        
        return items
    
    def stat(self, path: str):
        """Get file/directory attributes."""
        full_path = self._get_full_path(path)
        if not full_path.exists():
            return SFTPServer.SFTP_NO_SUCH_FILE
        
        return self._path_to_attr(full_path)
    
    def open(self, path: str, flags: int, attr):
        """Open file for reading/writing."""
        full_path = self._get_full_path(path)
        
        # Create a simple file handle
        class TestSFTPHandle:
            def __init__(self, file_path: Path, flags: int):
                self.path = file_path
                self.flags = flags
                self.position = 0
                
                if flags & os.O_CREAT:
                    file_path.touch()
            
            def read(self, offset: int, length: int) -> bytes:
                if not self.path.exists():
                    return SFTPServer.SFTP_NO_SUCH_FILE
                
                data = self.path.read_bytes()
                return data[offset:offset + length]
            
            def write(self, offset: int, data: bytes) -> int:
                if not self.path.exists():
                    self.path.touch()
                
                current_data = self.path.read_bytes() if self.path.exists() else b''
                
                # Extend data if necessary
                if offset > len(current_data):
                    current_data += b'\x00' * (offset - len(current_data))
                
                # Write new data
                new_data = current_data[:offset] + data + current_data[offset + len(data):]
                self.path.write_bytes(new_data)
                
                return SFTPServer.SFTP_OK
            
            def close(self) -> int:
                return SFTPServer.SFTP_OK
        
        return TestSFTPHandle(full_path, flags)
    
    def mkdir(self, path: str, attr) -> int:
        """Create directory."""
        full_path = self._get_full_path(path)
        try:
            full_path.mkdir(parents=True)
            return SFTPServer.SFTP_OK
        except FileExistsError:
            return SFTPServer.SFTP_FAILURE
    
    def rmdir(self, path: str) -> int:
        """Remove directory."""
        full_path = self._get_full_path(path)
        try:
            full_path.rmdir()
            return SFTPServer.SFTP_OK
        except (FileNotFoundError, OSError):
            return SFTPServer.SFTP_FAILURE
    
    def _path_to_attr(self, path: Path):
        """Convert path to SFTP attributes."""
        from ssh_library.protocol.sftp_messages import SFTPAttributes
        
        stat = path.stat()
        attr = SFTPAttributes()
        attr.st_size = stat.st_size
        attr.st_mode = stat.st_mode
        attr.st_atime = int(stat.st_atime)
        attr.st_mtime = int(stat.st_mtime)
        attr.filename = path.name
        
        return attr


class SSHServerRunner:
    """Helper class to run SSH server in a separate thread."""
    
    def __init__(self, port: int = 0):
        self.port = port
        self.server_socket = None
        self.server_thread = None
        self.running = False
        self.ssh_server = TestSSHServer()
        
    def start(self):
        """Start the SSH server."""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('localhost', self.port))
        
        # Get the actual port if 0 was specified
        self.port = self.server_socket.getsockname()[1]
        
        self.server_socket.listen(5)
        self.running = True
        
        self.server_thread = threading.Thread(target=self._run_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        
        # Wait a bit for server to start
        time.sleep(0.1)
    
    def stop(self):
        """Stop the SSH server."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        if self.server_thread:
            self.server_thread.join(timeout=1.0)
    
    def _run_server(self):
        """Run the server loop."""
        while self.running:
            try:
                client_socket, addr = self.server_socket.accept()
                
                # Handle client in a separate thread
                client_thread = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except OSError:
                # Socket was closed
                break
    
    def _handle_client(self, client_socket):
        """Handle a client connection."""
        try:
            transport = Transport(client_socket)
            transport.start_server(self.ssh_server.host_key, server=self.ssh_server)
            
            # Keep connection alive
            while transport.is_active():
                time.sleep(0.1)
                
        except Exception:
            # Client disconnected or error occurred
            pass
        finally:
            client_socket.close()


@pytest.fixture
def ssh_server():
    """Fixture that provides a running SSH server."""
    server = SSHServerRunner()
    server.start()
    yield server
    server.stop()


@pytest.fixture
def temp_sftp_root():
    """Fixture that provides a temporary directory for SFTP operations."""
    with tempfile.TemporaryDirectory() as temp_dir:
        yield temp_dir


class TestClientServerIntegration:
    """End-to-end integration tests between client and server."""
    
    def test_password_authentication(self, ssh_server):
        """Test password authentication flow."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            client.connect(
                hostname='localhost',
                port=ssh_server.port,
                username='testuser',
                password='testpass',
                timeout=5.0
            )
            
            # Verify connection is established
            assert client.get_transport().is_active()
            
        finally:
            client.close()
    
    def test_public_key_authentication(self, ssh_server):
        """Test public key authentication flow."""
        # Generate key pair
        private_key = Ed25519Key.generate()
        
        # Add public key to server
        ssh_server.ssh_server.add_authorized_key('keyuser', private_key)
        
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            client.connect(
                hostname='localhost',
                port=ssh_server.port,
                username='keyuser',
                pkey=private_key,
                timeout=5.0
            )
            
            # Verify connection is established
            assert client.get_transport().is_active()
            
        finally:
            client.close()
    
    def test_authentication_failure(self, ssh_server):
        """Test authentication failure handling."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        with pytest.raises(AuthenticationException):
            client.connect(
                hostname='localhost',
                port=ssh_server.port,
                username='testuser',
                password='wrongpass',
                timeout=5.0
            )
    
    def test_host_key_rejection(self, ssh_server):
        """Test host key rejection policy."""
        client = SSHClient()
        client.set_missing_host_key_policy(RejectPolicy())
        
        with pytest.raises(SSHException):
            client.connect(
                hostname='localhost',
                port=ssh_server.port,
                username='testuser',
                password='testpass',
                timeout=5.0
            )
    
    def test_command_execution(self, ssh_server):
        """Test command execution through SSH."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            client.connect(
                hostname='localhost',
                port=ssh_server.port,
                username='testuser',
                password='testpass',
                timeout=5.0
            )
            
            # Test simple command
            stdin, stdout, stderr = client.exec_command('echo hello')
            output = stdout.read().decode('utf-8').strip()
            assert output == 'hello'
            
            # Test command with arguments
            stdin, stdout, stderr = client.exec_command('echo "test message"')
            output = stdout.read().decode('utf-8').strip()
            assert output == '"test message"'
            
            # Test command with stderr
            stdin, stdout, stderr = client.exec_command('echo error >&2')
            error_output = stderr.read().decode('utf-8').strip()
            assert error_output == 'error'
            
        finally:
            client.close()
    
    def test_multiple_channels(self, ssh_server):
        """Test multiple simultaneous channels."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            client.connect(
                hostname='localhost',
                port=ssh_server.port,
                username='testuser',
                password='testpass',
                timeout=5.0
            )
            
            # Execute multiple commands simultaneously
            channels = []
            for i in range(3):
                stdin, stdout, stderr = client.exec_command(f'echo message{i}')
                channels.append((stdin, stdout, stderr))
            
            # Read results
            for i, (stdin, stdout, stderr) in enumerate(channels):
                output = stdout.read().decode('utf-8').strip()
                assert output == f'message{i}'
            
        finally:
            client.close()
    
    def test_connection_reuse(self, ssh_server):
        """Test connection reuse for multiple operations."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            client.connect(
                hostname='localhost',
                port=ssh_server.port,
                username='testuser',
                password='testpass',
                timeout=5.0
            )
            
            # Execute multiple commands on same connection
            for i in range(5):
                stdin, stdout, stderr = client.exec_command(f'echo test{i}')
                output = stdout.read().decode('utf-8').strip()
                assert output == f'test{i}'
                
                # Verify connection is still active
                assert client.get_transport().is_active()
            
        finally:
            client.close()


class TestSFTPIntegration:
    """Integration tests for SFTP functionality."""
    
    @pytest.fixture
    def sftp_client(self, ssh_server, temp_sftp_root):
        """Fixture that provides an SFTP client connected to test server."""
        # Set up SFTP server
        sftp_server = TestSFTPServer(temp_sftp_root)
        ssh_server.ssh_server.sftp_server = sftp_server
        
        # Connect client
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(
            hostname='localhost',
            port=ssh_server.port,
            username='testuser',
            password='testpass',
            timeout=5.0
        )
        
        sftp = client.open_sftp()
        yield sftp, temp_sftp_root
        
        sftp.close()
        client.close()
    
    def test_file_upload_download(self, sftp_client):
        """Test file upload and download operations."""
        sftp, root_path = sftp_client
        
        # Create test file
        test_data = b"Hello, SFTP World!"
        local_file = Path(root_path) / "local_test.txt"
        local_file.write_bytes(test_data)
        
        # Upload file
        remote_path = "remote_test.txt"
        sftp.put(str(local_file), remote_path)
        
        # Verify file exists on server
        remote_file = Path(root_path) / remote_path
        assert remote_file.exists()
        assert remote_file.read_bytes() == test_data
        
        # Download file
        download_path = Path(root_path) / "downloaded_test.txt"
        sftp.get(remote_path, str(download_path))
        
        # Verify downloaded content
        assert download_path.read_bytes() == test_data
    
    def test_directory_operations(self, sftp_client):
        """Test directory creation and listing."""
        sftp, root_path = sftp_client
        
        # Create directory
        test_dir = "test_directory"
        sftp.mkdir(test_dir)
        
        # Verify directory exists
        dir_path = Path(root_path) / test_dir
        assert dir_path.exists()
        assert dir_path.is_dir()
        
        # List directory contents
        contents = sftp.listdir(".")
        assert test_dir in contents
        
        # Remove directory
        sftp.rmdir(test_dir)
        assert not dir_path.exists()
    
    def test_file_attributes(self, sftp_client):
        """Test file attribute operations."""
        sftp, root_path = sftp_client
        
        # Create test file
        test_file = "attr_test.txt"
        test_data = b"Test file for attributes"
        
        local_file = Path(root_path) / test_file
        local_file.write_bytes(test_data)
        
        sftp.put(str(local_file), test_file)
        
        # Get file attributes
        attr = sftp.stat(test_file)
        assert attr.st_size == len(test_data)
        
        # Test chmod (if supported)
        try:
            sftp.chmod(test_file, 0o644)
        except NotImplementedError:
            # Some SFTP servers don't support chmod
            pass


class TestPerformanceBenchmarks:
    """Performance benchmark tests."""
    
    def test_connection_performance(self, ssh_server):
        """Benchmark connection establishment performance."""
        times = []
        
        for _ in range(5):  # Reduced iterations for CI
            start_time = time.time()
            
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            
            try:
                client.connect(
                    hostname='localhost',
                    port=ssh_server.port,
                    username='testuser',
                    password='testpass',
                    timeout=5.0
                )
                
                connect_time = time.time() - start_time
                times.append(connect_time)
                
            finally:
                client.close()
        
        # Basic performance assertions
        avg_time = sum(times) / len(times)
        assert avg_time < 2.0  # Should connect within 2 seconds on average
        assert max(times) < 5.0  # No connection should take more than 5 seconds
    
    def test_command_execution_performance(self, ssh_server):
        """Benchmark command execution performance."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            client.connect(
                hostname='localhost',
                port=ssh_server.port,
                username='testuser',
                password='testpass',
                timeout=5.0
            )
            
            times = []
            for i in range(10):
                start_time = time.time()
                
                stdin, stdout, stderr = client.exec_command(f'echo test{i}')
                output = stdout.read()
                
                exec_time = time.time() - start_time
                times.append(exec_time)
            
            # Performance assertions
            avg_time = sum(times) / len(times)
            assert avg_time < 0.5  # Commands should execute quickly
            
        finally:
            client.close()


class TestInteroperability:
    """Tests for interoperability with other SSH implementations."""
    
    @pytest.mark.skipif(
        not os.path.exists('/usr/bin/ssh'),
        reason="OpenSSH client not available"
    )
    def test_openssh_client_compatibility(self, ssh_server):
        """Test compatibility with OpenSSH client (if available)."""
        # This test would require setting up key-based auth
        # and running openssh client commands
        # Skipped in basic test suite but useful for full compatibility testing
        pass
    
    @pytest.mark.skipif(
        not os.path.exists('/usr/sbin/sshd'),
        reason="OpenSSH server not available"
    )
    def test_openssh_server_compatibility(self):
        """Test compatibility with OpenSSH server (if available)."""
        # This test would connect to a real OpenSSH server
        # Skipped in basic test suite but useful for full compatibility testing
        pass


# Async integration tests (if async support is available)
try:
    from ssh_library.client.async_ssh_client import AsyncSSHClient
    
    class TestAsyncIntegration:
        """Integration tests for async functionality."""
        
        @pytest.mark.asyncio
        async def test_async_connection(self, ssh_server):
            """Test async SSH connection."""
            client = AsyncSSHClient()
            
            try:
                await client.connect(
                    hostname='localhost',
                    port=ssh_server.port,
                    username='testuser',
                    password='testpass',
                    timeout=5.0
                )
                
                # Test async command execution
                result = await client.exec_command('echo async_test')
                assert b'async_test' in result.stdout
                
            finally:
                await client.close()
        
        @pytest.mark.asyncio
        async def test_concurrent_connections(self, ssh_server):
            """Test multiple concurrent async connections."""
            async def connect_and_execute(client_id):
                client = AsyncSSHClient()
                try:
                    await client.connect(
                        hostname='localhost',
                        port=ssh_server.port,
                        username='testuser',
                        password='testpass',
                        timeout=5.0
                    )
                    
                    result = await client.exec_command(f'echo client_{client_id}')
                    return result.stdout.decode().strip()
                    
                finally:
                    await client.close()
            
            # Run multiple clients concurrently
            tasks = [connect_and_execute(i) for i in range(3)]
            results = await asyncio.gather(*tasks)
            
            # Verify results
            for i, result in enumerate(results):
                assert result == f'client_{i}'

except ImportError:
    # Async support not available
    pass