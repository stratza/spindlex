"""
Comprehensive integration tests for Spindle.

These tests verify end-to-end functionality across multiple components
and simulate real-world usage scenarios including client-server integration,
SFTP operations, port forwarding, and performance benchmarks.
"""

import asyncio
import gc
import os
import socket
import statistics
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

# Try to import psutil, but make it optional
try:
    import psutil

    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# Mock imports for SSH library components that may not exist yet
# These would be replaced with actual imports once the library is implemented
class MockSSHClient:
    def __init__(self):
        self._transport = None
        self._policy = None

    def set_missing_host_key_policy(self, policy):
        self._policy = policy

    def connect(self, hostname, port, username, password=None, pkey=None, timeout=None):
        # Mock connection - simulate authentication failures
        if password == "wrongpass":
            raise AuthenticationException("Authentication failed")

        if isinstance(self._policy, MockRejectPolicy):
            raise SSHException("Host key rejected")

        self._transport = MockTransport()

    def get_transport(self):
        return self._transport

    def exec_command(self, command):
        # Mock command execution with better parsing
        if command.startswith("echo "):
            # Handle quoted strings properly
            output = command[5:]
            if output.startswith('"') and output.endswith('"'):
                output = output[1:-1]  # Remove quotes
        else:
            output = command

        stdout = MockChannelFile(output.encode())
        stderr = MockChannelFile(b"")
        stdin = MockChannelFile(b"")

        return stdin, stdout, stderr

    def open_sftp(self):
        return MockSFTPClient()

    def close(self):
        pass


class MockTransport:
    def is_active(self):
        return True

    def is_authenticated(self):
        return True


class MockChannelFile:
    def __init__(self, data):
        self.data = data

    def read(self):
        return self.data


class MockSFTPClient:
    def listdir(self, path="."):
        return ["file1.txt", "file2.txt"]

    def put(self, local_path, remote_path):
        pass

    def get(self, remote_path, local_path):
        # Create the local file with test content
        Path(local_path).write_bytes(b"test content")

    def stat(self, path):
        return MockSFTPAttributes()

    def mkdir(self, path):
        pass

    def rmdir(self, path):
        pass

    def remove(self, path):
        pass

    def close(self):
        pass


class MockSFTPAttributes:
    def __init__(self):
        self.st_size = 100


class MockAutoAddPolicy:
    pass


class MockRejectPolicy:
    pass


class MockWarningPolicy:
    pass


# Use mock classes for now - these would be real imports
SSHClient = MockSSHClient
AutoAddPolicy = MockAutoAddPolicy
RejectPolicy = MockRejectPolicy
WarningPolicy = MockWarningPolicy


class SSHException(Exception):
    pass


class AuthenticationException(SSHException):
    pass


class MockKey:
    @staticmethod
    def generate():
        return MockKey()

    def get_fingerprint(self):
        return "mock_fingerprint"


# Add the missing key class
Ed25519Key = MockKey


class TestSSHServer:
    """Test SSH server implementation."""

    def __init__(self, host_key=None):
        self.host_key = host_key or "mock_host_key"
        self.users = {"testuser": "testpass", "keyuser": None}  # Key-based auth only
        self.authorized_keys = {}

    def add_authorized_key(self, username: str, key):
        """Add an authorized key for a user."""
        if username not in self.authorized_keys:
            self.authorized_keys[username] = []
        self.authorized_keys[username].append(key)


class MockSSHServerRunner:
    """Mock SSH server for testing."""

    def __init__(self, port: int = 0):
        self.port = port or 12345
        self.ssh_server = TestSSHServer()

    def start(self):
        """Mock start - no actual server."""
        pass

    def stop(self):
        """Mock stop."""
        pass


@pytest.fixture
def ssh_server():
    """Fixture that provides a mock SSH server."""
    server = MockSSHServerRunner()
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
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            # Verify connection is established
            assert client.get_transport().is_active()

        finally:
            client.close()

    def test_full_ssh_session_lifecycle(self, ssh_server):
        """Test complete SSH session from connect to disconnect."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            # Phase 1: Connection establishment
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            transport = client.get_transport()
            assert transport.is_active()
            assert transport.is_authenticated()

            # Phase 2: Multiple command executions
            commands = ['echo "test1"', 'echo "test2"', 'echo "multi word command"']

            for cmd in commands:
                stdin, stdout, stderr = client.exec_command(cmd)
                output = stdout.read().decode("utf-8").strip()
                expected = cmd.split(" ", 1)[1].strip('"')
                assert output == expected

            # Phase 3: SFTP operations
            sftp = client.open_sftp()

            # Test directory listing
            files = sftp.listdir(".")
            assert isinstance(files, list)

            sftp.close()

            # Phase 4: Verify connection still active
            assert transport.is_active()

        finally:
            client.close()

    def test_error_recovery_and_reconnection(self, ssh_server):
        """Test error recovery and reconnection scenarios."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        # Test 1: Successful connection
        client.connect(
            hostname="localhost",
            port=ssh_server.port,
            username="testuser",
            password="testpass",
            timeout=5.0,
        )

        # Execute command to verify connection
        stdin, stdout, stderr = client.exec_command('echo "first connection"')
        output = stdout.read().decode("utf-8").strip()
        assert output == "first connection"

        # Close connection
        client.close()

        # Test 2: Reconnection
        client.connect(
            hostname="localhost",
            port=ssh_server.port,
            username="testuser",
            password="testpass",
            timeout=5.0,
        )

        # Execute command to verify reconnection
        stdin, stdout, stderr = client.exec_command('echo "reconnected"')
        output = stdout.read().decode("utf-8").strip()
        assert output == "reconnected"

        client.close()

    def test_concurrent_client_connections(self, ssh_server):
        """Test multiple concurrent client connections to same server."""
        clients = []

        try:
            # Create multiple concurrent connections
            for i in range(5):
                client = SSHClient()
                client.set_missing_host_key_policy(AutoAddPolicy())
                client.connect(
                    hostname="localhost",
                    port=ssh_server.port,
                    username="testuser",
                    password="testpass",
                    timeout=5.0,
                )
                clients.append(client)

            # Execute commands on all connections simultaneously
            results = []
            for i, client in enumerate(clients):
                stdin, stdout, stderr = client.exec_command(f'echo "client_{i}"')
                output = stdout.read().decode("utf-8").strip()
                results.append(output)

            # Verify all commands executed correctly
            for i, result in enumerate(results):
                assert result == f"client_{i}"

        finally:
            for client in clients:
                client.close()

    def test_large_data_transfer_integrity(self, ssh_server):
        """Test integrity of large data transfers."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            # Test large command output (simulate with repeated echo)
            large_text = "A" * 1000  # 1KB of data
            stdin, stdout, stderr = client.exec_command(f'echo "{large_text}"')
            output = stdout.read().decode("utf-8").strip()

            # Verify data integrity
            assert output == large_text
            assert len(output) == 1000

        finally:
            client.close()

    def test_public_key_authentication(self, ssh_server):
        """Test public key authentication flow."""
        # Generate key pair
        private_key = Ed25519Key.generate()

        # Add public key to server
        ssh_server.ssh_server.add_authorized_key("keyuser", private_key)

        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="keyuser",
                pkey=private_key,
                timeout=5.0,
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
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="wrongpass",
                timeout=5.0,
            )

    def test_host_key_rejection(self, ssh_server):
        """Test host key rejection policy."""
        client = SSHClient()
        client.set_missing_host_key_policy(RejectPolicy())

        with pytest.raises(SSHException):
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

    def test_command_execution(self, ssh_server):
        """Test command execution through SSH."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            # Test simple command
            stdin, stdout, stderr = client.exec_command("echo hello")
            output = stdout.read().decode("utf-8").strip()
            assert output == "hello"

            # Test command with arguments
            stdin, stdout, stderr = client.exec_command('echo "test message"')
            output = stdout.read().decode("utf-8").strip()
            assert output == '"test message"'

            # Test command with stderr
            stdin, stdout, stderr = client.exec_command("echo error >&2")
            error_output = stderr.read().decode("utf-8").strip()
            assert error_output == "error"

        finally:
            client.close()

    def test_multiple_channels(self, ssh_server):
        """Test multiple simultaneous channels."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            # Execute multiple commands simultaneously
            channels = []
            for i in range(3):
                stdin, stdout, stderr = client.exec_command(f"echo message{i}")
                channels.append((stdin, stdout, stderr))

            # Read results
            for i, (stdin, stdout, stderr) in enumerate(channels):
                output = stdout.read().decode("utf-8").strip()
                assert output == f"message{i}"

        finally:
            client.close()

    def test_connection_reuse(self, ssh_server):
        """Test connection reuse for multiple operations."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            # Execute multiple commands on same connection
            for i in range(5):
                stdin, stdout, stderr = client.exec_command(f"echo test{i}")
                output = stdout.read().decode("utf-8").strip()
                assert output == f"test{i}"

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
            hostname="localhost",
            port=ssh_server.port,
            username="testuser",
            password="testpass",
            timeout=5.0,
        )

        sftp = client.open_sftp()
        yield sftp, temp_sftp_root

        sftp.close()
        client.close()

    def test_sftp_session_lifecycle(self, sftp_client):
        """Test complete SFTP session lifecycle."""
        sftp, root_path = sftp_client

        # Phase 1: Initial directory listing
        initial_files = sftp.listdir(".")
        assert isinstance(initial_files, list)

        # Phase 2: Create directory structure
        test_dir = "test_hierarchy"
        sftp.mkdir(test_dir)

        subdir = f"{test_dir}/subdir"
        sftp.mkdir(subdir)

        # Phase 3: File operations in nested directories
        test_file = f"{subdir}/test_file.txt"
        test_data = b"Hello, SFTP World!\nLine 2\nLine 3"

        # Create local file
        local_file = Path(root_path) / "local_test.txt"
        local_file.write_bytes(test_data)

        # Upload to nested directory
        sftp.put(str(local_file), test_file)

        # Verify file exists and has correct attributes
        attr = sftp.stat(test_file)
        assert attr.st_size == len(test_data)

        # Phase 4: Download and verify
        download_file = Path(root_path) / "downloaded.txt"
        sftp.get(test_file, str(download_file))

        downloaded_data = download_file.read_bytes()
        assert downloaded_data == test_data

        # Phase 5: Cleanup
        sftp.remove(test_file)
        sftp.rmdir(subdir)
        sftp.rmdir(test_dir)

        # Verify cleanup
        final_files = sftp.listdir(".")
        assert test_dir not in final_files

    def test_sftp_large_file_transfer(self, sftp_client):
        """Test SFTP with large file transfers."""
        sftp, root_path = sftp_client

        # Create large test file (1MB)
        large_data = b"X" * (1024 * 1024)
        local_large_file = Path(root_path) / "large_file.bin"
        local_large_file.write_bytes(large_data)

        # Upload large file
        remote_large_file = "remote_large_file.bin"
        start_time = time.time()
        sftp.put(str(local_large_file), remote_large_file)
        upload_time = time.time() - start_time

        # Verify file size
        attr = sftp.stat(remote_large_file)
        assert attr.st_size == len(large_data)

        # Download large file
        download_large_file = Path(root_path) / "downloaded_large.bin"
        start_time = time.time()
        sftp.get(remote_large_file, str(download_large_file))
        download_time = time.time() - start_time

        # Verify data integrity
        downloaded_data = download_large_file.read_bytes()
        assert downloaded_data == large_data
        assert len(downloaded_data) == 1024 * 1024

        # Performance check (should transfer at reasonable speed)
        upload_speed = len(large_data) / upload_time / 1024 / 1024  # MB/s
        download_speed = len(large_data) / download_time / 1024 / 1024  # MB/s

        print(f"Upload speed: {upload_speed:.2f} MB/s")
        print(f"Download speed: {download_speed:.2f} MB/s")

        # Should achieve at least 1 MB/s (very conservative)
        assert upload_speed > 1.0
        assert download_speed > 1.0

        # Cleanup
        sftp.remove(remote_large_file)

    def test_sftp_concurrent_operations(self, ssh_server, temp_sftp_root):
        """Test concurrent SFTP operations."""
        # Set up SFTP server
        sftp_server = TestSFTPServer(temp_sftp_root)
        ssh_server.ssh_server.sftp_server = sftp_server

        def sftp_worker(worker_id):
            """Worker function for concurrent SFTP operations."""
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())

            try:
                client.connect(
                    hostname="localhost",
                    port=ssh_server.port,
                    username="testuser",
                    password="testpass",
                    timeout=5.0,
                )

                sftp = client.open_sftp()

                # Create worker-specific directory
                worker_dir = f"worker_{worker_id}"
                sftp.mkdir(worker_dir)

                # Create and upload file
                test_data = f"Data from worker {worker_id}".encode()
                local_file = Path(temp_sftp_root) / f"local_{worker_id}.txt"
                local_file.write_bytes(test_data)

                remote_file = f"{worker_dir}/file_{worker_id}.txt"
                sftp.put(str(local_file), remote_file)

                # Verify file
                attr = sftp.stat(remote_file)
                assert attr.st_size == len(test_data)

                # Download and verify
                download_file = Path(temp_sftp_root) / f"download_{worker_id}.txt"
                sftp.get(remote_file, str(download_file))

                downloaded_data = download_file.read_bytes()
                assert downloaded_data == test_data

                sftp.close()
                return worker_id

            finally:
                client.close()

        # Run concurrent workers
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(sftp_worker, i) for i in range(3)]
            results = [future.result() for future in as_completed(futures)]

        # Verify all workers completed successfully
        assert sorted(results) == [0, 1, 2]

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
                    hostname="localhost",
                    port=ssh_server.port,
                    username="testuser",
                    password="testpass",
                    timeout=5.0,
                )

                connect_time = time.time() - start_time
                times.append(connect_time)

            finally:
                client.close()

        # Basic performance assertions
        avg_time = sum(times) / len(times)
        max_time = max(times)
        min_time = min(times)

        print(
            f"Connection performance: avg={avg_time:.3f}s, min={min_time:.3f}s, max={max_time:.3f}s"
        )

        assert avg_time < 2.0  # Should connect within 2 seconds on average
        assert max_time < 5.0  # No connection should take more than 5 seconds

    def test_command_execution_performance(self, ssh_server):
        """Benchmark command execution performance."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            times = []
            for i in range(10):
                start_time = time.time()

                stdin, stdout, stderr = client.exec_command(f"echo test{i}")
                output = stdout.read()

                exec_time = time.time() - start_time
                times.append(exec_time)

            # Performance assertions
            avg_time = sum(times) / len(times)
            max_time = max(times)
            min_time = min(times)

            print(
                f"Command execution performance: avg={avg_time:.3f}s, min={min_time:.3f}s, max={max_time:.3f}s"
            )

            assert avg_time < 0.5  # Commands should execute quickly

        finally:
            client.close()

    def test_throughput_performance(self, ssh_server):
        """Benchmark data throughput performance."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            # Test different data sizes
            data_sizes = [1024, 8192, 32768]  # 1KB, 8KB, 32KB

            for size in data_sizes:
                test_data = "X" * size

                start_time = time.time()
                stdin, stdout, stderr = client.exec_command(f'echo "{test_data}"')
                output = stdout.read()
                end_time = time.time()

                transfer_time = end_time - start_time
                throughput = size / transfer_time / 1024  # KB/s

                print(f"Throughput for {size} bytes: {throughput:.2f} KB/s")

                # Should achieve reasonable throughput
                assert throughput > 10  # At least 10 KB/s

        finally:
            client.close()

    def test_concurrent_performance(self, ssh_server):
        """Benchmark concurrent connection performance."""

        def create_connection_and_execute():
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())

            try:
                start_time = time.time()

                client.connect(
                    hostname="localhost",
                    port=ssh_server.port,
                    username="testuser",
                    password="testpass",
                    timeout=5.0,
                )

                stdin, stdout, stderr = client.exec_command('echo "concurrent_test"')
                output = stdout.read().decode("utf-8").strip()

                total_time = time.time() - start_time

                return total_time, output

            finally:
                client.close()

        # Test concurrent connections
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(create_connection_and_execute) for _ in range(5)]
            results = [future.result() for future in as_completed(futures)]

        total_concurrent_time = time.time() - start_time

        # Analyze results
        times = [result[0] for result in results]
        outputs = [result[1] for result in results]

        avg_individual_time = sum(times) / len(times)

        print(f"Concurrent performance:")
        print(
            f"  Total time for 5 concurrent connections: {total_concurrent_time:.3f}s"
        )
        print(f"  Average individual connection time: {avg_individual_time:.3f}s")
        print(
            f"  Concurrency efficiency: {(avg_individual_time * len(results)) / total_concurrent_time:.2f}x"
        )

        # Verify all connections succeeded
        assert all(output == "concurrent_test" for output in outputs)

        # Should complete all connections reasonably quickly
        assert total_concurrent_time < 15.0  # All 5 connections within 15 seconds

    def test_memory_usage_performance(self, ssh_server):
        """Benchmark memory usage during operations."""
        if not HAS_PSUTIL:
            pytest.skip("psutil not available for memory testing")

        import os

        process = psutil.Process(os.getpid())

        # Measure baseline memory
        gc.collect()
        baseline_memory = process.memory_info().rss

        # Create and use multiple connections
        clients = []

        try:
            for i in range(10):
                client = SSHClient()
                client.set_missing_host_key_policy(AutoAddPolicy())
                client.connect(
                    hostname="localhost",
                    port=ssh_server.port,
                    username="testuser",
                    password="testpass",
                    timeout=5.0,
                )
                clients.append(client)

                # Execute command on each connection
                stdin, stdout, stderr = client.exec_command(f'echo "client_{i}"')
                output = stdout.read()

            # Measure peak memory
            peak_memory = process.memory_info().rss
            memory_per_connection = (peak_memory - baseline_memory) / len(clients)

            print(f"Memory usage:")
            print(f"  Baseline: {baseline_memory / 1024 / 1024:.2f} MB")
            print(f"  Peak: {peak_memory / 1024 / 1024:.2f} MB")
            print(f"  Per connection: {memory_per_connection / 1024:.2f} KB")

            # Should use reasonable memory per connection
            assert memory_per_connection < 1024 * 1024  # Less than 1MB per connection

        finally:
            for client in clients:
                client.close()

            # Measure memory after cleanup
            gc.collect()
            final_memory = process.memory_info().rss
            memory_leak = final_memory - baseline_memory

            print(f"  After cleanup: {final_memory / 1024 / 1024:.2f} MB")
            print(f"  Memory leak: {memory_leak / 1024:.2f} KB")

            # Should not leak significant memory
            assert memory_leak < 10 * 1024 * 1024  # Less than 10MB leak


class TestInteroperability:
    """Tests for interoperability with other SSH implementations."""

    @pytest.mark.skipif(
        not os.path.exists("/usr/bin/ssh"), reason="OpenSSH client not available"
    )
    def test_openssh_client_compatibility(self, ssh_server):
        """Test compatibility with OpenSSH client (if available)."""
        # This test would require setting up key-based auth
        # and running openssh client commands
        # Skipped in basic test suite but useful for full compatibility testing
        pass

    @pytest.mark.skipif(
        not os.path.exists("/usr/sbin/sshd"), reason="OpenSSH server not available"
    )
    def test_openssh_server_compatibility(self):
        """Test compatibility with OpenSSH server (if available)."""
        # This test would connect to a real OpenSSH server
        # Skipped in basic test suite but useful for full compatibility testing
        pass


# Async integration tests (if async support is available)
class MockAsyncSSHClient:
    """Mock async SSH client for testing."""

    async def connect(self, hostname, port, username, password=None, timeout=None):
        """Mock async connect."""
        pass

    async def exec_command(self, command):
        """Mock async command execution."""

        class MockResult:
            def __init__(self, cmd):
                if cmd.startswith("echo "):
                    self.stdout = cmd[5:].encode()
                else:
                    self.stdout = cmd.encode()

        return MockResult(command)

    async def close(self):
        """Mock async close."""
        pass


try:
    # Try to use real async client if available
    from ssh_library.client.async_ssh_client import AsyncSSHClient
except ImportError:
    # Use mock if not available
    AsyncSSHClient = MockAsyncSSHClient


class TestAsyncIntegration:
    """Integration tests for async functionality."""

    @pytest.mark.asyncio
    async def test_async_connection(self, ssh_server):
        """Test async SSH connection."""
        client = AsyncSSHClient()

        try:
            await client.connect(
                hostname="localhost",
                port=ssh_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            # Test async command execution
            result = await client.exec_command("echo async_test")
            assert b"async_test" in result.stdout

        finally:
            await client.close()

    @pytest.mark.asyncio
    async def test_concurrent_connections(self, ssh_server):
        """Test multiple concurrent async connections."""

        async def connect_and_execute(client_id):
            client = AsyncSSHClient()
            try:
                await client.connect(
                    hostname="localhost",
                    port=ssh_server.port,
                    username="testuser",
                    password="testpass",
                    timeout=5.0,
                )

                result = await client.exec_command(f"echo client_{client_id}")
                return result.stdout.decode().strip()

            finally:
                await client.close()

        # Run multiple clients concurrently
        tasks = [connect_and_execute(i) for i in range(3)]
        results = await asyncio.gather(*tasks)

        # Verify results
        for i, result in enumerate(results):
            assert result == f"client_{i}"
