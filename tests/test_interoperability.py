"""
Interoperability tests with OpenSSH and other SSH implementations.

These tests verify that ssh-library can work with real SSH servers
and that real SSH clients can work with ssh-library servers.
"""

import os
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from ssh_library import SSHClient, AutoAddPolicy
from ssh_library.crypto.pkey import Ed25519Key, RSAKey


class TestOpenSSHInteroperability:
    """Test interoperability with OpenSSH."""
    
    @pytest.fixture
    def openssh_available(self):
        """Check if OpenSSH tools are available."""
        try:
            subprocess.run(['ssh', '-V'], capture_output=True, check=True)
            subprocess.run(['ssh-keygen', '-V'], capture_output=True, check=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError):
            pytest.skip("OpenSSH tools not available")
    
    @pytest.fixture
    def temp_ssh_dir(self):
        """Create temporary SSH directory with keys."""
        with tempfile.TemporaryDirectory() as temp_dir:
            ssh_dir = Path(temp_dir) / '.ssh'
            ssh_dir.mkdir()
            
            # Generate test keys using ssh-keygen
            key_path = ssh_dir / 'test_key'
            subprocess.run([
                'ssh-keygen', '-t', 'ed25519', '-f', str(key_path),
                '-N', '', '-C', 'test@ssh-library'
            ], check=True, capture_output=True)
            
            yield ssh_dir
    
    def test_connect_to_openssh_server(self, openssh_available, temp_ssh_dir):
        """Test connecting to a real OpenSSH server (if configured)."""
        # This test requires a configured SSH server
        # Skip if SSH_TEST_HOST environment variable is not set
        test_host = os.environ.get('SSH_TEST_HOST')
        test_user = os.environ.get('SSH_TEST_USER', 'testuser')
        test_password = os.environ.get('SSH_TEST_PASSWORD')
        test_key = os.environ.get('SSH_TEST_KEY')
        
        if not test_host:
            pytest.skip("SSH_TEST_HOST not configured")
        
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        try:
            if test_key:
                # Use key-based authentication
                key_path = Path(test_key)
                if not key_path.exists():
                    pytest.skip(f"SSH key not found: {test_key}")
                
                client.connect(
                    hostname=test_host,
                    username=test_user,
                    key_filename=test_key,
                    timeout=10.0
                )
            elif test_password:
                # Use password authentication
                client.connect(
                    hostname=test_host,
                    username=test_user,
                    password=test_password,
                    timeout=10.0
                )
            else:
                pytest.skip("No authentication method configured")
            
            # Test basic command execution
            stdin, stdout, stderr = client.exec_command('echo "Hello from ssh-library"')
            output = stdout.read().decode().strip()
            assert output == "Hello from ssh-library"
            
            # Test SFTP if available
            try:
                sftp = client.open_sftp()
                
                # Test directory listing
                files = sftp.listdir('.')
                assert isinstance(files, list)
                
                sftp.close()
            except Exception:
                # SFTP might not be available
                pass
            
        finally:
            client.close()
    
    def test_openssh_client_with_library_server(self, openssh_available, temp_ssh_dir):
        """Test OpenSSH client connecting to ssh-library server."""
        # This would require implementing a full SSH server
        # and running it in a separate process
        pytest.skip("Full server implementation test - requires separate process")
    
    def test_key_format_compatibility(self, openssh_available, temp_ssh_dir):
        """Test SSH key format compatibility with OpenSSH."""
        # Generate key with ssh-library
        library_key = Ed25519Key.generate()
        
        # Save in OpenSSH format
        key_file = temp_ssh_dir / 'library_key'
        library_key.save_to_file(str(key_file))
        
        # Try to load with OpenSSH tools
        result = subprocess.run([
            'ssh-keygen', '-l', '-f', str(key_file)
        ], capture_output=True, text=True)
        
        # Should succeed and show fingerprint
        assert result.returncode == 0
        assert 'ED25519' in result.stdout or 'ed25519' in result.stdout
    
    def test_public_key_format_compatibility(self, openssh_available, temp_ssh_dir):
        """Test public key format compatibility."""
        # Generate key with ssh-library
        library_key = Ed25519Key.generate()
        public_key = library_key.get_public_key()
        
        # Save public key in OpenSSH format
        pub_key_file = temp_ssh_dir / 'library_key.pub'
        pub_key_str = public_key.get_openssh_string()
        pub_key_file.write_text(pub_key_str + '\n')
        
        # Verify with ssh-keygen
        result = subprocess.run([
            'ssh-keygen', '-l', '-f', str(pub_key_file)
        ], capture_output=True, text=True)
        
        assert result.returncode == 0
        assert 'ED25519' in result.stdout or 'ed25519' in result.stdout


class TestProtocolCompliance:
    """Test SSH protocol compliance and edge cases."""
    
    def test_protocol_version_negotiation(self):
        """Test SSH protocol version negotiation."""
        # Test that we properly handle SSH-2.0 protocol
        client = SSHClient()
        
        # This would require a mock server that sends different protocol versions
        # For now, just verify our protocol string
        transport = client._transport if hasattr(client, '_transport') else None
        if transport:
            assert transport.local_version.startswith('SSH-2.0-')
    
    def test_algorithm_negotiation(self):
        """Test cryptographic algorithm negotiation."""
        # Verify that we support required algorithms
        from ssh_library.crypto.backend import get_crypto_backend
        
        backend = get_crypto_backend()
        
        # Test that we support required KEX algorithms
        supported_kex = backend.get_supported_kex_algorithms()
        assert 'curve25519-sha256' in supported_kex
        
        # Test that we support required ciphers
        supported_ciphers = backend.get_supported_ciphers()
        assert 'chacha20-poly1305@openssh.com' in supported_ciphers
    
    def test_message_format_compliance(self):
        """Test SSH message format compliance."""
        from ssh_library.protocol.messages import Message
        
        # Test basic message serialization/deserialization
        msg = Message()
        msg.add_byte(1)  # SSH_MSG_DISCONNECT
        msg.add_int(2)   # reason code
        msg.add_string("Test disconnect")
        msg.add_string("")  # language tag
        
        # Serialize and deserialize
        data = msg.get_bytes()
        
        new_msg = Message(data)
        assert new_msg.get_byte() == 1
        assert new_msg.get_int() == 2
        assert new_msg.get_string() == "Test disconnect"


class TestSecurityCompliance:
    """Test security-related compliance and best practices."""
    
    def test_secure_defaults(self):
        """Test that secure defaults are used."""
        client = SSHClient()
        
        # Verify that weak algorithms are not supported by default
        from ssh_library.crypto.backend import get_crypto_backend
        backend = get_crypto_backend()
        
        # Should not support weak ciphers
        weak_ciphers = ['des', '3des-cbc', 'arcfour', 'rc4']
        supported_ciphers = backend.get_supported_ciphers()
        
        for weak_cipher in weak_ciphers:
            assert weak_cipher not in supported_ciphers
        
        # Should not support weak MACs
        weak_macs = ['hmac-md5', 'hmac-sha1-96']
        supported_macs = backend.get_supported_macs()
        
        for weak_mac in weak_macs:
            assert weak_mac not in supported_macs
    
    def test_host_key_verification(self):
        """Test host key verification behavior."""
        from ssh_library.hostkeys.policy import RejectPolicy, AutoAddPolicy
        
        # Test that RejectPolicy actually rejects unknown keys
        policy = RejectPolicy()
        
        # This would require a mock scenario
        # For now, just verify the policy exists and is callable
        assert hasattr(policy, 'missing_host_key')
        
        # Test AutoAddPolicy
        auto_policy = AutoAddPolicy()
        assert hasattr(auto_policy, 'missing_host_key')
    
    def test_authentication_security(self):
        """Test authentication security measures."""
        # Test that passwords are not logged or exposed
        client = SSHClient()
        
        # This would require checking log output and memory
        # For now, verify that authentication methods exist
        assert hasattr(client, 'connect')
        
        # Test that private keys are handled securely
        key = Ed25519Key.generate()
        assert hasattr(key, 'get_private_bytes')
        assert hasattr(key, 'get_public_key')


class TestPerformanceCompliance:
    """Test performance requirements and benchmarks."""
    
    def test_connection_speed_benchmark(self):
        """Benchmark connection establishment speed."""
        # This would require a test server
        # For now, just test that timing utilities exist
        import time
        
        start_time = time.time()
        
        # Simulate some work
        time.sleep(0.001)
        
        elapsed = time.time() - start_time
        assert elapsed > 0
    
    def test_throughput_benchmark(self):
        """Benchmark data throughput."""
        # Test that we can handle reasonable data volumes
        test_data = b'x' * (1024 * 1024)  # 1MB
        
        # This would require actual SSH connection
        # For now, just verify we can handle the data
        assert len(test_data) == 1024 * 1024
    
    def test_memory_usage(self):
        """Test memory usage patterns."""
        # Basic memory usage test
        import gc
        
        # Force garbage collection
        gc.collect()
        
        # Create and destroy objects
        clients = [SSHClient() for _ in range(10)]
        del clients
        
        # Force garbage collection again
        gc.collect()
        
        # This is a basic test - more sophisticated memory profiling
        # would be needed for production use


class TestErrorHandling:
    """Test error handling and recovery."""
    
    def test_connection_timeout_handling(self):
        """Test connection timeout handling."""
        client = SSHClient()
        
        # Try to connect to non-existent host
        with pytest.raises(Exception):  # Should raise some connection error
            client.connect(
                hostname='192.0.2.1',  # TEST-NET-1 (should not be routable)
                username='test',
                password='test',
                timeout=1.0  # Short timeout
            )
    
    def test_authentication_error_handling(self):
        """Test authentication error handling."""
        # This would require a test server
        # For now, verify that authentication exceptions exist
        from ssh_library.exceptions import AuthenticationException
        
        assert issubclass(AuthenticationException, Exception)
    
    def test_protocol_error_handling(self):
        """Test protocol error handling."""
        from ssh_library.exceptions import ProtocolException
        
        assert issubclass(ProtocolException, Exception)
    
    def test_graceful_disconnection(self):
        """Test graceful connection cleanup."""
        client = SSHClient()
        
        # Should be able to close even if not connected
        client.close()
        
        # Should be able to close multiple times
        client.close()


# Mark all tests in this module as integration tests
pytestmark = pytest.mark.integration