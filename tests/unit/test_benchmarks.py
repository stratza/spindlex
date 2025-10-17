"""
Performance benchmark suite for Spindle.

This module contains comprehensive performance tests and benchmarks
to ensure the library meets performance requirements.
"""

import asyncio
import gc
import statistics
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List

import pytest

from spindle import AutoAddPolicy, SSHClient

# Skip all tests in this module if full implementation is not available
pytest.importorskip(
    "spindle.crypto.pkey", reason="Full Spindle implementation not available"
)
pytest.importorskip(
    "spindle.crypto.backend", reason="Full Spindle implementation not available"
)
pytest.importorskip(
    "spindle.logging", reason="Full Spindle implementation not available"
)

from spindle.crypto.backend import get_crypto_backend
from spindle.crypto.pkey import ECDSAKey, Ed25519Key, RSAKey
from spindle.logging import get_performance_monitor


class BenchmarkResult:
    """Container for benchmark results."""

    def __init__(self, name: str, times: List[float], unit: str = "seconds"):
        self.name = name
        self.times = times
        self.unit = unit
        self.count = len(times)
        self.mean = statistics.mean(times) if times else 0
        self.median = statistics.median(times) if times else 0
        self.stdev = statistics.stdev(times) if len(times) > 1 else 0
        self.min_time = min(times) if times else 0
        self.max_time = max(times) if times else 0

    def __str__(self):
        return (
            f"{self.name}: {self.mean:.4f}±{self.stdev:.4f} {self.unit} "
            f"(n={self.count}, min={self.min_time:.4f}, max={self.max_time:.4f})"
        )


def benchmark_function(
    func, iterations: int = 100, warmup: int = 10
) -> BenchmarkResult:
    """Benchmark a function with warmup and multiple iterations."""
    # Warmup
    for _ in range(warmup):
        func()

    # Actual benchmark
    times = []
    for _ in range(iterations):
        start_time = time.perf_counter()
        func()
        end_time = time.perf_counter()
        times.append(end_time - start_time)

    return BenchmarkResult(func.__name__, times)


class TestCryptographicBenchmarks:
    """Benchmark cryptographic operations."""

    def test_key_generation_performance(self):
        """Benchmark key generation for different algorithms."""
        results = {}

        # Ed25519 key generation
        def gen_ed25519():
            Ed25519Key.generate()

        results["ed25519_keygen"] = benchmark_function(gen_ed25519, iterations=50)

        # ECDSA key generation
        def gen_ecdsa():
            ECDSAKey.generate()

        results["ecdsa_keygen"] = benchmark_function(gen_ecdsa, iterations=50)

        # RSA key generation (smaller iterations due to cost)
        def gen_rsa_2048():
            RSAKey.generate(2048)

        results["rsa_2048_keygen"] = benchmark_function(gen_rsa_2048, iterations=10)

        def gen_rsa_4096():
            RSAKey.generate(4096)

        results["rsa_4096_keygen"] = benchmark_function(gen_rsa_4096, iterations=5)

        # Print results
        for name, result in results.items():
            print(f"\n{result}")

        # Performance assertions
        assert results["ed25519_keygen"].mean < 0.1  # Should be very fast
        assert results["ecdsa_keygen"].mean < 0.1  # Should be very fast
        assert results["rsa_2048_keygen"].mean < 2.0  # Should be reasonable
        assert results["rsa_4096_keygen"].mean < 10.0  # Slower but acceptable

    def test_signature_performance(self):
        """Benchmark signature operations."""
        # Generate keys
        ed25519_key = Ed25519Key.generate()
        ecdsa_key = ECDSAKey.generate()
        rsa_key = RSAKey.generate(2048)

        test_data = b"Hello, World!" * 100  # 1.3KB of data

        results = {}

        # Ed25519 signing
        def sign_ed25519():
            ed25519_key.sign(test_data)

        results["ed25519_sign"] = benchmark_function(sign_ed25519, iterations=1000)

        # ECDSA signing
        def sign_ecdsa():
            ecdsa_key.sign(test_data)

        results["ecdsa_sign"] = benchmark_function(sign_ecdsa, iterations=1000)

        # RSA signing
        def sign_rsa():
            rsa_key.sign(test_data)

        results["rsa_sign"] = benchmark_function(sign_rsa, iterations=500)

        # Verification benchmarks
        ed25519_sig = ed25519_key.sign(test_data)
        ecdsa_sig = ecdsa_key.sign(test_data)
        rsa_sig = rsa_key.sign(test_data)

        def verify_ed25519():
            ed25519_key.get_public_key().verify(ed25519_sig, test_data)

        results["ed25519_verify"] = benchmark_function(verify_ed25519, iterations=1000)

        def verify_ecdsa():
            ecdsa_key.get_public_key().verify(ecdsa_sig, test_data)

        results["ecdsa_verify"] = benchmark_function(verify_ecdsa, iterations=1000)

        def verify_rsa():
            rsa_key.get_public_key().verify(rsa_sig, test_data)

        results["rsa_verify"] = benchmark_function(verify_rsa, iterations=500)

        # Print results
        for name, result in results.items():
            print(f"\n{result}")

        # Performance assertions
        assert results["ed25519_sign"].mean < 0.001  # Very fast
        assert results["ed25519_verify"].mean < 0.001  # Very fast
        assert results["ecdsa_sign"].mean < 0.01  # Fast
        assert results["ecdsa_verify"].mean < 0.01  # Fast
        assert results["rsa_sign"].mean < 0.1  # Reasonable
        assert results["rsa_verify"].mean < 0.01  # Fast verification

    def test_encryption_performance(self):
        """Benchmark encryption/decryption operations."""
        backend = get_crypto_backend()

        # Test data of various sizes
        test_sizes = [1024, 8192, 65536]  # 1KB, 8KB, 64KB

        for size in test_sizes:
            test_data = b"x" * size

            # Test ChaCha20-Poly1305
            key = backend.generate_random_bytes(32)
            nonce = backend.generate_random_bytes(12)

            def encrypt_chacha20():
                cipher = backend.create_cipher(
                    "chacha20-poly1305@openssh.com", key, nonce
                )
                return cipher.encrypt(test_data)

            result = benchmark_function(encrypt_chacha20, iterations=100)
            print(f"\nChaCha20-Poly1305 encrypt {size} bytes: {result}")

            # Calculate throughput
            throughput_mbps = (size * result.count) / (sum(result.times) * 1024 * 1024)
            print(f"Throughput: {throughput_mbps:.2f} MB/s")

            # Should achieve reasonable throughput
            assert throughput_mbps > 10  # At least 10 MB/s

    def test_key_exchange_performance(self):
        """Benchmark key exchange operations."""
        backend = get_crypto_backend()

        results = {}

        # Curve25519 key exchange
        def kex_curve25519():
            private_key = backend.generate_curve25519_private_key()
            public_key = private_key.public_key()
            peer_private = backend.generate_curve25519_private_key()
            peer_public = peer_private.public_key()

            # Perform key exchange
            shared_secret = private_key.exchange(peer_public)
            return shared_secret

        results["curve25519_kex"] = benchmark_function(kex_curve25519, iterations=100)

        # ECDH key exchange
        def kex_ecdh():
            private_key = backend.generate_ecdh_private_key()
            public_key = private_key.public_key()
            peer_private = backend.generate_ecdh_private_key()
            peer_public = peer_private.public_key()

            # Perform key exchange
            shared_secret = private_key.exchange(peer_public)
            return shared_secret

        results["ecdh_kex"] = benchmark_function(kex_ecdh, iterations=100)

        # Print results
        for name, result in results.items():
            print(f"\n{result}")

        # Performance assertions
        assert results["curve25519_kex"].mean < 0.01  # Should be very fast
        assert results["ecdh_kex"].mean < 0.01  # Should be very fast


class TestConnectionBenchmarks:
    """Benchmark SSH connection operations."""

    @pytest.fixture
    def mock_server(self):
        """Mock SSH server for testing (would need actual implementation)."""
        # This would require a real test server
        # For now, skip these tests
        pytest.skip("Mock server not implemented")

    def test_connection_establishment_performance(self, mock_server):
        """Benchmark SSH connection establishment."""
        times = []

        for _ in range(10):
            start_time = time.perf_counter()

            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())

            try:
                client.connect(
                    hostname="localhost",
                    port=mock_server.port,
                    username="testuser",
                    password="testpass",
                    timeout=5.0,
                )

                connect_time = time.perf_counter() - start_time
                times.append(connect_time)

            finally:
                client.close()

        result = BenchmarkResult("connection_establishment", times)
        print(f"\n{result}")

        # Should connect reasonably quickly
        assert result.mean < 2.0
        assert result.max_time < 5.0

    def test_command_execution_performance(self, mock_server):
        """Benchmark command execution."""
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())

        try:
            client.connect(
                hostname="localhost",
                port=mock_server.port,
                username="testuser",
                password="testpass",
                timeout=5.0,
            )

            # Benchmark simple commands
            def exec_echo():
                stdin, stdout, stderr = client.exec_command("echo test")
                return stdout.read()

            result = benchmark_function(exec_echo, iterations=50)
            print(f"\n{result}")

            # Should execute commands quickly
            assert result.mean < 0.1

        finally:
            client.close()

    def test_concurrent_connections_performance(self, mock_server):
        """Benchmark concurrent SSH connections."""

        def create_connection():
            client = SSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())

            try:
                client.connect(
                    hostname="localhost",
                    port=mock_server.port,
                    username="testuser",
                    password="testpass",
                    timeout=5.0,
                )

                # Execute a simple command
                stdin, stdout, stderr = client.exec_command("echo concurrent")
                output = stdout.read()

                return len(output)

            finally:
                client.close()

        # Test concurrent connections
        start_time = time.perf_counter()

        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(create_connection) for _ in range(10)]
            results = [future.result() for future in as_completed(futures)]

        total_time = time.perf_counter() - start_time

        print(
            f"\nConcurrent connections: {len(results)} connections in {total_time:.4f}s"
        )
        print(f"Average time per connection: {total_time / len(results):.4f}s")

        # Should handle concurrent connections efficiently
        assert total_time < 10.0  # All connections should complete within 10s
        assert len(results) == 10  # All connections should succeed


class TestMemoryBenchmarks:
    """Benchmark memory usage and garbage collection."""

    def test_memory_usage_per_connection(self):
        """Test memory usage per SSH connection."""
        import os

        import psutil

        process = psutil.Process(os.getpid())

        # Measure baseline memory
        gc.collect()
        baseline_memory = process.memory_info().rss

        # Create multiple clients (without connecting)
        clients = []
        for _ in range(100):
            client = SSHClient()
            clients.append(client)

        # Measure memory after creating clients
        after_creation = process.memory_info().rss
        memory_per_client = (after_creation - baseline_memory) / len(clients)

        print(f"\nMemory per SSHClient object: {memory_per_client / 1024:.2f} KB")

        # Clean up
        del clients
        gc.collect()

        # Measure memory after cleanup
        after_cleanup = process.memory_info().rss

        print(f"Memory baseline: {baseline_memory / 1024 / 1024:.2f} MB")
        print(f"Memory after creation: {after_creation / 1024 / 1024:.2f} MB")
        print(f"Memory after cleanup: {after_cleanup / 1024 / 1024:.2f} MB")

        # Memory should be reasonable
        assert memory_per_client < 50 * 1024  # Less than 50KB per client

        # Memory should be mostly reclaimed after cleanup
        memory_leak = after_cleanup - baseline_memory
        assert memory_leak < 1024 * 1024  # Less than 1MB leak

    def test_garbage_collection_performance(self):
        """Test garbage collection performance with SSH objects."""

        # Create and destroy many objects
        def create_destroy_cycle():
            objects = []

            # Create objects
            for _ in range(100):
                client = SSHClient()
                key = Ed25519Key.generate()
                objects.extend([client, key])

            # Destroy objects
            del objects

        # Benchmark garbage collection
        result = benchmark_function(create_destroy_cycle, iterations=10)
        print(f"\nGarbage collection cycle: {result}")

        # Should not take too long
        assert result.mean < 1.0


class TestScalabilityBenchmarks:
    """Test scalability characteristics."""

    def test_channel_scalability(self):
        """Test performance with many channels."""
        # This would require a connected client
        # For now, just test object creation

        from spindle.transport.channel import Channel

        def create_channels():
            channels = []
            for _ in range(100):
                # Create mock channel (would need transport in real scenario)
                channel = Channel(None, 0)  # Mock parameters
                channels.append(channel)
            return len(channels)

        result = benchmark_function(create_channels, iterations=10)
        print(f"\nChannel creation (100 channels): {result}")

        # Should be able to create channels quickly
        assert result.mean < 0.1

    def test_message_processing_scalability(self):
        """Test message processing performance."""
        from spindle.protocol.messages import Message

        def process_messages():
            messages = []
            for i in range(1000):
                msg = Message()
                msg.add_byte(1)
                msg.add_int(i)
                msg.add_string(f"message_{i}")

                # Serialize and deserialize
                data = msg.get_bytes()
                new_msg = Message(data)

                # Read back data
                msg_type = new_msg.get_byte()
                msg_id = new_msg.get_int()
                msg_text = new_msg.get_string()

                messages.append((msg_type, msg_id, msg_text))

            return len(messages)

        result = benchmark_function(process_messages, iterations=10)
        print(f"\nMessage processing (1000 messages): {result}")

        # Should process messages efficiently
        assert result.mean < 1.0


# Async benchmarks (if available)
try:
    from spindle.client.async_ssh_client import AsyncSSHClient

    class TestAsyncBenchmarks:
        """Benchmark async operations."""

        @pytest.mark.asyncio
        async def test_async_connection_performance(self):
            """Benchmark async connection performance."""
            # This would require an async test server
            pytest.skip("Async server not implemented")

        @pytest.mark.asyncio
        async def test_concurrent_async_operations(self):
            """Benchmark concurrent async operations."""

            # Test concurrent key generation
            async def async_keygen():
                return Ed25519Key.generate()

            start_time = time.perf_counter()

            # Run concurrent key generation
            tasks = [async_keygen() for _ in range(10)]
            keys = await asyncio.gather(*tasks)

            total_time = time.perf_counter() - start_time

            print(
                f"\nAsync concurrent key generation: {len(keys)} keys in {total_time:.4f}s"
            )

            assert len(keys) == 10
            assert total_time < 2.0  # Should be reasonably fast

except ImportError:
    # Async support not available
    pass


# Performance test configuration
def pytest_configure(config):
    """Configure pytest for performance tests."""
    config.addinivalue_line(
        "markers", "performance: mark test as a performance benchmark"
    )


# Mark all tests in this module as performance tests
pytestmark = pytest.mark.performance
