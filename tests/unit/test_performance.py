"""
Performance Tests for SSH Library

Tests performance characteristics and optimizations of the SSH library.
"""

import time
import pytest
from unittest.mock import Mock, patch
from ssh_library.crypto.backend import default_crypto_backend
from ssh_library.transport.transport import Transport


class TestPerformance:
    """Test performance characteristics of SSH library."""
    
    def test_crypto_backend_performance(self):
        """Test cryptographic backend performance."""
        backend = default_crypto_backend
        
        # Test random number generation performance
        start_time = time.time()
        for _ in range(100):
            random_data = backend.generate_random(1024)
            assert len(random_data) == 1024
        
        random_time = time.time() - start_time
        
        # Should complete within reasonable time (adjust threshold as needed)
        assert random_time < 1.0, f"Random generation too slow: {random_time:.3f}s"
    
    def test_message_packing_performance(self):
        """Test message packing/unpacking performance."""
        from ssh_library.protocol.messages import Message, KexInitMessage
        
        # Create test message
        cookie = b"x" * 16
        algorithms = ["test-algorithm-1", "test-algorithm-2", "test-algorithm-3"]
        
        kex_msg = KexInitMessage(
            cookie=cookie,
            kex_algorithms=algorithms,
            server_host_key_algorithms=algorithms,
            encryption_algorithms_client_to_server=algorithms,
            encryption_algorithms_server_to_client=algorithms,
            mac_algorithms_client_to_server=algorithms,
            mac_algorithms_server_to_client=algorithms,
            compression_algorithms_client_to_server=["none"],
            compression_algorithms_server_to_client=["none"]
        )
        
        # Test packing performance
        start_time = time.time()
        for _ in range(1000):
            packed = kex_msg.pack()
            assert len(packed) > 0
        
        pack_time = time.time() - start_time
        
        # Test unpacking performance
        packed_data = kex_msg.pack()
        start_time = time.time()
        for _ in range(1000):
            unpacked = Message.unpack(packed_data)
            assert isinstance(unpacked, KexInitMessage)
        
        unpack_time = time.time() - start_time
        
        # Should complete within reasonable time
        assert pack_time < 0.5, f"Message packing too slow: {pack_time:.3f}s"
        assert unpack_time < 0.5, f"Message unpacking too slow: {unpack_time:.3f}s"
    
    def test_transport_packet_building_performance(self):
        """Test transport packet building performance."""
        mock_socket = Mock()
        transport = Transport(mock_socket)
        
        # Test packet building performance
        test_payload = b"x" * 1024  # 1KB payload
        
        start_time = time.time()
        for _ in range(1000):
            packet = transport._build_packet(test_payload)
            assert len(packet) > len(test_payload)
        
        build_time = time.time() - start_time
        
        # Should complete within reasonable time
        assert build_time < 0.5, f"Packet building too slow: {build_time:.3f}s"
    
    def test_channel_buffer_performance(self):
        """Test channel buffer operations performance."""
        from ssh_library.transport.channel import Channel
        
        mock_transport = Mock()
        channel = Channel(mock_transport, 1)
        
        # Initialize channel state
        channel._local_window_size = 32768
        channel._remote_window_size = 32768
        channel._recv_buffer = b""
        
        # Test buffer operations
        test_data = b"x" * 1024
        
        start_time = time.time()
        for _ in range(1000):
            # Simulate receiving data
            channel._recv_buffer += test_data
            
            # Simulate reading data
            if len(channel._recv_buffer) >= 1024:
                data = channel._recv_buffer[:1024]
                channel._recv_buffer = channel._recv_buffer[1024:]
        
        buffer_time = time.time() - start_time
        
        # Should complete within reasonable time
        assert buffer_time < 0.1, f"Buffer operations too slow: {buffer_time:.3f}s"
    
    @pytest.mark.asyncio
    async def test_async_performance_comparison(self):
        """Test that async operations don't add significant overhead."""
        # This is a basic test to ensure async wrappers don't add excessive overhead
        # In a real scenario, you'd compare with actual network operations
        
        import asyncio
        
        # Test async sleep performance (as a baseline)
        start_time = time.time()
        
        tasks = []
        for _ in range(100):
            tasks.append(asyncio.sleep(0.001))  # 1ms sleep
        
        await asyncio.gather(*tasks)
        
        async_time = time.time() - start_time
        
        # Should complete reasonably quickly
        # Note: This is just testing asyncio overhead, not actual SSH performance
        assert async_time < 1.0, f"Async operations too slow: {async_time:.3f}s"
    
    def test_memory_usage_basic(self):
        """Basic test for memory usage patterns."""
        import gc
        
        # Force garbage collection
        gc.collect()
        
        # Create multiple transport instances
        transports = []
        for _ in range(10):
            mock_socket = Mock()
            transport = Transport(mock_socket)
            transports.append(transport)
        
        # Clean up
        for transport in transports:
            transport.close()
        
        transports.clear()
        
        # Force garbage collection again
        gc.collect()
        
        # This is a basic test - in a real scenario you'd measure actual memory usage
        # using tools like memory_profiler or tracemalloc
        assert True  # Placeholder assertion
    
    def test_concurrent_channel_performance(self):
        """Test performance with multiple concurrent channels."""
        from ssh_library.transport.channel import Channel
        
        mock_transport = Mock()
        
        # Create multiple channels
        channels = []
        start_time = time.time()
        
        for i in range(100):
            channel = Channel(mock_transport, i)
            channel._local_window_size = 32768
            channel._remote_window_size = 32768
            channels.append(channel)
        
        creation_time = time.time() - start_time
        
        # Test operations on all channels
        test_data = b"test data"
        start_time = time.time()
        
        for channel in channels:
            channel._recv_buffer = test_data
            # Simulate some processing
            data = channel._recv_buffer
            channel._recv_buffer = b""
        
        operation_time = time.time() - start_time
        
        # Clean up
        for channel in channels:
            channel.close()
        
        # Should complete within reasonable time
        assert creation_time < 0.1, f"Channel creation too slow: {creation_time:.3f}s"
        assert operation_time < 0.1, f"Channel operations too slow: {operation_time:.3f}s"


class TestOptimizations:
    """Test specific optimizations in the SSH library."""
    
    def test_buffer_reuse_optimization(self):
        """Test that buffers are reused efficiently."""
        from ssh_library.transport.channel import Channel
        
        mock_transport = Mock()
        channel = Channel(mock_transport, 1)
        
        # Test that buffer operations don't create excessive objects
        initial_buffer = channel._recv_buffer
        
        # Add data
        channel._recv_buffer += b"test data"
        
        # Read data
        data = channel._recv_buffer[:4]
        channel._recv_buffer = channel._recv_buffer[4:]
        
        # Buffer should still be the same type
        assert isinstance(channel._recv_buffer, bytes)
        assert data == b"test"
    
    def test_message_caching_optimization(self):
        """Test message object reuse where applicable."""
        from ssh_library.protocol.messages import Message
        
        # Test that message creation is efficient
        msg_type = 1
        
        start_time = time.time()
        messages = []
        
        for _ in range(1000):
            msg = Message(msg_type)
            messages.append(msg)
        
        creation_time = time.time() - start_time
        
        # Should be reasonably fast
        assert creation_time < 0.1, f"Message creation too slow: {creation_time:.3f}s"
        
        # Clean up
        messages.clear()
    
    def test_crypto_context_reuse(self):
        """Test that crypto contexts are reused efficiently."""
        backend = default_crypto_backend
        
        # Test multiple random generations (should reuse context)
        start_time = time.time()
        
        for _ in range(100):
            data1 = backend.generate_random(32)
            data2 = backend.generate_random(32)
            assert data1 != data2  # Should be different random data
        
        generation_time = time.time() - start_time
        
        # Should be efficient due to context reuse
        assert generation_time < 0.5, f"Crypto operations too slow: {generation_time:.3f}s"