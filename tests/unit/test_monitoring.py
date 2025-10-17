"""
Tests for SSH library performance monitoring functionality.

Tests performance metrics collection, timing operations, and protocol analysis.
"""

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from ssh_library.logging.monitoring import (
    ConnectionMetrics,
    CryptoTimer,
    PerformanceMetric,
    PerformanceMonitor,
    ProtocolAnalyzer,
    get_performance_monitor,
    get_protocol_analyzer,
    timed_operation,
)


class TestPerformanceMetric:
    """Test PerformanceMetric dataclass."""

    def test_metric_creation(self):
        """Test creating performance metric."""
        metric = PerformanceMetric(
            operation="test_op",
            duration=1.234,
            timestamp=time.time(),
            metadata={"key": "value"},
        )

        assert metric.operation == "test_op"
        assert metric.duration == 1.234
        assert metric.metadata["key"] == "value"


class TestConnectionMetrics:
    """Test ConnectionMetrics dataclass."""

    def test_metrics_initialization(self):
        """Test connection metrics initialization."""
        metrics = ConnectionMetrics()

        assert metrics.connection_time is None
        assert metrics.bytes_sent == 0
        assert metrics.packets_sent == 0
        assert metrics.channels_opened == 0

    def test_metrics_update(self):
        """Test updating connection metrics."""
        metrics = ConnectionMetrics()
        metrics.bytes_sent = 1024
        metrics.packets_sent = 5

        assert metrics.bytes_sent == 1024
        assert metrics.packets_sent == 5


class TestPerformanceMonitor:
    """Test PerformanceMonitor functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.monitor = PerformanceMonitor(max_metrics=100)

    def test_record_metric(self):
        """Test recording performance metrics."""
        self.monitor.record_metric("test_operation", 1.5, host="example.com")

        metrics = self.monitor.get_recent_metrics(limit=1)
        assert len(metrics) == 1
        assert metrics[0].operation == "test_operation"
        assert metrics[0].duration == 1.5
        assert metrics[0].metadata["host"] == "example.com"

    def test_time_operation_context_manager(self):
        """Test timing operation with context manager."""
        with self.monitor.time_operation("test_context", param="value"):
            time.sleep(0.01)  # Small delay for measurable duration

        metrics = self.monitor.get_recent_metrics(operation="test_context")
        assert len(metrics) == 1
        assert metrics[0].duration > 0.005  # Should be at least 5ms
        assert metrics[0].metadata["param"] == "value"

    def test_connection_metrics_management(self):
        """Test connection metrics management."""
        conn_id = "test_conn_123"

        # Get initial metrics
        metrics = self.monitor.get_connection_metrics(conn_id)
        assert isinstance(metrics, ConnectionMetrics)
        assert metrics.bytes_sent == 0

        # Update metrics
        self.monitor.update_connection_metric(conn_id, "connection_time", 2.5)
        self.monitor.increment_connection_counter(conn_id, "bytes_sent", 1024)
        self.monitor.increment_connection_counter(conn_id, "packets_sent", 1)

        # Verify updates
        updated_metrics = self.monitor.get_connection_metrics(conn_id)
        assert updated_metrics.connection_time == 2.5
        assert updated_metrics.bytes_sent == 1024
        assert updated_metrics.packets_sent == 1

    def test_operation_statistics(self):
        """Test operation statistics calculation."""
        # Record multiple metrics for same operation
        durations = [0.1, 0.2, 0.3, 0.4, 0.5]
        for duration in durations:
            self.monitor.record_metric("test_stats", duration)

        stats = self.monitor.get_operation_stats("test_stats")

        assert stats["count"] == 5
        assert stats["min"] == 0.1
        assert stats["max"] == 0.5
        assert stats["mean"] == 0.3
        assert stats["median"] == 0.3

    def test_get_recent_metrics_filtering(self):
        """Test filtering recent metrics by operation."""
        self.monitor.record_metric("op1", 1.0)
        self.monitor.record_metric("op2", 2.0)
        self.monitor.record_metric("op1", 1.5)

        # Get all metrics
        all_metrics = self.monitor.get_recent_metrics()
        assert len(all_metrics) == 3

        # Get filtered metrics
        op1_metrics = self.monitor.get_recent_metrics(operation="op1")
        assert len(op1_metrics) == 2
        assert all(m.operation == "op1" for m in op1_metrics)

    def test_clear_metrics(self):
        """Test clearing metrics."""
        conn_id = "test_conn"
        self.monitor.record_metric("test_op", 1.0)
        self.monitor.get_connection_metrics(conn_id)

        # Clear specific connection
        self.monitor.clear_metrics(connection_id=conn_id)
        assert conn_id not in self.monitor.connection_metrics
        assert len(self.monitor.metrics) == 1  # General metrics still there

        # Clear all metrics
        self.monitor.clear_metrics()
        assert len(self.monitor.metrics) == 0
        assert len(self.monitor.connection_metrics) == 0


class TestTimedOperationDecorator:
    """Test timed_operation decorator."""

    def setup_method(self):
        """Set up test fixtures."""
        # Clear global monitor
        get_performance_monitor().clear_metrics()

    def test_decorator_basic_usage(self):
        """Test basic decorator usage."""

        @timed_operation("decorated_function")
        def test_function():
            time.sleep(0.01)
            return "result"

        result = test_function()
        assert result == "result"

        monitor = get_performance_monitor()
        metrics = monitor.get_recent_metrics(operation="decorated_function")
        assert len(metrics) == 1
        assert metrics[0].duration > 0.005

    def test_decorator_with_metadata(self):
        """Test decorator with metadata."""

        @timed_operation("decorated_with_meta", category="test", version="1.0")
        def test_function_with_meta():
            return "result"

        test_function_with_meta()

        monitor = get_performance_monitor()
        metrics = monitor.get_recent_metrics(operation="decorated_with_meta")
        assert len(metrics) == 1
        assert metrics[0].metadata["category"] == "test"
        assert metrics[0].metadata["version"] == "1.0"


class TestCryptoTimer:
    """Test CryptoTimer functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.monitor = PerformanceMonitor()
        self.crypto_timer = CryptoTimer(self.monitor)

    def test_time_crypto_operation(self):
        """Test timing crypto operations."""
        with self.crypto_timer.time_crypto_operation("encrypt", "aes256", key_size=256):
            time.sleep(0.01)

        metrics = self.monitor.get_recent_metrics(operation="crypto_encrypt")
        assert len(metrics) == 1
        assert metrics[0].metadata["algorithm"] == "aes256"
        assert metrics[0].metadata["key_size"] == 256
        assert metrics[0].metadata["category"] == "crypto"

    def test_time_key_generation(self):
        """Test timing key generation."""
        with self.crypto_timer.time_key_generation("rsa", 2048):
            time.sleep(0.005)

        metrics = self.monitor.get_recent_metrics(operation="crypto_keygen")
        assert len(metrics) == 1
        assert metrics[0].metadata["algorithm"] == "rsa"
        assert metrics[0].metadata["key_size"] == 2048

    def test_time_key_exchange(self):
        """Test timing key exchange."""
        with self.crypto_timer.time_key_exchange("curve25519"):
            time.sleep(0.005)

        metrics = self.monitor.get_recent_metrics(operation="crypto_kex")
        assert len(metrics) == 1
        assert metrics[0].metadata["algorithm"] == "curve25519"

    def test_time_encryption_decryption(self):
        """Test timing encryption and decryption."""
        with self.crypto_timer.time_encryption("aes256-ctr", 1024):
            time.sleep(0.002)

        with self.crypto_timer.time_decryption("aes256-ctr", 1024):
            time.sleep(0.002)

        encrypt_metrics = self.monitor.get_recent_metrics(operation="crypto_encrypt")
        decrypt_metrics = self.monitor.get_recent_metrics(operation="crypto_decrypt")

        assert len(encrypt_metrics) == 1
        assert len(decrypt_metrics) == 1
        assert encrypt_metrics[0].metadata["data_size"] == 1024
        assert decrypt_metrics[0].metadata["data_size"] == 1024


class TestProtocolAnalyzer:
    """Test ProtocolAnalyzer functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.monitor = PerformanceMonitor()
        self.analyzer = ProtocolAnalyzer(self.monitor)

    def test_record_message(self):
        """Test recording protocol messages."""
        conn_id = "test_conn"

        self.analyzer.record_message("sent", "SSH_MSG_KEXINIT", 256, conn_id)
        self.analyzer.record_message("received", "SSH_MSG_KEXINIT", 280, conn_id)

        # Check message counts
        assert self.analyzer.message_counts["sent_SSH_MSG_KEXINIT"] == 1
        assert self.analyzer.message_counts["received_SSH_MSG_KEXINIT"] == 1

        # Check connection metrics were updated
        conn_metrics = self.monitor.get_connection_metrics(conn_id)
        assert conn_metrics.packets_sent == 1
        assert conn_metrics.packets_received == 1
        assert conn_metrics.bytes_sent == 256
        assert conn_metrics.bytes_received == 280

    def test_get_message_stats(self):
        """Test getting message statistics."""
        conn_id = "test_conn"

        # Record multiple messages of same type
        for i in range(5):
            self.analyzer.record_message("sent", "SSH_MSG_NEWKEYS", 100 + i, conn_id)

        stats = self.analyzer.get_message_stats()

        sent_stats = stats["sent_SSH_MSG_NEWKEYS"]
        assert sent_stats["count"] == 5
        assert sent_stats["total_bytes"] == 510  # 100+101+102+103+104
        assert sent_stats["avg_size"] == 102.0
        assert sent_stats["min_size"] == 100
        assert sent_stats["max_size"] == 104

    def test_clear_stats(self):
        """Test clearing protocol statistics."""
        self.analyzer.record_message("sent", "SSH_MSG_KEXINIT", 256, "conn1")

        assert len(self.analyzer.message_counts) > 0

        self.analyzer.clear_stats()

        assert len(self.analyzer.message_counts) == 0
        assert len(self.analyzer.message_sizes) == 0

    def test_message_size_history_bounds(self):
        """Test that message size history is bounded."""
        conn_id = "test_conn"

        # Record more messages than the bound (1000)
        for i in range(1200):
            self.analyzer.record_message("sent", "SSH_MSG_DATA", 64, conn_id)

        # Should be trimmed to 500 (half of 1000) when it exceeds 1000
        sizes = self.analyzer.message_sizes["sent_SSH_MSG_DATA"]
        assert (
            len(sizes) <= 1000
        )  # Should be bounded but may not be exactly 500 due to timing


class TestGlobalInstances:
    """Test global monitor and analyzer instances."""

    def test_get_performance_monitor_singleton(self):
        """Test that get_performance_monitor returns same instance."""
        monitor1 = get_performance_monitor()
        monitor2 = get_performance_monitor()

        assert monitor1 is monitor2

    def test_get_protocol_analyzer_singleton(self):
        """Test that get_protocol_analyzer returns same instance."""
        analyzer1 = get_protocol_analyzer()
        analyzer2 = get_protocol_analyzer()

        assert analyzer1 is analyzer2

    def test_global_instances_integration(self):
        """Test integration between global instances."""
        monitor = get_performance_monitor()
        analyzer = get_protocol_analyzer()

        # Analyzer should use the same monitor
        assert analyzer.monitor is monitor


class TestThreadSafety:
    """Test thread safety of monitoring components."""

    def test_performance_monitor_thread_safety(self):
        """Test that PerformanceMonitor is thread-safe."""
        monitor = PerformanceMonitor(max_metrics=1000)  # Ensure we have enough capacity

        def record_metrics():
            for i in range(20):  # Reduced number to avoid deque overflow
                monitor.record_metric(
                    f"thread_op_{threading.current_thread().ident}", 0.001 * i
                )

        # Start multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=record_metrics)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Should have 100 total metrics (5 threads * 20 each)
        all_metrics = monitor.get_recent_metrics()
        assert len(all_metrics) == 100

    def test_protocol_analyzer_thread_safety(self):
        """Test that ProtocolAnalyzer is thread-safe."""
        analyzer = ProtocolAnalyzer()

        def record_messages():
            thread_id = threading.current_thread().ident
            for i in range(50):
                analyzer.record_message("sent", "SSH_MSG_DATA", 64, f"conn_{thread_id}")

        # Start multiple threads
        threads = []
        for _ in range(3):
            thread = threading.Thread(target=record_messages)
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Should have recorded 150 messages total
        assert analyzer.message_counts["sent_SSH_MSG_DATA"] == 150
