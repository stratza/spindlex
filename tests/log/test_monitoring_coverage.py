"""
Coverage tests for spindlex/logging/monitoring.py.

Covers the missed lines:
- PerformanceMonitor.record_metric with >1000 stats (line 82)
- PerformanceMonitor.print_summary with data (lines 222-263)
- PerformanceMonitor.clear_metrics with connection_id (line 214)
- CryptoTimer all time_* methods (lines 328, 337, 341, 349, 353, 357)
- ProtocolAnalyzer.record_message (lines 395, 435)
- ProtocolAnalyzer.get_message_stats (line 452)
"""

from __future__ import annotations

from spindlex.logging.monitoring import (
    CryptoTimer,
    PerformanceMonitor,
    ProtocolAnalyzer,
    get_performance_monitor,
    get_protocol_analyzer,
    timed_operation,
)

# ---------------------------------------------------------------------------
# PerformanceMonitor
# ---------------------------------------------------------------------------


class TestPerformanceMonitorRecordMetric:
    def test_record_metric_trims_stats_over_1000(self):
        """When operation_stats exceeds 1000 entries, it is trimmed to 500."""
        monitor = PerformanceMonitor()
        # Add 1001 entries to trigger the trim path (line 82)
        for i in range(1001):
            monitor.operation_stats["op1"].append(float(i))
        # Call record_metric again to trigger the trim
        monitor.record_metric("op1", 0.001)
        assert len(monitor.operation_stats["op1"]) <= 501


class TestPerformanceMonitorClearMetrics:
    def test_clear_metrics_specific_connection(self):
        monitor = PerformanceMonitor()
        monitor.connection_metrics["conn1"] = monitor.get_connection_metrics("conn1")
        monitor.connection_metrics["conn2"] = monitor.get_connection_metrics("conn2")
        monitor.clear_metrics(connection_id="conn1")
        assert "conn1" not in monitor.connection_metrics
        assert "conn2" in monitor.connection_metrics

    def test_clear_metrics_all(self):
        monitor = PerformanceMonitor()
        monitor.record_metric("op", 0.1)
        monitor.clear_metrics()
        assert len(monitor.metrics) == 0
        assert len(monitor.operation_stats) == 0


class TestPerformanceMonitorPrintSummary:
    def test_print_summary_no_data(self, capsys):
        monitor = PerformanceMonitor()
        monitor.print_summary()
        captured = capsys.readouterr()
        assert "No metrics recorded yet" in captured.out

    def test_print_summary_with_operation_stats(self, capsys):
        monitor = PerformanceMonitor()
        for i in range(5):
            monitor.record_metric("test_op", 0.01 * i)
        monitor.print_summary()
        captured = capsys.readouterr()
        assert "test_op" in captured.out
        assert "Operation Statistics" in captured.out

    def test_print_summary_with_connection_metrics(self, capsys):
        monitor = PerformanceMonitor()
        # Add connection metrics without operation stats
        cm = monitor.get_connection_metrics("conn-abc")
        cm.packets_sent = 10
        cm.packets_received = 20
        cm.errors = 0
        monitor.print_summary()
        captured = capsys.readouterr()
        assert "Connection Statistics" in captured.out

    def test_print_summary_with_both(self, capsys):
        monitor = PerformanceMonitor()
        monitor.record_metric("kex", 0.05)
        monitor.get_connection_metrics("conn-xyz")
        monitor.print_summary()
        captured = capsys.readouterr()
        assert "SpindleX Performance Summary" in captured.out

    def test_print_summary_p95_path_over_20(self, capsys):
        """Test p95 calculation when count > 20."""
        monitor = PerformanceMonitor()
        for i in range(25):
            monitor.operation_stats["heavy_op"].append(float(i))
        monitor.print_summary()
        captured = capsys.readouterr()
        assert "heavy_op" in captured.out


class TestGetOperationStatsEdgeCases:
    def test_empty_stats_returns_empty_dict(self):
        monitor = PerformanceMonitor()
        result = monitor.get_operation_stats("nonexistent")
        assert result == {}

    def test_p99_path_over_100_entries(self):
        """Exercises p99 branch in get_operation_stats (count > 100)."""
        monitor = PerformanceMonitor()
        for i in range(110):
            monitor.operation_stats["bulk"].append(float(i))
        stats = monitor.get_operation_stats("bulk")
        assert "p99" in stats
        assert stats["count"] == 110


# ---------------------------------------------------------------------------
# CryptoTimer
# ---------------------------------------------------------------------------


class TestCryptoTimer:
    def test_time_crypto_operation_without_key_size(self):
        monitor = PerformanceMonitor()
        timer = CryptoTimer(monitor)
        with timer.time_crypto_operation("sign", "ed25519"):
            pass
        stats = monitor.get_operation_stats("crypto_sign")
        assert stats["count"] == 1

    def test_time_crypto_operation_with_key_size(self):
        monitor = PerformanceMonitor()
        timer = CryptoTimer(monitor)
        with timer.time_crypto_operation("sign", "rsa", key_size=2048):
            pass
        stats = monitor.get_operation_stats("crypto_sign")
        assert stats["count"] == 1

    def test_time_key_generation(self):
        monitor = PerformanceMonitor()
        timer = CryptoTimer(monitor)
        with timer.time_key_generation("ed25519", 256):
            pass
        stats = monitor.get_operation_stats("crypto_keygen")
        assert stats["count"] == 1

    def test_time_key_exchange(self):
        monitor = PerformanceMonitor()
        timer = CryptoTimer(monitor)
        with timer.time_key_exchange("curve25519"):
            pass
        stats = monitor.get_operation_stats("crypto_kex")
        assert stats["count"] == 1

    def test_time_encryption(self):
        monitor = PerformanceMonitor()
        timer = CryptoTimer(monitor)
        with timer.time_encryption("aes256-ctr", 1024):
            pass
        stats = monitor.get_operation_stats("crypto_encrypt")
        assert stats["count"] == 1

    def test_time_decryption(self):
        monitor = PerformanceMonitor()
        timer = CryptoTimer(monitor)
        with timer.time_decryption("aes256-ctr", 1024):
            pass
        stats = monitor.get_operation_stats("crypto_decrypt")
        assert stats["count"] == 1

    def test_time_signature(self):
        monitor = PerformanceMonitor()
        timer = CryptoTimer(monitor)
        with timer.time_signature("ed25519", 256):
            pass
        stats = monitor.get_operation_stats("crypto_sign")
        assert stats["count"] == 1

    def test_time_verification(self):
        monitor = PerformanceMonitor()
        timer = CryptoTimer(monitor)
        with timer.time_verification("ed25519", 256):
            pass
        stats = monitor.get_operation_stats("crypto_verify")
        assert stats["count"] == 1

    def test_default_global_monitor_used_when_none(self):
        timer = CryptoTimer()
        # Should use the global monitor without error
        assert timer.monitor is get_performance_monitor()


# ---------------------------------------------------------------------------
# ProtocolAnalyzer
# ---------------------------------------------------------------------------


class TestProtocolAnalyzer:
    def test_record_message_sent(self):
        monitor = PerformanceMonitor()
        analyzer = ProtocolAnalyzer(monitor)
        analyzer.record_message("sent", "KEXINIT", 100, "conn1")
        assert monitor.get_connection_metrics("conn1").packets_sent == 1
        assert monitor.get_connection_metrics("conn1").bytes_sent == 100

    def test_record_message_received(self):
        monitor = PerformanceMonitor()
        analyzer = ProtocolAnalyzer(monitor)
        analyzer.record_message("received", "KEXINIT", 200, "conn1")
        assert monitor.get_connection_metrics("conn1").packets_received == 1
        assert monitor.get_connection_metrics("conn1").bytes_received == 200

    def test_record_message_trims_sizes(self):
        """When message_sizes[key] > 1000, it is trimmed."""
        monitor = PerformanceMonitor()
        analyzer = ProtocolAnalyzer(monitor)
        key = "sent_KEXINIT"
        for _ in range(1001):
            analyzer.message_sizes[key].append(100)
        # One more to trigger trim
        analyzer.record_message("sent", "KEXINIT", 100, "conn1")
        assert len(analyzer.message_sizes[key]) <= 501

    def test_get_message_stats_with_data(self):
        monitor = PerformanceMonitor()
        analyzer = ProtocolAnalyzer(monitor)
        analyzer.record_message("sent", "NEWKEYS", 50, "conn2")
        analyzer.record_message("sent", "NEWKEYS", 60, "conn2")
        stats = analyzer.get_message_stats()
        assert "sent_NEWKEYS" in stats
        assert stats["sent_NEWKEYS"]["count"] == 2
        assert stats["sent_NEWKEYS"]["total_bytes"] == 110

    def test_get_message_stats_empty_sizes(self):
        """When sizes list is empty, stats only contains count."""
        monitor = PerformanceMonitor()
        analyzer = ProtocolAnalyzer(monitor)
        # Manually set a count with no sizes
        analyzer.message_counts["sent_KEXDH"] = 3
        stats = analyzer.get_message_stats()
        assert stats["sent_KEXDH"] == {"count": 3}

    def test_clear_stats(self):
        monitor = PerformanceMonitor()
        analyzer = ProtocolAnalyzer(monitor)
        analyzer.record_message("sent", "X", 10, "c")
        analyzer.clear_stats()
        assert len(analyzer.message_counts) == 0
        assert len(analyzer.message_sizes) == 0

    def test_get_protocol_analyzer_returns_global(self):
        analyzer = get_protocol_analyzer()
        assert isinstance(analyzer, ProtocolAnalyzer)


# ---------------------------------------------------------------------------
# timed_operation decorator
# ---------------------------------------------------------------------------


class TestTimedOperationDecorator:
    def test_decorator_records_metric(self):
        """The timed_operation decorator should record a performance metric."""
        monitor = get_performance_monitor()

        @timed_operation("test_decorated_func")
        def my_func():
            return 42

        result = my_func()
        assert result == 42
        # At least one new metric should have been recorded
        metrics = [m for m in monitor.metrics if m.operation == "test_decorated_func"]
        assert len(metrics) >= 1
