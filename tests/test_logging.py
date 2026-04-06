
import json
import logging
import time
import pytest
from spindlex.logging.formatters import SSHFormatter, JSONFormatter, SecurityFormatter, DebugFormatter
from spindlex.logging.sanitizer import LogSanitizer
from spindlex.logging.handlers import SecurityHandler, PerformanceHandler
from spindlex.logging.logger import get_logger, configure_logging

from spindlex.logging.monitoring import (
    PerformanceMonitor, PerformanceMetric, ConnectionMetrics,
    get_performance_monitor, timed_operation, CryptoTimer,
    ProtocolAnalyzer, get_protocol_analyzer
)

def test_performance_monitor():
    monitor = PerformanceMonitor(max_metrics=10)
    
    # Test recording metrics
    monitor.record_metric("test_op", 0.5, meta="data")
    metrics = monitor.get_recent_metrics("test_op")
    assert len(metrics) == 1
    assert metrics[0].operation == "test_op"
    assert metrics[0].duration == 0.5
    assert metrics[0].metadata == {"meta": "data"}
    
    # Test statistics
    for i in range(5):
        monitor.record_metric("stat_op", float(i))
    
    stats = monitor.get_operation_stats("stat_op")
    assert stats["count"] == 5
    assert stats["min"] == 0.0
    assert stats["max"] == 4.0
    assert stats["mean"] == 2.0
    
    # Test connection metrics
    conn_id = "conn1"
    monitor.update_connection_metric(conn_id, "bytes_sent", 100)
    monitor.increment_connection_counter(conn_id, "packets_sent", 2)
    
    conn_metrics = monitor.get_connection_metrics(conn_id)
    assert conn_metrics.bytes_sent == 100
    assert conn_metrics.packets_sent == 2
    
    # Test clear
    monitor.clear_metrics()
    assert len(monitor.get_recent_metrics()) == 0
    assert monitor.get_operation_stats("stat_op") == {}

def test_timed_operation_decorator():
    monitor = get_performance_monitor()
    monitor.clear_metrics()
    
    @timed_operation("decorated_op")
    def sample_func():
        time.sleep(0.01)
        return "done"
        
    result = sample_func()
    assert result == "done"
    
    metrics = monitor.get_recent_metrics("decorated_op")
    assert len(metrics) == 1
    assert metrics[0].duration >= 0.01

def test_crypto_timer():
    monitor = PerformanceMonitor()
    timer = CryptoTimer(monitor=monitor)
    
    with timer.time_encryption("AES", 1024):
        time.sleep(0.01)
        
    metrics = monitor.get_recent_metrics("crypto_encrypt")
    assert len(metrics) == 1
    assert metrics[0].metadata["algorithm"] == "AES"
    assert metrics[0].metadata["data_size"] == 1024

def test_protocol_analyzer():
    monitor = PerformanceMonitor()
    analyzer = ProtocolAnalyzer(monitor=monitor)
    
    analyzer.record_message("sent", "KEXINIT", 128, "conn1")
    analyzer.record_message("received", "NEWKEYS", 64, "conn1")
    
    stats = analyzer.get_message_stats()
    assert stats["sent_KEXINIT"]["count"] == 1
    assert stats["sent_KEXINIT"]["total_bytes"] == 128
    assert stats["received_NEWKEYS"]["count"] == 1
    
    conn_metrics = monitor.get_connection_metrics("conn1")
    assert conn_metrics.packets_sent == 1
    assert conn_metrics.bytes_sent == 128
    assert conn_metrics.packets_received == 1
    assert conn_metrics.bytes_received == 64
    
    analyzer.clear_stats()
    assert analyzer.get_message_stats() == {}

def test_log_sanitizer_message():
    sanitizer = LogSanitizer()
    
    # Test password redaction
    assert "password=[PASSWORD_REDACTED]" in sanitizer.sanitize_message("password=secret123")
    assert "password: [PASSWORD_REDACTED]" in sanitizer.sanitize_message("password: secret123")
    
    # Test IP redaction
    assert "192.168.1.***" == sanitizer.sanitize_message("192.168.1.100")
    
    # Test SSH key redaction
    long_key = "AAAA" + "B" * 50
    assert "[SSH_KEY_REDACTED]" == sanitizer.sanitize_message(long_key)
    
    # Test private key redaction
    priv_key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
    assert "[PRIVATE_KEY_REDACTED]" == sanitizer.sanitize_message(priv_key)

def test_log_sanitizer_dict():
    data = {
        "user": "alice",
        "password": "secretpassword",
        "nested": {
            "key": "private-key-data",
            "info": "connected to 10.0.0.1"
        },
        "list": ["plain", "password=hidden"]
    }
    
    sanitized = LogSanitizer.sanitize_dict(data)
    
    assert sanitized["user"] == "alice"
    assert sanitized["password"] == "[REDACTED]"
    assert sanitized["nested"]["key"] == "[REDACTED]"
    assert "10.0.0.***" in sanitized["nested"]["info"]
    assert sanitized["list"][0] == "plain"
    assert "password=[PASSWORD_REDACTED]" in sanitized["list"][1]

def test_ssh_formatter():
    formatter = SSHFormatter(sanitize=True)
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Connecting with password=secret",
        args=(),
        exc_info=None
    )
    
    formatted = formatter.format(record)
    assert "INFO" in formatted
    assert "password=[PASSWORD_REDACTED]" in formatted
    assert "secret" not in formatted

def test_json_formatter():
    formatter = JSONFormatter(sanitize=True)
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Login attempt for %s",
        args=("alice",),
        exc_info=None
    )
    record.custom_field = "custom_value"
    
    formatted = formatter.format(record)
    data = json.loads(formatted)
    
    assert data["logger"] == "test"
    assert data["level"] == "INFO"
    assert data["message"] == "Login attempt for alice"
    assert data["extra"]["custom_field"] == "custom_value"

def test_security_formatter():
    formatter = SecurityFormatter(sanitize=True)
    record = logging.LogRecord(
        name="security",
        level=logging.WARNING,
        pathname="auth.py",
        lineno=20,
        msg="Failed login",
        args=(),
        exc_info=None
    )
    # Test without client_ip (should default to unknown)
    formatted = formatter.format(record)
    assert "[unknown]" in formatted
    
    # Test with client_ip
    record.client_ip = "1.2.3.4"
    formatted = formatter.format(record)
    assert "[1.2.3.***]" in formatted

def test_debug_formatter():
    formatter = DebugFormatter(sanitize=False)
    record = logging.LogRecord(
        name="debug",
        level=logging.DEBUG,
        pathname="protocol.py",
        lineno=50,
        msg="Raw packet: %s",
        args=("data",),
        exc_info=None
    )
    record.funcName = "process_packet"
    
    formatted = formatter.format(record)
    assert "DEBUG" in formatted
    assert "protocol.py:50" in formatted
    assert "process_packet()" in formatted
    assert "Raw packet: data" in formatted

def test_security_handler(tmp_path):
    log_file = tmp_path / "security.log"
    handler = SecurityHandler(filename=str(log_file))
    
    record = logging.LogRecord(
        name="test_security",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Security event",
        args=(),
        exc_info=None
    )
    record.client_ip = "127.0.0.1"
    
    handler.emit(record)
    handler.close()
    
    assert log_file.exists()
    content = log_file.read_text()
    assert "Security event" in content
    assert "127.0.0.***" in content

def test_performance_handler(tmp_path):
    log_file = tmp_path / "perf.json"
    handler = PerformanceHandler(filename=str(log_file), json_format=True)
    
    record = logging.LogRecord(
        name="test_perf",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Perf metric",
        args=(),
        exc_info=None
    )
    
    handler.emit(record)
    handler.close()
    
    assert log_file.exists()
    content = log_file.read_text()
    data = json.loads(content)
    assert data["message"] == "Perf metric"

def test_configure_logging(tmp_path):
    out_file = tmp_path / "main.log"
    configure_logging(level="DEBUG", output_file=str(out_file))
    logger = get_logger("spindlex.test")
    
    logger.info("Test message with password=secret")
    
    assert out_file.exists()
    content = out_file.read_text()
    assert "Test message" in content
    assert "password=[PASSWORD_REDACTED]" in content
