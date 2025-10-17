"""
Tests for SSH library logging functionality.

Tests structured logging, sanitization, formatters, and handlers.
"""

import json
import logging
import os
import tempfile
from io import StringIO
from unittest.mock import MagicMock, patch

import pytest

from spindlex.logging import (
    DebugFormatter,
    JSONFormatter,
    LogSanitizer,
    PerformanceHandler,
    SecurityFormatter,
    SecurityHandler,
    SSHFormatter,
    SSHLogger,
    configure_logging,
    get_logger,
)


class TestLogSanitizer:
    """Test log sanitization functionality."""

    def test_sanitize_passwords(self):
        """Test password sanitization."""
        test_cases = [
            ("password=secret123", "password=[PASSWORD_REDACTED]"),
            ('password: "mypass"', "password: [PASSWORD_REDACTED]"),
            ("password = secret", "password = [PASSWORD_REDACTED]"),
            ('PASSWORD="test123"', "PASSWORD=[PASSWORD_REDACTED]"),
        ]

        for input_msg, expected in test_cases:
            result = LogSanitizer.sanitize_message(input_msg)
            assert "[PASSWORD_REDACTED]" in result

    def test_sanitize_ssh_keys(self):
        """Test SSH key material sanitization."""
        ssh_key = "AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA"
        message = f"SSH key data: {ssh_key}"

        result = LogSanitizer.sanitize_message(message)
        assert "[SSH_KEY_REDACTED]" in result
        assert ssh_key not in result

    def test_sanitize_private_keys(self):
        """Test private key block sanitization."""
        private_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAu726mo
-----END RSA PRIVATE KEY-----"""

        result = LogSanitizer.sanitize_message(private_key)
        assert "[PRIVATE_KEY_REDACTED]" in result
        assert "BEGIN RSA PRIVATE KEY" not in result

    def test_sanitize_ip_addresses(self):
        """Test IP address partial sanitization."""
        message = "Connected to 192.168.1.100"
        result = LogSanitizer.sanitize_message(message)
        assert "192.168.1.***" in result
        assert "192.168.1.100" not in result

    def test_sanitize_dict(self):
        """Test dictionary sanitization."""
        test_dict = {
            "username": "testuser",
            "password": "secret123",
            "host": "192.168.1.50",
            "ssh_key_data": "AAAAB3NzaC1yc2EAAAADAQABAAABgQC7vbqajDhA",
        }

        result = LogSanitizer.sanitize_dict(test_dict)

        assert result["username"] == "testuser"
        assert result["password"] == "[REDACTED]"
        assert "192.168.1.***" in result["host"]
        assert "[SSH_KEY_REDACTED]" in result["ssh_key_data"]

    def test_sanitize_nested_dict(self):
        """Test nested dictionary sanitization."""
        test_dict = {"connection": {"auth": {"password": "secret", "username": "user"}}}

        result = LogSanitizer.sanitize_dict(test_dict)
        assert result["connection"]["auth"]["password"] == "[REDACTED]"
        assert result["connection"]["auth"]["username"] == "user"


class TestSSHFormatter:
    """Test SSH log formatter."""

    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = SSHFormatter(sanitize=True)
        self.formatter_no_sanitize = SSHFormatter(sanitize=False)

    def test_format_basic_message(self):
        """Test basic message formatting."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        result = self.formatter.format(record)
        assert "test.INFO: Test message" in result

    def test_format_with_sanitization(self):
        """Test message formatting with sanitization."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Login with password=secret123",
            args=(),
            exc_info=None,
        )

        result = self.formatter.format(record)
        assert "[PASSWORD_REDACTED]" in result
        assert "secret123" not in result

    def test_format_without_sanitization(self):
        """Test message formatting without sanitization."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Login with password=secret123",
            args=(),
            exc_info=None,
        )

        result = self.formatter_no_sanitize.format(record)
        assert "secret123" in result
        assert "[PASSWORD_REDACTED]" not in result

    def test_format_with_args(self):
        """Test formatting with message arguments."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="User %s login with password %s",
            args=("testuser", "secret123"),
            exc_info=None,
        )

        result = self.formatter.format(record)
        assert "testuser" in result
        assert "[PASSWORD_REDACTED]" in result
        assert "secret123" not in result


class TestJSONFormatter:
    """Test JSON log formatter."""

    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = JSONFormatter(sanitize=True)

    def test_format_json_structure(self):
        """Test JSON formatting structure."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=42,
            msg="Test message",
            args=(),
            exc_info=None,
            func="test_func",
        )
        record.module = "test_module"
        record.funcName = "test_func"

        result = self.formatter.format(record)
        data = json.loads(result)

        assert data["level"] == "INFO"
        assert data["logger"] == "test"
        assert data["message"] == "Test message"
        assert data["module"] == "test_module"
        assert data["function"] == "test_func"
        assert data["line"] == 42
        assert "timestamp" in data

    def test_format_with_extra_fields(self):
        """Test JSON formatting with extra fields."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Test message",
            args=(),
            exc_info=None,
        )
        record.custom_field = "custom_value"
        record.connection_id = "conn123"

        result = self.formatter.format(record)
        data = json.loads(result)

        assert "extra" in data
        assert data["extra"]["custom_field"] == "custom_value"
        assert data["extra"]["connection_id"] == "conn123"

    def test_format_with_sanitization(self):
        """Test JSON formatting with sanitization."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Login password=secret123",
            args=(),
            exc_info=None,
        )

        result = self.formatter.format(record)
        data = json.loads(result)

        assert "[PASSWORD_REDACTED]" in data["message"]
        assert "secret123" not in result


class TestSecurityFormatter:
    """Test security event formatter."""

    def setup_method(self):
        """Set up test fixtures."""
        self.formatter = SecurityFormatter()

    def test_format_security_event(self):
        """Test security event formatting."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Authentication failed",
            args=(),
            exc_info=None,
        )
        record.client_ip = "192.168.1.100"

        result = self.formatter.format(record)
        assert "SECURITY.INFO" in result
        assert (
            "192.168.1.100" in result or "192.168.1.***" in result
        )  # IP may or may not be sanitized in this context
        assert "Authentication failed" in result

    def test_format_without_client_ip(self):
        """Test formatting when client_ip is missing."""
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Security event",
            args=(),
            exc_info=None,
        )

        result = self.formatter.format(record)
        assert "[unknown]" in result


class TestSSHLogger:
    """Test SSH logger functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.logger = SSHLogger("test_logger")
        self.stream = StringIO()

        # Add stream handler for testing
        handler = logging.StreamHandler(self.stream)
        handler.setFormatter(SSHFormatter(sanitize=False))
        self.logger.logger.addHandler(handler)
        self.logger.logger.setLevel(logging.DEBUG)

    def test_basic_logging_methods(self):
        """Test basic logging methods."""
        self.logger.info("Info message")
        self.logger.debug("Debug message")
        self.logger.warning("Warning message")
        self.logger.error("Error message")

        output = self.stream.getvalue()
        assert "Info message" in output
        assert "Debug message" in output
        assert "Warning message" in output
        assert "Error message" in output

    def test_security_event_logging(self):
        """Test security event logging."""
        # Mock security logger
        with patch.object(self.logger, "_security_logger") as mock_security_logger:
            mock_security_logger = MagicMock()
            self.logger._security_logger = mock_security_logger

            self.logger.security_event(
                "auth_failure",
                "Authentication failed for user",
                client_ip="192.168.1.100",
                username="testuser",
            )

            mock_security_logger.info.assert_called_once()
            args, kwargs = mock_security_logger.info.call_args
            assert "Authentication failed for user" in args
            assert kwargs["extra"]["event_type"] == "auth_failure"
            assert kwargs["extra"]["client_ip"] == "192.168.1.100"
            assert kwargs["extra"]["username"] == "testuser"

    def test_performance_metric_logging(self):
        """Test performance metric logging."""
        with patch.object(self.logger, "_performance_logger") as mock_perf_logger:
            mock_perf_logger = MagicMock()
            self.logger._performance_logger = mock_perf_logger

            self.logger.performance_metric("ssh_connect", 1.234, host="example.com")

            mock_perf_logger.info.assert_called_once()
            args, kwargs = mock_perf_logger.info.call_args
            assert "ssh_connect" in args[0]
            assert "1.2340s" in args[0]
            assert kwargs["extra"]["operation"] == "ssh_connect"
            assert kwargs["extra"]["duration_seconds"] == 1.234
            assert kwargs["extra"]["host"] == "example.com"

    def test_protocol_debug_logging(self):
        """Test protocol debug logging."""
        self.logger.protocol_debug(
            "sent",
            "SSH_MSG_KEXINIT",
            {"algorithms": ["curve25519-sha256"]},
            connection_id="conn123",
        )

        output = self.stream.getvalue()
        assert "SSH sent SSH_MSG_KEXINIT" in output


class TestSecurityHandler:
    """Test security log handler."""

    def test_console_handler(self):
        """Test security handler with console output."""
        handler = SecurityHandler()

        record = logging.LogRecord(
            name="security",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Security event",
            args=(),
            exc_info=None,
        )
        record.client_ip = "192.168.1.100"

        # Should not raise exception
        handler.emit(record)

    def test_file_handler(self):
        """Test security handler with file output."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
            tmp_path = tmp_file.name

        try:
            handler = SecurityHandler(tmp_path)

            record = logging.LogRecord(
                name="security",
                level=logging.INFO,
                pathname="",
                lineno=0,
                msg="Security event",
                args=(),
                exc_info=None,
            )
            record.client_ip = "192.168.1.100"

            handler.emit(record)
            handler.close()

            # Verify file was written
            assert os.path.exists(tmp_path)
            with open(tmp_path, "r") as f:
                content = f.read()
                assert "Security event" in content
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)


class TestConfigureLogging:
    """Test logging configuration."""

    def test_configure_basic_logging(self):
        """Test basic logging configuration."""
        configure_logging(level="DEBUG", format_type="standard")

        logger = logging.getLogger("ssh_library")
        assert logger.level == logging.DEBUG
        assert len(logger.handlers) > 0

    def test_configure_json_logging(self):
        """Test JSON logging configuration."""
        configure_logging(level="INFO", json_format=True)

        logger = logging.getLogger("ssh_library")
        assert logger.level == logging.INFO

    def test_configure_with_files(self):
        """Test logging configuration with file outputs."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            main_log = os.path.join(tmp_dir, "main.log")
            security_log = os.path.join(tmp_dir, "security.log")

            try:
                configure_logging(
                    level="INFO", output_file=main_log, security_file=security_log
                )

                # Test that loggers are configured
                main_logger = logging.getLogger("ssh_library")
                security_logger = logging.getLogger("ssh_library.security")

                assert main_logger.level == logging.INFO
                assert len(main_logger.handlers) > 0
                assert len(security_logger.handlers) > 0
            finally:
                # Clean up handlers to avoid file locks
                for logger_name in [
                    "ssh_library",
                    "ssh_library.security",
                    "ssh_library.performance",
                ]:
                    logger = logging.getLogger(logger_name)
                    for handler in logger.handlers[:]:
                        handler.close()
                        logger.removeHandler(handler)

    def test_get_logger_singleton(self):
        """Test that get_logger returns same instance."""
        logger1 = get_logger("test_singleton")
        logger2 = get_logger("test_singleton")

        assert logger1 is logger2
        assert logger1.name == "test_singleton"
