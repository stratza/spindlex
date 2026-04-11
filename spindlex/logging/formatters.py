"""
Custom log formatters for SpindleX.
"""

import json
import logging
import time

from .sanitizer import LogSanitizer


class SSHFormatter(logging.Formatter):
    """Standard SpindleX log formatter with security sanitization."""

    def __init__(self, fmt: str = None, datefmt: str = None, sanitize: bool = True):
        """
        Initialize SSH formatter.

        Args:
            fmt: Log format string
            datefmt: Date format string
            sanitize: Whether to sanitize sensitive information
        """
        if fmt is None:
            fmt = "[%(asctime)s] %(name)s.%(levelname)s: %(message)s"
        if datefmt is None:
            datefmt = "%Y-%m-%d %H:%M:%S"

        super().__init__(fmt, datefmt)
        self.sanitize = sanitize

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with optional sanitization."""
        if self.sanitize:
            # Create a copy to avoid modifying the original record
            record_copy = logging.makeLogRecord(record.__dict__)

            # First format the message normally to get the final message
            formatted_message = super().format(record_copy)

            # Then sanitize the final formatted message
            sanitized_message = LogSanitizer.sanitize_message(formatted_message)

            return sanitized_message
        else:
            return super().format(record)


class JSONFormatter(logging.Formatter):
    """JSON log formatter for structured logging."""

    def __init__(self, sanitize: bool = True, include_extra: bool = True):
        """
        Initialize JSON formatter.

        Args:
            sanitize: Whether to sanitize sensitive information
            include_extra: Whether to include extra fields from LogRecord
        """
        super().__init__()
        self.sanitize = sanitize
        self.include_extra = include_extra

    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON."""
        log_data = {
            "timestamp": time.time(),
            "level": record.levelname,
            "logger": record.name,
            "message": (
                str(record.msg) % record.args if record.args else str(record.msg)
            ),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_data["exception"] = self.formatException(record.exc_info)

        # Add extra fields
        if self.include_extra:
            extra_fields = {}
            for key, value in record.__dict__.items():
                if key not in {
                    "name",
                    "msg",
                    "args",
                    "levelname",
                    "levelno",
                    "pathname",
                    "filename",
                    "module",
                    "exc_info",
                    "exc_text",
                    "stack_info",
                    "lineno",
                    "funcName",
                    "created",
                    "msecs",
                    "relativeCreated",
                    "thread",
                    "threadName",
                    "processName",
                    "process",
                    "getMessage",
                }:
                    extra_fields[key] = value

            if extra_fields:
                log_data["extra"] = extra_fields

        # Sanitize if requested
        if self.sanitize:
            log_data = LogSanitizer.sanitize_dict(log_data)

        return json.dumps(log_data, default=str, separators=(",", ":"))


class SecurityFormatter(SSHFormatter):
    """Enhanced formatter for security-related events."""

    def __init__(self, sanitize: bool = True):
        """Initialize security formatter with enhanced format."""
        fmt = "[%(asctime)s] SECURITY.%(levelname)s [%(client_ip)s]: %(message)s"
        super().__init__(fmt, sanitize=sanitize)

    def format(self, record: logging.LogRecord) -> str:
        """Format security log record with client IP if available."""
        # Ensure client_ip field exists
        if not hasattr(record, "client_ip"):
            record.client_ip = "unknown"

        return super().format(record)


class DebugFormatter(SSHFormatter):
    """Detailed formatter for debugging with protocol information."""

    def __init__(self, sanitize: bool = False):
        """Initialize debug formatter with detailed format."""
        fmt = (
            "[%(asctime)s.%(msecs)03d] %(name)s.%(levelname)s "
            "[%(filename)s:%(lineno)d] %(funcName)s(): %(message)s"
        )
        datefmt = "%Y-%m-%d %H:%M:%S"
        super().__init__(fmt, datefmt, sanitize=sanitize)
