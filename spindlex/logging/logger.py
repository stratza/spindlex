"""
Main logging interface for SpindleX.
"""

import logging
import logging.config
from typing import Any, Optional, Union

from .formatters import DebugFormatter, JSONFormatter, SSHFormatter
from .handlers import PerformanceHandler, SecurityHandler


class SSHLogger:
    """Enhanced logger for SpindleX with security and performance features."""

    def __init__(self, name: str, logger: Optional[logging.Logger] = None):
        """
        Initialize SSH logger.

        Args:
            name: Logger name
            logger: Existing logger instance (if None, creates new one)
        """
        self.name = name
        self.logger = logger or logging.getLogger(name)

        # Bug #4 Fixed: Enforce log sanitization by attaching the filter
        # to the logger instance if it's not already there.
        from .sanitizer import SanitizingFilter

        has_filter = any(isinstance(f, SanitizingFilter) for f in self.logger.filters)
        if not has_filter:
            self.logger.addFilter(SanitizingFilter())

        self._security_logger: Optional[logging.Logger] = None
        self._performance_logger: Optional[logging.Logger] = None

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log debug message."""
        self.logger.debug(msg, *args, **kwargs)

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log info message."""
        self.logger.info(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log warning message."""
        self.logger.warning(msg, *args, **kwargs)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log error message."""
        self.logger.error(msg, *args, **kwargs)

    def critical(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log critical message."""
        self.logger.critical(msg, *args, **kwargs)

    def exception(self, msg: str, *args: Any, **kwargs: Any) -> None:
        """Log exception with traceback."""
        self.logger.exception(msg, *args, **kwargs)

    def security_event(
        self,
        event_type: str,
        message: str,
        client_ip: str = "unknown",
        username: str = "unknown",
        **kwargs: Any,
    ) -> None:
        """
        Log security-related event.

        Args:
            event_type: Type of security event (auth_success, auth_failure, etc.)
            message: Event description
            client_ip: Client IP address
            username: Username involved in event
            **kwargs: Additional event data
        """
        if not self._security_logger:
            self._security_logger = logging.getLogger(f"{self.name}.security")

        extra = {
            "event_type": event_type,
            "client_ip": client_ip,
            "username": username,
            **kwargs,
        }

        self._security_logger.info(message, extra=extra)

    def performance_metric(
        self, operation: str, duration: float, **kwargs: Any
    ) -> None:
        """
        Log performance metric.

        Args:
            operation: Operation name
            duration: Operation duration in seconds
            **kwargs: Additional metric data
        """
        if not self._performance_logger:
            self._performance_logger = logging.getLogger(f"{self.name}.performance")

        extra = {"operation": operation, "duration_seconds": duration, **kwargs}

        message = f"Operation '{operation}' completed in {duration:.4f}s"
        self._performance_logger.info(message, extra=extra)

    def protocol_debug(
        self, direction: str, message_type: str, data: dict[str, Any], **kwargs: Any
    ) -> None:
        """
        Log protocol-level debugging information.

        Args:
            direction: 'sent' or 'received'
            message_type: SSH message type
            data: Message data
            **kwargs: Additional debug data
        """
        extra = {
            "direction": direction,
            "message_type": message_type,
            "data": data,
            **kwargs,
        }

        message = f"SSH {direction} {message_type}"
        self.logger.debug(message, extra=extra)


# Global logger registry
_loggers: dict[str, SSHLogger] = {}


def get_logger(name: str) -> SSHLogger:
    """
    Get or create SSH logger instance.

    Args:
        name: Logger name

    Returns:
        SSHLogger instance
    """
    full_name = f"spindlex.{name}" if not name.startswith("spindlex") else name
    if full_name not in _loggers:
        _loggers[full_name] = SSHLogger(full_name)
    return _loggers[full_name]


def configure_logging(
    level: Union[str, int] = logging.INFO,
    format_type: str = "standard",
    output_file: Optional[str] = None,
    security_file: Optional[str] = None,
    performance_file: Optional[str] = None,
    sanitize: bool = True,
    json_format: bool = False,
) -> None:
    """
    Configure SpindleX logging.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: Format type ('standard', 'debug', 'json')
        output_file: Main log file path
        security_file: Security events log file path
        performance_file: Performance metrics log file path
        sanitize: Whether to sanitize sensitive information
        json_format: Whether to use JSON formatting for main logs
    """
    # Convert string level to int if needed
    if isinstance(level, str):
        level = getattr(logging, level.upper())

    # Configure root SSH logger
    root_logger = logging.getLogger("spindlex")
    root_logger.setLevel(level)

    # Clear existing handlers
    root_logger.handlers.clear()

    # Choose formatter
    formatter: logging.Formatter
    if json_format or format_type == "json":
        formatter = JSONFormatter(sanitize=sanitize)
    elif format_type == "debug":
        formatter = DebugFormatter(sanitize=sanitize)
    else:
        formatter = SSHFormatter(sanitize=sanitize)

    # Add main handler
    handler: logging.Handler
    if output_file:
        import os

        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        handler = logging.FileHandler(output_file)
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(formatter)
    handler.setLevel(level)
    root_logger.addHandler(handler)

    # Configure security logger
    if security_file or not output_file:
        security_logger = logging.getLogger("spindlex.security")
        security_logger.setLevel(logging.INFO)
        security_handler = SecurityHandler(security_file)
        security_logger.addHandler(security_handler)
        security_logger.propagate = False  # Don't propagate to root logger

    # Configure performance logger
    if performance_file or not output_file:
        perf_logger = logging.getLogger("spindlex.performance")
        perf_logger.setLevel(logging.INFO)
        perf_handler = PerformanceHandler(performance_file, json_format=True)
        perf_logger.addHandler(perf_handler)
        perf_logger.propagate = False  # Don't propagate to root logger

    # Set library-wide logging level
    logging.getLogger("spindlex").setLevel(level)
