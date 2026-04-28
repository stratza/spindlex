"""
Custom log handlers for SpindleX.
"""

import logging
import logging.handlers
import os
from typing import Optional

from .formatters import SecurityFormatter
from .sanitizer import SanitizingFilter


class SecurityHandler(logging.Handler):
    """Handler for security-related events with special formatting."""

    def __init__(
        self,
        filename: Optional[str] = None,
        max_bytes: int = 10 * 1024 * 1024,  # 10MB
        backup_count: int = 5,
    ):
        """
        Initialize security handler.

        Args:
            filename: Log file path (if None, logs to console)
            max_bytes: Maximum file size before rotation
            backup_count: Number of backup files to keep
        """
        super().__init__()
        self.addFilter(SanitizingFilter())

        self.filename = filename

        if filename:
            # Ensure directory exists
            dirname = os.path.dirname(filename)
            if dirname:
                os.makedirs(dirname, exist_ok=True)

            # Use rotating file handler
            self.file_handler = logging.handlers.RotatingFileHandler(
                filename, maxBytes=max_bytes, backupCount=backup_count
            )
            self.file_handler.setFormatter(SecurityFormatter())
        else:
            # Use console handler
            self.console_handler = logging.StreamHandler()
            self.console_handler.setFormatter(SecurityFormatter())

    def emit(self, record: logging.LogRecord) -> None:
        """Emit log record to appropriate handler."""
        try:
            if self.filename:
                self.file_handler.emit(record)
            else:
                self.console_handler.emit(record)
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        """Close the handler."""
        if hasattr(self, "file_handler"):
            self.file_handler.close()
        elif hasattr(self, "console_handler"):
            self.console_handler.close()
        super().close()


class PerformanceHandler(logging.Handler):
    """Handler for performance metrics and timing information."""

    def __init__(self, filename: Optional[str] = None, json_format: bool = True):
        """
        Initialize performance handler.

        Args:
            filename: Log file path (if None, logs to console)
            json_format: Whether to use JSON formatting
        """
        super().__init__()

        self.filename = filename
        self.json_format = json_format

        if json_format:
            from .formatters import JSONFormatter

            formatter: logging.Formatter = JSONFormatter(sanitize=False)
        else:
            from .formatters import SSHFormatter

            formatter = SSHFormatter(
                fmt="[%(asctime)s] PERF.%(levelname)s: %(message)s", sanitize=False
            )

        if filename:
            # Ensure directory exists
            dirname = os.path.dirname(filename)
            if dirname:
                os.makedirs(dirname, exist_ok=True)

            self.file_handler = logging.FileHandler(filename)
            self.file_handler.setFormatter(formatter)
        else:
            self.console_handler = logging.StreamHandler()
            self.console_handler.setFormatter(formatter)

    def emit(self, record: logging.LogRecord) -> None:
        """Emit performance log record."""
        try:
            if self.filename:
                self.file_handler.emit(record)
            else:
                self.console_handler.emit(record)
        except Exception:
            self.handleError(record)

    def close(self) -> None:
        """Close the handler."""
        if hasattr(self, "file_handler"):
            self.file_handler.close()
        elif hasattr(self, "console_handler"):
            self.console_handler.close()
        super().close()
