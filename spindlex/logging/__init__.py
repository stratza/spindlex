"""
SpindleX Logging Module

Provides structured logging with security-aware sanitization and configurable output formats.
"""

from .formatters import DebugFormatter, JSONFormatter, SecurityFormatter, SSHFormatter
from .handlers import PerformanceHandler, SecurityHandler
from .logger import SSHLogger, configure_logging, get_logger
from .monitoring import (
    ConnectionMetrics,
    CryptoTimer,
    PerformanceMetric,
    PerformanceMonitor,
    ProtocolAnalyzer,
    get_performance_monitor,
    get_protocol_analyzer,
    timed_operation,
)
from .sanitizer import LogSanitizer

__all__ = [
    "SSHLogger",
    "get_logger",
    "configure_logging",
    "SSHFormatter",
    "JSONFormatter",
    "SecurityFormatter",
    "DebugFormatter",
    "SecurityHandler",
    "PerformanceHandler",
    "LogSanitizer",
    "PerformanceMonitor",
    "get_performance_monitor",
    "timed_operation",
    "CryptoTimer",
    "ProtocolAnalyzer",
    "get_protocol_analyzer",
    "PerformanceMetric",
    "ConnectionMetrics",
]
