"""
Performance monitoring and metrics collection for SpindleX.
"""

import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import wraps
from typing import Any, Callable, ContextManager, Iterator, Optional, Union

from .logger import get_logger


@dataclass
class PerformanceMetric:
    """Container for performance metric data."""

    operation: str
    duration: float
    timestamp: float
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectionMetrics:
    """Metrics for SSH connection operations."""

    connection_time: Optional[float] = None
    handshake_time: Optional[float] = None
    auth_time: Optional[float] = None
    kex_time: Optional[float] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    channels_opened: int = 0
    channels_closed: int = 0
    errors: int = 0


class PerformanceMonitor:
    """Performance monitoring and metrics collection system."""

    def __init__(self, max_metrics: int = 10000):
        """
        Initialize performance monitor.

        Args:
            max_metrics: Maximum number of metrics to keep in memory
        """
        self.max_metrics = max_metrics
        self.metrics: deque[PerformanceMetric] = deque(maxlen=max_metrics)
        self.connection_metrics: dict[str, ConnectionMetrics] = {}
        self.operation_stats: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.RLock()
        self.logger = get_logger("spindlex.monitoring")

    def record_metric(self, operation: str, duration: float, **metadata: Any) -> None:
        """
        Record a performance metric.

        Args:
            operation: Operation name
            duration: Operation duration in seconds
            **metadata: Additional metric metadata
        """
        metric = PerformanceMetric(
            operation=operation,
            duration=duration,
            timestamp=time.time(),
            metadata=metadata,
        )

        with self._lock:
            self.metrics.append(metric)
            self.operation_stats[operation].append(duration)

            # Keep only recent stats to prevent memory growth
            if len(self.operation_stats[operation]) > 1000:
                self.operation_stats[operation] = self.operation_stats[operation][-500:]

        # Log performance metric
        self.logger.performance_metric(operation, duration, **metadata)

    @contextmanager
    def time_operation(self, operation: str, **metadata: Any) -> Iterator[None]:
        """
        Context manager for timing operations.

        Args:
            operation: Operation name
            **metadata: Additional metadata to record
        """
        start_time = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start_time
            self.record_metric(operation, duration, **metadata)

    def get_connection_metrics(self, connection_id: str) -> ConnectionMetrics:
        """
        Get metrics for a specific connection.

        Args:
            connection_id: Unique connection identifier

        Returns:
            ConnectionMetrics instance
        """
        with self._lock:
            if connection_id not in self.connection_metrics:
                self.connection_metrics[connection_id] = ConnectionMetrics()
            return self.connection_metrics[connection_id]

    def update_connection_metric(
        self, connection_id: str, metric_name: str, value: Union[float, int, str]
    ) -> None:
        """
        Update a specific connection metric.

        Args:
            connection_id: Connection identifier
            metric_name: Name of metric to update
            value: New metric value
        """
        metrics = self.get_connection_metrics(connection_id)
        setattr(metrics, metric_name, value)

    def increment_connection_counter(
        self, connection_id: str, counter_name: str, amount: int = 1
    ) -> None:
        """
        Increment a connection counter metric.

        Args:
            connection_id: Connection identifier
            counter_name: Name of counter to increment
            amount: Amount to increment by
        """
        metrics = self.get_connection_metrics(connection_id)
        current_value = getattr(metrics, counter_name, 0)
        setattr(metrics, counter_name, current_value + amount)

    def get_operation_stats(self, operation: str) -> dict[str, float]:
        """
        Get statistical summary for an operation.

        Args:
            operation: Operation name

        Returns:
            Dictionary with min, max, mean, median statistics
        """
        with self._lock:
            durations = self.operation_stats.get(operation, [])

            if not durations:
                return {}

            sorted_durations = sorted(durations)
            count = len(sorted_durations)

            return {
                "count": count,
                "min": min(sorted_durations),
                "max": max(sorted_durations),
                "mean": sum(sorted_durations) / count,
                "median": sorted_durations[count // 2],
                "p95": (
                    sorted_durations[int(count * 0.95)]
                    if count > 20
                    else sorted_durations[-1]
                ),
                "p99": (
                    sorted_durations[int(count * 0.99)]
                    if count > 100
                    else sorted_durations[-1]
                ),
            }

    def get_recent_metrics(
        self, operation: Optional[str] = None, limit: int = 100
    ) -> list[PerformanceMetric]:
        """
        Get recent performance metrics.

        Args:
            operation: Filter by operation name (optional)
            limit: Maximum number of metrics to return

        Returns:
            List of recent metrics
        """
        with self._lock:
            metrics = list(self.metrics)

            if operation:
                metrics = [m for m in metrics if m.operation == operation]

            return metrics[-limit:]

    def clear_metrics(self, connection_id: Optional[str] = None) -> None:
        """
        Clear stored metrics.

        Args:
            connection_id: Clear metrics for specific connection (optional)
        """
        with self._lock:
            if connection_id:
                self.connection_metrics.pop(connection_id, None)
            else:
                self.metrics.clear()
                self.connection_metrics.clear()
                self.operation_stats.clear()


# Global performance monitor instance
_performance_monitor = PerformanceMonitor()


def get_performance_monitor() -> PerformanceMonitor:
    """Get the global performance monitor instance."""
    return _performance_monitor


def timed_operation(operation_name: str, **metadata: Any) -> Callable[..., Any]:
    """
    Decorator for timing function execution.

    Args:
        operation_name: Name of the operation being timed
        **metadata: Additional metadata to record
    """

    def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
        @wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with _performance_monitor.time_operation(operation_name, **metadata):
                return func(*args, **kwargs)

        return wrapper

    return decorator


class CryptoTimer:
    """Specialized timer for cryptographic operations."""

    def __init__(self, monitor: Optional[PerformanceMonitor] = None):
        """
        Initialize crypto timer.

        Args:
            monitor: Performance monitor instance (uses global if None)
        """
        self.monitor = monitor or get_performance_monitor()
        self.logger = get_logger("spindlex.crypto.timing")

    @contextmanager
    def time_crypto_operation(
        self,
        operation: str,
        algorithm: str,
        key_size: Optional[int] = None,
        **metadata: Any,
    ) -> Iterator[None]:
        """
        Time a cryptographic operation.

        Args:
            operation: Type of crypto operation (encrypt, decrypt, sign, verify, etc.)
            algorithm: Cryptographic algorithm name
            key_size: Key size in bits (optional)
            **metadata: Additional metadata
        """
        crypto_metadata = {"algorithm": algorithm, "category": "crypto", **metadata}

        if key_size:
            crypto_metadata["key_size"] = key_size

        with self.monitor.time_operation(f"crypto_{operation}", **crypto_metadata):
            yield

    def time_key_generation(self, algorithm: str, key_size: int) -> ContextManager[None]:
        """Time key generation operation."""
        return self.time_crypto_operation("keygen", algorithm, key_size)

    def time_key_exchange(self, algorithm: str) -> ContextManager[None]:
        """Time key exchange operation."""
        return self.time_crypto_operation("kex", algorithm)

    def time_encryption(self, cipher: str, data_size: int) -> ContextManager[None]:
        """Time encryption operation."""
        return self.time_crypto_operation("encrypt", cipher, data_size=data_size)

    def time_decryption(self, cipher: str, data_size: int) -> ContextManager[None]:
        """Time decryption operation."""
        return self.time_crypto_operation("decrypt", cipher, data_size=data_size)

    def time_signature(self, algorithm: str, key_size: int) -> ContextManager[None]:
        """Time signature operation."""
        return self.time_crypto_operation("sign", algorithm, key_size)

    def time_verification(self, algorithm: str, key_size: int) -> ContextManager[None]:
        """Time signature verification operation."""
        return self.time_crypto_operation("verify", algorithm, key_size)


class ProtocolAnalyzer:
    """Analyzer for SSH protocol debugging and performance analysis."""

    def __init__(self, monitor: Optional[PerformanceMonitor] = None):
        """
        Initialize protocol analyzer.

        Args:
            monitor: Performance monitor instance (uses global if None)
        """
        self.monitor = monitor or get_performance_monitor()
        self.logger = get_logger("spindlex.protocol.analyzer")
        self.message_counts: dict[str, int] = defaultdict(int)
        self.message_sizes: dict[str, list[int]] = defaultdict(list)
        self._lock = threading.RLock()

    def record_message(
        self, direction: str, message_type: str, size: int, connection_id: str
    ) -> None:
        """
        Record SSH protocol message for analysis.

        Args:
            direction: 'sent' or 'received'
            message_type: SSH message type
            size: Message size in bytes
            connection_id: Connection identifier
        """
        with self._lock:
            key = f"{direction}_{message_type}"
            self.message_counts[key] += 1
            self.message_sizes[key].append(size)

            # Keep size history bounded
            if len(self.message_sizes[key]) > 1000:
                self.message_sizes[key] = self.message_sizes[key][-500:]

        # Update connection metrics
        if direction == "sent":
            self.monitor.increment_connection_counter(connection_id, "packets_sent")
            self.monitor.increment_connection_counter(connection_id, "bytes_sent", size)
        else:
            self.monitor.increment_connection_counter(connection_id, "packets_received")
            self.monitor.increment_connection_counter(
                connection_id, "bytes_received", size
            )

        # Log protocol event for debugging
        self.logger.protocol_debug(
            direction=direction,
            message_type=message_type,
            data={"size": size, "connection_id": connection_id},
        )

    def get_message_stats(self) -> dict[str, dict[str, Any]]:
        """
        Get statistics for protocol messages.

        Returns:
            Dictionary with message statistics
        """
        with self._lock:
            stats = {}

            for message_key, count in self.message_counts.items():
                sizes = self.message_sizes[message_key]
                if sizes:
                    stats[message_key] = {
                        "count": count,
                        "total_bytes": sum(sizes),
                        "avg_size": sum(sizes) / len(sizes),
                        "min_size": min(sizes),
                        "max_size": max(sizes),
                    }
                else:
                    stats[message_key] = {"count": count}

            return stats

    def clear_stats(self) -> None:
        """Clear protocol analysis statistics."""
        with self._lock:
            self.message_counts.clear()
            self.message_sizes.clear()


# Global protocol analyzer instance
_protocol_analyzer = ProtocolAnalyzer()


def get_protocol_analyzer() -> ProtocolAnalyzer:
    """Get the global protocol analyzer instance."""
    return _protocol_analyzer
