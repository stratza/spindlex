"""
Configuration for SSH Library Integration Tests

This module provides configuration settings and utilities for running
comprehensive integration tests.
"""

import os
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class OpenSSHTestConfig:
    """Configuration for OpenSSH interoperability tests."""

    host: Optional[str] = None
    port: int = 22
    username: Optional[str] = None
    password: Optional[str] = None
    key_filename: Optional[str] = None

    @classmethod
    def from_environment(cls) -> "OpenSSHTestConfig":
        """Create config from environment variables."""
        return cls(
            host=os.environ.get("SSH_TEST_HOST"),
            port=int(os.environ.get("SSH_TEST_PORT", "22")),
            username=os.environ.get("SSH_TEST_USER"),
            password=os.environ.get("SSH_TEST_PASSWORD"),
            key_filename=os.environ.get("SSH_TEST_KEY"),
        )

    @property
    def is_configured(self) -> bool:
        """Check if OpenSSH testing is properly configured."""
        return (
            self.host is not None
            and self.username is not None
            and (self.password is not None or self.key_filename is not None)
        )


@dataclass
class PerformanceTestConfig:
    """Configuration for performance tests."""

    # Connection performance
    max_connections: int = 50
    connection_timeout: float = 10.0

    # Command execution performance
    max_commands_per_connection: int = 100
    command_timeout: float = 5.0

    # SFTP performance
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    min_throughput_mbps: float = 1.0  # Minimum 1 MB/s

    # Benchmark iterations
    crypto_iterations: int = 100
    connection_iterations: int = 10
    command_iterations: int = 50

    # Memory limits
    max_memory_per_connection_kb: int = 1024  # 1MB per connection
    max_memory_leak_mb: int = 10  # 10MB total leak allowed

    @classmethod
    def from_environment(cls) -> "PerformanceTestConfig":
        """Create config from environment variables."""
        return cls(
            max_connections=int(os.environ.get("PERF_MAX_CONNECTIONS", "50")),
            connection_timeout=float(os.environ.get("PERF_CONNECTION_TIMEOUT", "10.0")),
            max_commands_per_connection=int(os.environ.get("PERF_MAX_COMMANDS", "100")),
            command_timeout=float(os.environ.get("PERF_COMMAND_TIMEOUT", "5.0")),
            max_file_size=int(
                os.environ.get("PERF_MAX_FILE_SIZE", str(10 * 1024 * 1024))
            ),
            min_throughput_mbps=float(os.environ.get("PERF_MIN_THROUGHPUT", "1.0")),
            crypto_iterations=int(os.environ.get("PERF_CRYPTO_ITERATIONS", "100")),
            connection_iterations=int(
                os.environ.get("PERF_CONNECTION_ITERATIONS", "10")
            ),
            command_iterations=int(os.environ.get("PERF_COMMAND_ITERATIONS", "50")),
            max_memory_per_connection_kb=int(
                os.environ.get("PERF_MAX_MEMORY_PER_CONN", "1024")
            ),
            max_memory_leak_mb=int(os.environ.get("PERF_MAX_MEMORY_LEAK", "10")),
        )


@dataclass
class IntegrationTestConfig:
    """Main configuration for integration tests."""

    # Test server configuration
    test_server_host: str = "localhost"
    test_server_port_range: tuple = (10000, 20000)
    test_server_timeout: float = 30.0

    # Test data configuration
    temp_dir_prefix: str = "spindlex_test_"
    cleanup_temp_files: bool = True

    # Logging configuration
    log_level: str = "INFO"
    log_to_file: bool = True
    log_file_prefix: str = "integration_test_"

    # Test execution configuration
    parallel_test_workers: int = 4
    test_timeout_seconds: int = 300  # 5 minutes per test
    retry_failed_tests: bool = False
    retry_count: int = 2

    # External dependencies
    openssh_config: OpenSSHTestConfig = None
    performance_config: PerformanceTestConfig = None

    def __post_init__(self):
        """Initialize sub-configurations."""
        if self.openssh_config is None:
            self.openssh_config = OpenSSHTestConfig.from_environment()

        if self.performance_config is None:
            self.performance_config = PerformanceTestConfig.from_environment()

    @classmethod
    def from_environment(cls) -> "IntegrationTestConfig":
        """Create config from environment variables."""
        return cls(
            test_server_host=os.environ.get("TEST_SERVER_HOST", "localhost"),
            test_server_port_range=(
                int(os.environ.get("TEST_SERVER_PORT_MIN", "10000")),
                int(os.environ.get("TEST_SERVER_PORT_MAX", "20000")),
            ),
            test_server_timeout=float(os.environ.get("TEST_SERVER_TIMEOUT", "30.0")),
            temp_dir_prefix=os.environ.get("TEST_TEMP_DIR_PREFIX", "ssh_library_test_"),
            cleanup_temp_files=os.environ.get("TEST_CLEANUP_TEMP", "true").lower()
            == "true",
            log_level=os.environ.get("TEST_LOG_LEVEL", "INFO"),
            log_to_file=os.environ.get("TEST_LOG_TO_FILE", "true").lower() == "true",
            log_file_prefix=os.environ.get("TEST_LOG_FILE_PREFIX", "integration_test_"),
            parallel_test_workers=int(os.environ.get("TEST_PARALLEL_WORKERS", "4")),
            test_timeout_seconds=int(os.environ.get("TEST_TIMEOUT", "300")),
            retry_failed_tests=os.environ.get("TEST_RETRY_FAILED", "false").lower()
            == "true",
            retry_count=int(os.environ.get("TEST_RETRY_COUNT", "2")),
        )


# Global configuration instance
CONFIG = IntegrationTestConfig.from_environment()


def get_test_config() -> IntegrationTestConfig:
    """Get the global test configuration."""
    return CONFIG


def print_test_config():
    """Print current test configuration."""
    config = get_test_config()

    print("Integration Test Configuration:")
    print("=" * 40)
    print(f"Test Server: {config.test_server_host}")
    print(f"Port Range: {config.test_server_port_range}")
    print(f"Timeout: {config.test_server_timeout}s")
    print(f"Log Level: {config.log_level}")
    print(f"Parallel Workers: {config.parallel_test_workers}")
    print()

    print("OpenSSH Configuration:")
    print("-" * 20)
    openssh = config.openssh_config
    if openssh.is_configured:
        print(f"Host: {openssh.host}")
        print(f"Port: {openssh.port}")
        print(f"Username: {openssh.username}")
        print(f"Auth Method: {'Key' if openssh.key_filename else 'Password'}")
    else:
        print("Not configured (set SSH_TEST_* environment variables)")
    print()

    print("Performance Configuration:")
    print("-" * 25)
    perf = config.performance_config
    print(f"Max Connections: {perf.max_connections}")
    print(f"Max File Size: {perf.max_file_size / 1024 / 1024:.1f} MB")
    print(f"Min Throughput: {perf.min_throughput_mbps} MB/s")
    print(f"Crypto Iterations: {perf.crypto_iterations}")


# Test environment validation
def validate_test_environment() -> Dict[str, Any]:
    """Validate the test environment and return status."""
    validation_results = {"valid": True, "warnings": [], "errors": [], "info": []}

    config = get_test_config()

    # Check Python version
    import sys

    if sys.version_info < (3, 9):
        validation_results["errors"].append(
            f"Python 3.9+ required, found {sys.version_info.major}.{sys.version_info.minor}"
        )
        validation_results["valid"] = False
    else:
        validation_results["info"].append(f"Python version: {sys.version}")

    # Check required packages
    required_packages = ["pytest", "psutil"]
    optional_packages = ["coverage", "pytest-cov", "pytest-html"]

    for package in required_packages:
        try:
            __import__(package)
            validation_results["info"].append(f"Required package '{package}' available")
        except ImportError:
            validation_results["errors"].append(
                f"Required package '{package}' not found"
            )
            validation_results["valid"] = False

    for package in optional_packages:
        try:
            __import__(package)
            validation_results["info"].append(f"Optional package '{package}' available")
        except ImportError:
            validation_results["warnings"].append(
                f"Optional package '{package}' not found"
            )

    # Check OpenSSH configuration
    if config.openssh_config.is_configured:
        validation_results["info"].append("OpenSSH interoperability tests enabled")
    else:
        validation_results["warnings"].append(
            "OpenSSH interoperability tests disabled (set SSH_TEST_* environment variables)"
        )

    # Check system resources
    try:
        import psutil

        memory_gb = psutil.virtual_memory().total / 1024 / 1024 / 1024
        if memory_gb < 2:
            validation_results["warnings"].append(
                f"Low system memory: {memory_gb:.1f} GB"
            )
        else:
            validation_results["info"].append(f"System memory: {memory_gb:.1f} GB")

        cpu_count = psutil.cpu_count()
        validation_results["info"].append(f"CPU cores: {cpu_count}")

    except ImportError:
        validation_results["warnings"].append(
            "Cannot check system resources (psutil not available)"
        )

    return validation_results


if __name__ == "__main__":
    print_test_config()
    print()

    validation = validate_test_environment()

    print("Environment Validation:")
    print("=" * 25)

    if validation["errors"]:
        print("ERRORS:")
        for error in validation["errors"]:
            print(f"  ❌ {error}")
        print()

    if validation["warnings"]:
        print("WARNINGS:")
        for warning in validation["warnings"]:
            print(f"  ⚠️  {warning}")
        print()

    if validation["info"]:
        print("INFO:")
        for info in validation["info"]:
            print(f"  ℹ️  {info}")
        print()

    if validation["valid"]:
        print("✅ Environment validation passed")
    else:
        print("❌ Environment validation failed")
        exit(1)
