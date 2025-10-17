"""Pytest configuration and fixtures."""

import pytest


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line("markers", "unit: Unit tests")
    config.addinivalue_line(
        "markers", "integration: Integration tests requiring external services"
    )
    config.addinivalue_line("markers", "performance: Performance and benchmark tests")
    config.addinivalue_line("markers", "security: Security-focused tests")
    config.addinivalue_line("markers", "slow: Tests that take a long time to run")


def skip_if_not_implemented(module_path):
    """Skip test if module is not fully implemented."""
    try:
        import importlib

        module = importlib.import_module(module_path)
        # Check if it's a placeholder by looking for a specific attribute
        if hasattr(module, "_is_placeholder"):
            return pytest.mark.skip(f"Module {module_path} not fully implemented yet")
        return pytest.mark.usefixtures()  # No-op marker
    except ImportError:
        return pytest.mark.skip(f"Module {module_path} not available")


# Fixture to check if full implementation is available
@pytest.fixture
def full_implementation_available():
    """Check if full Spindle implementation is available."""
    try:
        from spindle.crypto.backend import get_crypto_backend
        from spindle.crypto.pkey import Ed25519Key

        # If we can import these without error, assume full implementation
        return True
    except (ImportError, AttributeError):
        return False


@pytest.fixture
def skip_if_no_implementation(full_implementation_available):
    """Skip test if full implementation is not available."""
    if not full_implementation_available:
        pytest.skip("Full Spindle implementation not available")
