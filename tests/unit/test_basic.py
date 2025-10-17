"""Basic tests to ensure CI pipeline works."""

import pytest


def test_import_spindle():
    """Test that we can import the spindle package."""
    import spindle

    assert spindle.__version__ == "0.1.0"


def test_basic_functionality():
    """Basic test to ensure pytest is working."""
    assert 1 + 1 == 2


def test_spindle_exports():
    """Test that spindle exports expected symbols."""
    import spindle

    # Check that basic exports exist (even if not implemented yet)
    expected_exports = [
        "__version__",
        "__author__",
        "__email__",
        "__license__",
    ]

    for export in expected_exports:
        assert hasattr(spindle, export), f"Missing export: {export}"


class TestSpindleBasic:
    """Basic test class for Spindle functionality."""

    def test_version_format(self):
        """Test that version follows semantic versioning."""
        import re

        import spindle

        # Check version format (major.minor.patch)
        version_pattern = r"^\d+\.\d+\.\d+$"
        assert re.match(version_pattern, spindle.__version__)

    def test_package_metadata(self):
        """Test package metadata is properly set."""
        import spindle

        assert isinstance(spindle.__author__, str)
        assert isinstance(spindle.__email__, str)
        assert isinstance(spindle.__license__, str)
        assert len(spindle.__author__) > 0
        assert "@" in spindle.__email__
        assert len(spindle.__license__) > 0
