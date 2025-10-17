"""Basic tests to ensure CI pipeline works."""

import pytest


def test_import_spindlex():
    """Test that we can import the spindlex package."""
    import spindlex

    assert spindlex.__version__ == "0.1.0"


def test_basic_functionality():
    """Basic test to ensure pytest is working."""
    assert 1 + 1 == 2


def test_spindlex_exports():
    """Test that spindlex exports expected symbols."""
    import spindlex

    # Check that basic exports exist (even if not implemented yet)
    expected_exports = [
        "__version__",
        "__author__",
        "__license__",
    ]

    for export in expected_exports:
        assert hasattr(spindlex, export), f"Missing export: {export}"


class TestSpindlexBasic:
    """Basic test class for SpindleX functionality."""

    def test_version_format(self):
        """Test that version follows semantic versioning."""
        import re

        import spindlex

        # Check version format (major.minor.patch)
        version_pattern = r"^\d+\.\d+\.\d+$"
        assert re.match(version_pattern, spindlex.__version__)

    def test_package_metadata(self):
        """Test package metadata is properly set."""
        import spindlex

        assert isinstance(spindlex.__author__, str)
        assert isinstance(spindlex.__license__, str)
        assert len(spindlex.__author__) > 0
        assert len(spindlex.__license__) > 0
