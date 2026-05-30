import importlib.util
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[2] / "scripts"


def load_script(name: str):
    path = SCRIPT_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


finalize_changelog_release = load_script("finalize_changelog_release")


def test_finalize_changelog_moves_unreleased_notes_under_version():
    content = """# Changelog

## [Unreleased]

### Fixed
*   Important fix.

## [0.7.0] - 2026-05-16
"""

    updated = finalize_changelog_release.finalize_changelog(
        content, version="0.7.1", release_date="2026-05-29"
    )

    assert "## [Unreleased]\n\n## [0.7.1] - 2026-05-29\n\n### Fixed" in updated
    assert updated.endswith("\n")


def test_finalize_changelog_is_idempotent_for_existing_version():
    content = """# Changelog

## [Unreleased]

## [0.7.1] - 2026-05-29

### Fixed
*   Important fix.
"""

    updated = finalize_changelog_release.finalize_changelog(
        content, version="0.7.1", release_date="2026-05-30"
    )

    assert updated == content


def test_finalize_changelog_requires_unreleased_heading():
    try:
        finalize_changelog_release.finalize_changelog(
            "# Changelog\n", version="0.7.1", release_date="2026-05-29"
        )
    except ValueError as exc:
        assert "Unreleased" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
