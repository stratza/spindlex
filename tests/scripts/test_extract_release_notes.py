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


extract_release_notes = load_script("extract_release_notes")


def test_extracts_requested_release_section(tmp_path):
    changelog = tmp_path / "changelog.md"
    changelog.write_text(
        """# Changelog

## [1.2.3] - 2026-05-05

### Fixed
*   Patched dependency metadata.

## [1.2.2] - 2026-05-01

### Fixed
*   Older change.
""",
        encoding="utf-8",
    )

    notes = extract_release_notes.extract_release_notes(changelog, "1.2.3")

    assert notes == "### Fixed\n*   Patched dependency metadata.\n"


def test_missing_release_section_raises(tmp_path):
    changelog = tmp_path / "changelog.md"
    changelog.write_text("# Changelog\n", encoding="utf-8")

    try:
        extract_release_notes.extract_release_notes(changelog, "1.2.3")
    except ValueError as exc:
        assert "Could not find" in str(exc)
    else:
        raise AssertionError("missing release section should fail")


def test_empty_release_section_raises(tmp_path):
    changelog = tmp_path / "changelog.md"
    changelog.write_text(
        """# Changelog

## [1.2.3] - 2026-05-05

## [1.2.2] - 2026-05-01
""",
        encoding="utf-8",
    )

    try:
        extract_release_notes.extract_release_notes(changelog, "1.2.3")
    except ValueError as exc:
        assert "empty" in str(exc)
    else:
        raise AssertionError("empty release section should fail")
