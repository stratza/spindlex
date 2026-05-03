import importlib.util
import sys
from pathlib import Path

SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "check_changelog_updated.py"
)
SPEC = importlib.util.spec_from_file_location("check_changelog_updated", SCRIPT_PATH)
assert SPEC is not None
check_changelog_updated = importlib.util.module_from_spec(SPEC)
sys.modules["check_changelog_updated"] = check_changelog_updated
assert SPEC.loader is not None
SPEC.loader.exec_module(check_changelog_updated)


def test_detects_added_changelog_content():
    diff = """diff --git a/docs/changelog.md b/docs/changelog.md
index 1111111..2222222 100644
--- a/docs/changelog.md
+++ b/docs/changelog.md
@@ -5,0 +6,2 @@
+### Fixed
+* Fixed release planning.
"""

    assert check_changelog_updated._has_added_changelog_content(diff)


def test_ignores_empty_added_lines():
    diff = """diff --git a/docs/changelog.md b/docs/changelog.md
index 1111111..2222222 100644
--- a/docs/changelog.md
+++ b/docs/changelog.md
@@ -5,0 +6,1 @@
+
"""

    assert not check_changelog_updated._has_added_changelog_content(diff)


def test_ignores_file_header_only():
    diff = """diff --git a/docs/changelog.md b/docs/changelog.md
index 1111111..2222222 100644
--- a/docs/changelog.md
+++ b/docs/changelog.md
"""

    assert not check_changelog_updated._has_added_changelog_content(diff)
