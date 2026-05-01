import importlib.util
import sys
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "validate_pr_body.py"
SPEC = importlib.util.spec_from_file_location("validate_pr_body", SCRIPT_PATH)
assert SPEC is not None
validate_pr_body = importlib.util.module_from_spec(SPEC)
sys.modules["validate_pr_body"] = validate_pr_body
assert SPEC.loader is not None
SPEC.loader.exec_module(validate_pr_body)


def pr_body(
    *,
    description: str = "Fixes #123\n\nThis updates the PR gate.",
    type_lines: str = "- [x] docs - Documentation-only change",
    tested: str = "- [x] Manual Test: validated locally",
) -> str:
    return f"""## Description

{description}

## Type of Change

{type_lines}

## How Has This Been Tested?

{tested}
"""


def test_valid_docs_change_does_not_require_release():
    result = validate_pr_body.validate_body(pr_body())

    assert result.valid
    assert result.change_type == "docs"
    assert result.release_needed == "false"
    assert result.release_type == "none"


def test_feature_change_requires_test_evidence():
    result = validate_pr_body.validate_body(
        pr_body(
            type_lines="- [x] feature - Adds behavior",
            tested="- [ ] Unit Tests: `pytest tests/test_...`",
        )
    )

    assert not result.valid
    assert "requires test evidence" in result.errors[0]


def test_feature_change_maps_to_minor_release():
    result = validate_pr_body.validate_body(
        pr_body(
            type_lines="- [x] feature - Adds behavior",
            tested="- [x] Unit Tests: `pytest tests/unit`",
        )
    )

    assert result.valid
    assert result.change_type == "feature"
    assert result.release_needed == "true"
    assert result.release_type == "minor"


def test_rejects_missing_type_selection():
    result = validate_pr_body.validate_body(
        pr_body(type_lines="- [ ] docs - Documentation-only change")
    )

    assert not result.valid
    assert "exactly one" in result.errors[0]


def test_rejects_multiple_type_selections():
    result = validate_pr_body.validate_body(
        pr_body(
            type_lines="\n".join(
                [
                    "- [x] docs - Documentation-only change",
                    "- [x] refactor - Non-functional change",
                ]
            )
        )
    )

    assert not result.valid
    assert "found 2" in result.errors[0]


def test_rejects_placeholder_only_description():
    result = validate_pr_body.validate_body(pr_body(description="Fixes # (issue)"))

    assert not result.valid
    assert "description" in result.errors[0].lower()
