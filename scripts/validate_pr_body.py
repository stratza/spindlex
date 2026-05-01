#!/usr/bin/env python3
"""Validate pull request metadata used by CI and release automation."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

VALID_TYPES = ("bug", "feature", "breaking", "docs", "refactor", "test")
RELEASE_TYPES = {
    "bug": ("true", "patch"),
    "feature": ("true", "minor"),
    "breaking": ("true", "major"),
    "docs": ("false", "none"),
    "refactor": ("false", "none"),
    "test": ("false", "none"),
}


@dataclass(frozen=True)
class ValidationResult:
    change_type: str
    release_needed: str
    release_type: str
    errors: tuple[str, ...]

    @property
    def valid(self) -> bool:
        return not self.errors


def _section(body: str, heading: str) -> str:
    pattern = re.compile(
        rf"^##\s+{re.escape(heading)}\s*$"
        r"(?P<section>.*?)"
        r"(?=^##\s+|\Z)",
        re.IGNORECASE | re.MULTILINE | re.DOTALL,
    )
    match = pattern.search(body)
    return match.group("section").strip() if match else ""


def _selected_change_types(body: str) -> list[str]:
    section = _section(body, "Type of Change")
    selected: list[str] = []

    for line in section.splitlines():
        match = re.match(r"^\s*[-*]\s+\[[xX]\]\s+`?([a-zA-Z_-]+)`?\b", line)
        if not match:
            continue

        change_type = match.group(1).lower()
        if change_type in VALID_TYPES:
            selected.append(change_type)

    return selected


def _has_description(body: str) -> bool:
    section = _section(body, "Description")
    placeholder_lines = {
        "fixes # (issue)",
        "fixes #",
        "please include a summary of the change and which issue is fixed.",
    }

    for raw_line in section.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("<!--"):
            continue
        if line.endswith("-->"):
            continue
        if line.lower() in placeholder_lines:
            continue
        return True

    return False


def _has_test_evidence(body: str) -> bool:
    section = _section(body, "How Has This Been Tested?")
    for raw_line in section.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("<!--") or line.endswith("-->"):
            continue
        if re.match(r"^[-*]\s+\[[xX]\]", line):
            return True
        if re.match(r"^[-*]\s+\[\s\]", line):
            continue
        if "please describe" in line.lower():
            continue
        return True

    return False


def validate_body(body: str) -> ValidationResult:
    errors: list[str] = []

    selected = _selected_change_types(body)
    if len(selected) != 1:
        errors.append(
            "Select exactly one Type of Change token "
            f"({', '.join(VALID_TYPES)}); found {len(selected)}."
        )

    change_type = selected[0] if len(selected) == 1 else "unknown"
    release_needed, release_type = RELEASE_TYPES.get(change_type, ("false", "none"))

    if not _has_description(body):
        errors.append(
            "PR description is empty or still contains only placeholder text."
        )

    if change_type in {"bug", "feature", "breaking"} and not _has_test_evidence(body):
        errors.append(
            f"Type '{change_type}' requires test evidence in "
            "'How Has This Been Tested?'."
        )

    return ValidationResult(
        change_type=change_type,
        release_needed=release_needed,
        release_type=release_type,
        errors=tuple(errors),
    )


def _body_from_event(event_path: Path) -> str:
    payload = json.loads(event_path.read_text(encoding="utf-8"))
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, dict):
        raise ValueError("GitHub event payload does not contain a pull_request object.")

    body = pull_request.get("body")
    return body if isinstance(body, str) else ""


def _write_github_output(result: ValidationResult) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return

    with Path(output_path).open("a", encoding="utf-8") as output:
        output.write(f"change_type={result.change_type}\n")
        output.write(f"release_needed={result.release_needed}\n")
        output.write(f"release_type={result.release_type}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--event-path", type=Path, help="Path to GitHub event JSON.")
    source.add_argument("--body", help="Pull request body to validate.")
    args = parser.parse_args(argv)

    body = args.body if args.body is not None else _body_from_event(args.event_path)
    result = validate_body(body)
    _write_github_output(result)

    print(f"change_type={result.change_type}")
    print(f"release_needed={result.release_needed}")
    print(f"release_type={result.release_type}")

    if result.valid:
        print("PR metadata validation passed.")
        return 0

    print("PR metadata validation failed:", file=sys.stderr)
    for error in result.errors:
        print(f"- {error}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
