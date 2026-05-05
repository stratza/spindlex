#!/usr/bin/env python3
"""Extract one release section from docs/changelog.md."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_CHANGELOG = Path("docs/changelog.md")
RELEASE_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?:\s+-\s+.*)?$")


def extract_release_notes(changelog: Path, version: str) -> str:
    lines = changelog.read_text(encoding="utf-8").splitlines()
    start: int | None = None
    end = len(lines)

    for index, line in enumerate(lines):
        match = RELEASE_HEADING.match(line)
        if not match:
            continue
        if match.group("version") == version:
            start = index + 1
            continue
        if start is not None:
            end = index
            break

    if start is None:
        raise ValueError(f"Could not find changelog section for version {version}.")

    notes = "\n".join(lines[start:end]).strip()
    if not notes:
        raise ValueError(f"Changelog section for version {version} is empty.")
    return notes + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        notes = extract_release_notes(args.changelog, args.version)
    except Exception as exc:
        print(f"Release note extraction failed: {exc}", file=sys.stderr)
        return 1

    args.output.write_text(notes, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
