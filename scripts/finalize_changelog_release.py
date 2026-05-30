#!/usr/bin/env python3
"""Move the current changelog notes from Unreleased into a release section."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import sys
from pathlib import Path

DEFAULT_CHANGELOG = Path("docs/changelog.md")
UNRELEASED_HEADING = "## [Unreleased]"
RELEASE_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?:\s+-\s+.*)?$")


def finalize_changelog(content: str, *, version: str, release_date: str) -> str:
    lines = content.splitlines()
    if any(
        (match := RELEASE_HEADING.match(line)) and match.group("version") == version
        for line in lines
    ):
        return content if content.endswith("\n") else f"{content}\n"

    try:
        unreleased_index = lines.index(UNRELEASED_HEADING)
    except ValueError as exc:
        raise ValueError("Could not find ## [Unreleased] in changelog.") from exc

    insert_at = unreleased_index + 1
    release_heading = f"## [{version}] - {release_date}"
    lines[insert_at:insert_at] = ["", release_heading]
    return "\n".join(lines).rstrip() + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    parser.add_argument("--version", required=True)
    parser.add_argument(
        "--date",
        default=dt.datetime.now(dt.UTC).date().isoformat(),
        help="Release date to write in YYYY-MM-DD format.",
    )
    args = parser.parse_args(argv)

    try:
        updated = finalize_changelog(
            args.changelog.read_text(encoding="utf-8"),
            version=args.version,
            release_date=args.date,
        )
    except Exception as exc:
        print(f"Changelog finalization failed: {exc}", file=sys.stderr)
        return 1

    args.changelog.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
