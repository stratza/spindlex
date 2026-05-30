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


def _section_end(lines: list[str], start: int) -> int:
    for index in range(start + 1, len(lines)):
        if RELEASE_HEADING.match(lines[index]):
            return index
    return len(lines)


def _trim_blank_edges(lines: list[str]) -> list[str]:
    start = 0
    end = len(lines)
    while start < end and not lines[start].strip():
        start += 1
    while end > start and not lines[end - 1].strip():
        end -= 1
    return lines[start:end]


def finalize_changelog(content: str, *, version: str, release_date: str) -> str:
    lines = content.splitlines()
    try:
        unreleased_index = lines.index(UNRELEASED_HEADING)
    except ValueError as exc:
        raise ValueError("Could not find ## [Unreleased] in changelog.") from exc

    version_index = next(
        (
            index
            for index, line in enumerate(lines)
            if (match := RELEASE_HEADING.match(line))
            and match.group("version") == version
        ),
        None,
    )
    if version_index is not None:
        existing_heading = lines[version_index]
        if "Unreleased" not in existing_heading:
            return content if content.endswith("\n") else f"{content}\n"

        unreleased_end = _section_end(lines, unreleased_index)
        version_end = _section_end(lines, version_index)
        unreleased_body = _trim_blank_edges(lines[unreleased_index + 1 : unreleased_end])
        version_body = _trim_blank_edges(lines[version_index + 1 : version_end])
        combined_body = unreleased_body.copy()
        if combined_body and version_body:
            combined_body.append("")
        combined_body.extend(version_body)

        del lines[version_index:version_end]
        del lines[unreleased_index + 1 : unreleased_end]
        lines[unreleased_index + 1 : unreleased_index + 1] = [
            "",
            f"## [{version}] - {release_date}",
            "",
            *combined_body,
            "",
        ]
        return "\n".join(lines).rstrip() + "\n"

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
