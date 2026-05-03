#!/usr/bin/env python3
"""Require release-producing pull requests to update the changelog."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_CHANGELOG = Path("docs/changelog.md")


def _event_payload(event_path: Path) -> dict[str, object]:
    return json.loads(event_path.read_text(encoding="utf-8"))


def _pull_request_shas(event_path: Path) -> tuple[str, str]:
    payload = _event_payload(event_path)
    pull_request = payload.get("pull_request")
    if not isinstance(pull_request, dict):
        raise ValueError("GitHub event payload does not contain a pull_request object.")

    base = pull_request.get("base")
    head = pull_request.get("head")
    if not isinstance(base, dict) or not isinstance(head, dict):
        raise ValueError("GitHub event payload does not contain base/head refs.")

    base_sha = base.get("sha")
    head_sha = head.get("sha")
    if not isinstance(base_sha, str) or not isinstance(head_sha, str):
        raise ValueError("GitHub event payload does not contain base/head SHAs.")

    return base_sha, head_sha


def _git_diff(changelog: Path, base_sha: str, head_sha: str) -> str:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("git executable was not found.")

    result = subprocess.run(  # noqa: S603 - fixed command with GitHub-provided SHAs.
        [
            git,
            "diff",
            "--unified=0",
            f"{base_sha}...{head_sha}",
            "--",
            changelog.as_posix(),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def _has_added_changelog_content(diff: str) -> bool:
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        if line[1:].strip():
            return True
    return False


def changelog_updated(changelog: Path, base_sha: str, head_sha: str) -> bool:
    diff = _git_diff(changelog, base_sha, head_sha)
    return _has_added_changelog_content(diff)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-path", type=Path, required=True)
    parser.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    args = parser.parse_args(argv)

    try:
        base_sha, head_sha = _pull_request_shas(args.event_path)
        updated = changelog_updated(args.changelog, base_sha, head_sha)
    except Exception as exc:
        print(f"Changelog check failed: {exc}", file=sys.stderr)
        return 1

    if updated:
        print(f"{args.changelog.as_posix()} has release-note changes.")
        return 0

    print(
        f"{args.changelog.as_posix()} must be updated for bug, feature, "
        "and breaking-change PRs.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
