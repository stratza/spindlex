#!/usr/bin/env python3
"""Plan PR-driven releases for GitHub Actions."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sync_project_version import read_pyproject_version, validate_version, version_info
from validate_pr_body import validate_body

RELEASE_BUMPS = {"patch", "minor", "major"}
NO_RELEASE_TYPES = {"docs", "refactor", "test", "none"}
DIRECT_RELEASE_TYPES = RELEASE_BUMPS | NO_RELEASE_TYPES


@dataclass(frozen=True)
class ReleasePlan:
    release_needed: str
    release_type: str
    change_type: str
    current_version: str
    next_version: str
    tag: str
    dry_run: str
    source_pr: str
    source_pr_url: str
    source_sha: str
    reason: str


def bump_version(version: str, release_type: str) -> str:
    validate_version(version)
    major, minor, patch = version_info(version)

    if release_type == "major":
        return f"{major + 1}.0.0"
    if release_type == "minor":
        return f"{major}.{minor + 1}.0"
    if release_type == "patch":
        return f"{major}.{minor}.{patch + 1}"
    return version


def _event_payload(event_path: Path) -> dict[str, Any]:
    return json.loads(event_path.read_text(encoding="utf-8"))


def _github_api_json(path: str, token: str) -> Any:
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"GitHub API request failed: {exc.code} {body}") from exc


def _associated_pull_requests(repository: str, sha: str, token: str) -> list[dict[str, Any]]:
    data = _github_api_json(f"/repos/{repository}/commits/{sha}/pulls", token)
    if not isinstance(data, list):
        raise RuntimeError("GitHub API returned an unexpected pull request payload.")
    return [item for item in data if isinstance(item, dict)]


def _last_merged_pull_request(
    repository: str, sha: str, token: str
) -> dict[str, Any] | None:
    candidates = [
        pr
        for pr in _associated_pull_requests(repository, sha, token)
        if pr.get("merged_at")
    ]
    if not candidates:
        return None
    return sorted(
        candidates,
        key=lambda pr: (str(pr.get("merged_at")), int(pr.get("number") or 0)),
    )[-1]


def _plan_from_release_type(
    *, release_type: str, current_version: str, dry_run: bool, source_sha: str, reason: str
) -> ReleasePlan:
    if release_type not in DIRECT_RELEASE_TYPES:
        raise ValueError(f"Unsupported release type override: {release_type!r}")

    release_needed = release_type in RELEASE_BUMPS
    next_version = bump_version(current_version, release_type) if release_needed else current_version
    return ReleasePlan(
        release_needed=str(release_needed).lower(),
        release_type=release_type if release_needed else "none",
        change_type=release_type,
        current_version=current_version,
        next_version=next_version,
        tag=f"v{next_version}",
        dry_run=str(dry_run).lower(),
        source_pr="",
        source_pr_url="",
        source_sha=source_sha,
        reason=reason,
    )


def _plan_from_pr_body(
    *,
    body: str,
    current_version: str,
    dry_run: bool,
    source_sha: str,
    source_pr: str = "",
    source_pr_url: str = "",
) -> ReleasePlan:
    result = validate_body(body)
    if not result.valid:
        errors = "\n".join(f"- {error}" for error in result.errors)
        raise ValueError(f"Source PR metadata is invalid:\n{errors}")

    release_needed = result.release_needed == "true"
    next_version = (
        bump_version(current_version, result.release_type)
        if release_needed
        else current_version
    )
    reason = (
        f"release planned from PR type {result.change_type}"
        if release_needed
        else f"no release for PR type {result.change_type}"
    )
    return ReleasePlan(
        release_needed=result.release_needed,
        release_type=result.release_type,
        change_type=result.change_type,
        current_version=current_version,
        next_version=next_version,
        tag=f"v{next_version}",
        dry_run=str(dry_run).lower(),
        source_pr=source_pr,
        source_pr_url=source_pr_url,
        source_sha=source_sha,
        reason=reason,
    )


def create_plan(event_path: Path) -> ReleasePlan:
    payload = _event_payload(event_path)
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    source_sha = os.environ.get("GITHUB_SHA", "")
    current_version = read_pyproject_version()

    if event_name == "workflow_dispatch":
        inputs = payload.get("inputs") if isinstance(payload.get("inputs"), dict) else {}
        release_type = str(inputs.get("release_type") or "patch")
        dry_run = str(inputs.get("dry_run", "true")).lower() != "false"
        if not dry_run:
            raise ValueError("workflow_dispatch is dry-run only for release safety.")
        return _plan_from_release_type(
            release_type=release_type,
            current_version=current_version,
            dry_run=True,
            source_sha=source_sha,
            reason="manual release dry run",
        )

    if event_name == "pull_request":
        pr = payload.get("pull_request")
        if not isinstance(pr, dict):
            raise ValueError("pull_request event does not include a pull_request object.")
        return _plan_from_pr_body(
            body=str(pr.get("body") or ""),
            current_version=current_version,
            dry_run=True,
            source_sha=source_sha,
            source_pr=str(pr.get("number") or ""),
            source_pr_url=str(pr.get("html_url") or ""),
        )

    if event_name == "push":
        head_commit = payload.get("head_commit")
        message = ""
        if isinstance(head_commit, dict):
            message = str(head_commit.get("message") or "")
        if "[skip release]" in message:
            return _plan_from_release_type(
                release_type="none",
                current_version=current_version,
                dry_run=False,
                source_sha=source_sha,
                reason="head commit contains [skip release]",
            )

        repository = os.environ.get("GITHUB_REPOSITORY", "")
        token = os.environ.get("GITHUB_TOKEN", "")
        if not repository or not token or not source_sha:
            raise ValueError("GITHUB_REPOSITORY, GITHUB_TOKEN, and GITHUB_SHA are required.")

        pr = _last_merged_pull_request(repository, source_sha, token)
        if pr is None:
            return _plan_from_release_type(
                release_type="none",
                current_version=current_version,
                dry_run=False,
                source_sha=source_sha,
                reason="no merged PR associated with push SHA",
            )
        return _plan_from_pr_body(
            body=str(pr.get("body") or ""),
            current_version=current_version,
            dry_run=False,
            source_sha=source_sha,
            source_pr=str(pr.get("number") or ""),
            source_pr_url=str(pr.get("html_url") or ""),
        )

    return _plan_from_release_type(
        release_type="none",
        current_version=current_version,
        dry_run=True,
        source_sha=source_sha,
        reason=f"unsupported event for publishing: {event_name or 'unknown'}",
    )


def _write_github_output(plan: ReleasePlan) -> None:
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with Path(output_path).open("a", encoding="utf-8") as output:
        for key, value in plan.__dict__.items():
            output.write(f"{key}={value}\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--event-path", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        plan = create_plan(args.event_path)
    except Exception as exc:
        print(f"Release planning failed: {exc}", file=sys.stderr)
        return 1

    _write_github_output(plan)
    print(json.dumps(plan.__dict__, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
