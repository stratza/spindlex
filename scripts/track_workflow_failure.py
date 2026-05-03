#!/usr/bin/env python3
"""Track post-merge workflow failures with deduplicated GitHub issues."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ISSUE_LABELS = {
    "ci-flake": ("flake", "ci", "triage"),
    "code-regression": ("ci", "triage"),
    "infra-flake": ("ci", "triage"),
    "pr-failure": ("ci", "triage"),
    "release-blocked": ("release-blocked", "ci", "triage"),
    "security-blocker": ("security-blocker", "ci", "triage"),
    "publish-partial": ("publish-partial", "ci", "triage"),
}

LABEL_COLORS = {
    "ci": "ededed",
    "triage": "ededed",
    "flake": "d4c5f9",
    "release-blocked": "b60205",
    "publish-partial": "fbca04",
    "security-blocker": "d93f0b",
}


@dataclass(frozen=True)
class FailureRecord:
    repository: str
    workflow: str
    failed_stage: str
    failure_class: str
    signature: str
    run_url: str
    source_sha: str
    branch: str
    source_pr: str = ""
    release_type: str = ""
    planned_version: str = ""
    next_action: str = ""

    @property
    def key(self) -> str:
        source = "/".join(
            [self.workflow, self.failed_stage, self.failure_class, self.signature]
        )
        return hashlib.sha256(source.encode("utf-8")).hexdigest()[:16]


class GitHubClient:
    def __init__(self, repository: str, token: str) -> None:
        self.repository = repository
        self.token = token

    def request(
        self, method: str, path: str, payload: dict[str, Any] | None = None
    ) -> Any:
        data = None
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            f"https://api.github.com{path}",
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"GitHub API request failed: {exc.code} {body}") from exc

        return json.loads(body) if body else {}

    def search_open_issues(
        self, labels: tuple[str, ...], key: str
    ) -> list[dict[str, Any]]:
        terms = [
            f"repo:{self.repository}",
            "is:issue",
            "is:open",
            f'"failure-key: {key}"',
        ]
        terms.extend(f"label:{label}" for label in labels)
        query = urllib.parse.urlencode({"q": " ".join(terms)})
        payload = self.request("GET", f"/search/issues?{query}")
        items = payload.get("items") if isinstance(payload, dict) else []
        return [item for item in items if isinstance(item, dict)]

    def search_open_issues_by_text(
        self, labels: tuple[str, ...], text: str
    ) -> list[dict[str, Any]]:
        terms = [f"repo:{self.repository}", "is:issue", "is:open", f'"{text}"']
        terms.extend(f"label:{label}" for label in labels)
        query = urllib.parse.urlencode({"q": " ".join(terms)})
        payload = self.request("GET", f"/search/issues?{query}")
        items = payload.get("items") if isinstance(payload, dict) else []
        return [item for item in items if isinstance(item, dict)]

    def create_issue(
        self, title: str, body: str, labels: tuple[str, ...]
    ) -> dict[str, Any]:
        self.ensure_labels(labels)
        return self.request(
            "POST",
            f"/repos/{self.repository}/issues",
            {"title": title, "body": body, "labels": list(labels)},
        )

    def ensure_labels(self, labels: tuple[str, ...]) -> None:
        for label in labels:
            payload = {
                "name": label,
                "color": LABEL_COLORS.get(label, "ededed"),
            }
            try:
                self.request("POST", f"/repos/{self.repository}/labels", payload)
            except RuntimeError as exc:
                if "422" not in str(exc):
                    raise

    def comment_issue(self, issue_number: int, body: str) -> dict[str, Any]:
        return self.request(
            "POST",
            f"/repos/{self.repository}/issues/{issue_number}/comments",
            {"body": body},
        )

    def close_issue(self, issue_number: int) -> dict[str, Any]:
        return self.request(
            "PATCH",
            f"/repos/{self.repository}/issues/{issue_number}",
            {"state": "closed", "state_reason": "completed"},
        )

    def workflow_runs(
        self, workflow_file: str, branch: str, status: str, per_page: int = 10
    ) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode(
            {"branch": branch, "status": status, "per_page": str(per_page)}
        )
        payload = self.request(
            "GET",
            f"/repos/{self.repository}/actions/workflows/{workflow_file}/runs?{query}",
        )
        runs = payload.get("workflow_runs") if isinstance(payload, dict) else []
        return [run for run in runs if isinstance(run, dict)]


def classify_failure(event_name: str, failed_stage: str, publish_partial: bool) -> str:
    normalized_stage = failed_stage.lower()
    if event_name == "pull_request":
        return "pr-failure"
    if publish_partial:
        return "publish-partial"
    if "security" in normalized_stage:
        return "security-blocker"
    if "release" in normalized_stage or "integration" in normalized_stage:
        return "release-blocked"
    if event_name in {"schedule", "workflow_dispatch"}:
        return "ci-flake"
    if event_name == "push":
        return "code-regression"
    return "infra-flake"


def issue_title(record: FailureRecord) -> str:
    if record.failure_class == "ci-flake":
        return f"[Flake] {record.workflow} failed at {record.failed_stage}"
    if record.failure_class == "publish-partial":
        return f"[Release] Partial publish for {record.planned_version}"
    if record.failure_class == "release-blocked":
        return f"[Release] {record.planned_version} blocked at {record.failed_stage}"
    return f"[CI] {record.workflow} failed at {record.failed_stage}"


def issue_body(record: FailureRecord, now: str) -> str:
    return f"""<!-- failure-key: {record.key} -->

## Failure tracking

- Failure key: `{record.key}`
- Failure class: `{record.failure_class}`
- Workflow: `{record.workflow}`
- Failed stage: `{record.failed_stage}`
- Run URL: {record.run_url}
- Source PR: {record.source_pr or "n/a"}
- Source SHA: `{record.source_sha}`
- Branch: `{record.branch}`
- Release type: `{record.release_type or "n/a"}`
- Planned version: `{record.planned_version or "n/a"}`
- First seen: `{now}`
- Latest seen: `{now}`

## Required action

{record.next_action}
"""


def update_comment(record: FailureRecord, now: str) -> str:
    return f"""Latest occurrence for `{record.key}`:

- Time: `{now}`
- Run URL: {record.run_url}
- Source SHA: `{record.source_sha}`
- Failed stage: `{record.failed_stage}`
- Failure class: `{record.failure_class}`
- Next action: {record.next_action}
"""


def append_summary(record: FailureRecord, issue_url: str, action: str) -> None:
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_path:
        return

    with Path(summary_path).open("a", encoding="utf-8") as summary:
        summary.write("## Failure tracking\n\n")
        summary.write(f"- source PR: `{record.source_pr or 'n/a'}`\n")
        summary.write(f"- source SHA: `{record.source_sha}`\n")
        summary.write(f"- failed stage: `{record.failed_stage}`\n")
        summary.write(f"- failure class: `{record.failure_class}`\n")
        summary.write(f"- failure key: `{record.key}`\n")
        summary.write(f"- issue URL: {issue_url or 'n/a'}\n")
        summary.write(f"- next action: {record.next_action}\n")
        summary.write(f"- automation action: `{action}`\n")


def ensure_issue(client: GitHubClient, record: FailureRecord) -> str:
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    labels = ISSUE_LABELS[record.failure_class]
    matches = client.search_open_issues(labels, record.key)
    if matches:
        issue = matches[0]
        number = int(issue["number"])
        client.comment_issue(number, update_comment(record, now))
        url = str(issue.get("html_url") or issue.get("url") or "")
        append_summary(record, url, "updated")
        return url

    issue = client.create_issue(issue_title(record), issue_body(record, now), labels)
    url = str(issue.get("html_url") or issue.get("url") or "")
    append_summary(record, url, "created")
    return url


def close_matching_issues(client: GitHubClient, record: FailureRecord) -> list[str]:
    closed: list[str] = []
    seen: set[int] = set()
    for failure_class in ("release-blocked", "publish-partial"):
        labels = ISSUE_LABELS[failure_class]
        matches = client.search_open_issues_by_text(labels, record.planned_version)
        for issue in matches:
            number = int(issue["number"])
            if number in seen:
                continue
            seen.add(number)
            client.comment_issue(
                number,
                f"Closing after a successful release run: {record.run_url}",
            )
            client.close_issue(number)
            closed.append(str(issue.get("html_url") or issue.get("url") or ""))
    return closed


def previous_failed_runs(
    client: GitHubClient, workflow_file: str, branch: str, current_run_id: str
) -> int:
    runs = client.workflow_runs(workflow_file, branch, "failure", per_page=10)
    return sum(str(run.get("id") or "") != current_run_id for run in runs)


def release_record(
    args: argparse.Namespace, failure_class: str, stage: str
) -> FailureRecord:
    return FailureRecord(
        repository=args.repository,
        workflow=args.workflow_name,
        failed_stage=stage,
        failure_class=failure_class,
        signature=f"{args.workflow_name}:{stage}:{args.release_type}:{args.planned_version}",
        run_url=args.run_url,
        source_sha=args.source_sha,
        branch=args.branch,
        source_pr=args.source_pr,
        release_type=args.release_type,
        planned_version=args.planned_version,
        next_action=(
            "Inspect the failed release stage, rerun if it was infrastructure-only, "
            "or fix forward with a new PR."
        ),
    )


def handle_release(args: argparse.Namespace) -> int:
    client = GitHubClient(args.repository, args.token)
    results = {
        "compatibility-matrix": args.compatibility_result,
        "integration": args.integration_result,
        "publish": args.publish_result,
    }

    if "cancelled" in results.values():
        print("Release failure tracking skipped for cancelled workflow.")
        return 0

    if args.compatibility_result != "success":
        record = release_record(args, "release-blocked", "compatibility-matrix")
        ensure_issue(client, record)
        return 0

    if args.integration_result != "success":
        record = release_record(args, "release-blocked", "integration")
        ensure_issue(client, record)
        return 0

    if args.publish_result == "success" and args.release_complete == "true":
        record = release_record(args, "release-blocked", "release")
        closed = close_matching_issues(client, record)
        append_summary(record, ", ".join(closed), "closed" if closed else "none")
        print(f"Closed {len(closed)} release failure issue(s).")
        return 0

    if args.publish_result == "success":
        record = release_record(args, "publish-partial", "publish")
        record = FailureRecord(
            **{
                **record.__dict__,
                "next_action": "Publish job succeeded without a verified release completion signal; keep release incidents open until PyPI and GitHub Release state are verified.",
            }
        )
        append_summary(record, "", "not-closed")
        print(
            "Release issue closure skipped because release completion was not verified."
        )
        return 0

    if args.publish_result == "failure":
        record = release_record(args, "publish-partial", "publish")
        record = FailureRecord(
            **{
                **record.__dict__,
                "next_action": "Check tag, GitHub Release, PyPI, and verification state; fix forward if any artifact is already public.",
            }
        )
        ensure_issue(client, record)
        return 0

    print("Release failure tracking found no actionable failure.")
    return 0


def handle_ci(args: argparse.Namespace) -> int:
    failure_class = classify_failure(args.event_name, args.failed_stage, False)
    record = FailureRecord(
        repository=args.repository,
        workflow=args.workflow_name,
        failed_stage=args.failed_stage,
        failure_class=failure_class,
        signature=f"{args.workflow_file}:{args.failed_stage}:{args.branch}",
        run_url=args.run_url,
        source_sha=args.source_sha,
        branch=args.branch,
        next_action="Rerun if infrastructure-related; otherwise fix forward on main.",
    )

    if failure_class == "pr-failure":
        append_summary(record, "", "summary-only")
        print("PR failure recorded in summary only.")
        return 0

    client = GitHubClient(args.repository, args.token)
    if failure_class == "ci-flake":
        previous_failures = previous_failed_runs(
            client, args.workflow_file, args.branch, args.run_id
        )
        if previous_failures < args.min_previous_failures:
            append_summary(record, "", "summary-only")
            print("First observed flake; no issue created.")
            return 0

    ensure_issue(client, record)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    release = subparsers.add_parser("release")
    release.add_argument("--repository", required=True)
    release.add_argument("--token", required=True)
    release.add_argument("--workflow-name", required=True)
    release.add_argument("--run-url", required=True)
    release.add_argument("--branch", required=True)
    release.add_argument("--source-pr", default="")
    release.add_argument("--source-sha", required=True)
    release.add_argument("--release-type", required=True)
    release.add_argument("--planned-version", required=True)
    release.add_argument("--compatibility-result", required=True)
    release.add_argument("--integration-result", required=True)
    release.add_argument("--publish-result", required=True)
    release.add_argument("--release-complete", default="")
    release.set_defaults(func=handle_release)

    ci = subparsers.add_parser("ci")
    ci.add_argument("--repository", required=True)
    ci.add_argument("--token", required=True)
    ci.add_argument("--workflow-name", required=True)
    ci.add_argument("--workflow-file", required=True)
    ci.add_argument("--run-id", required=True)
    ci.add_argument("--run-url", required=True)
    ci.add_argument("--branch", required=True)
    ci.add_argument("--source-sha", required=True)
    ci.add_argument("--event-name", required=True)
    ci.add_argument("--failed-stage", required=True)
    ci.add_argument("--min-previous-failures", type=int, default=1)
    ci.set_defaults(func=handle_ci)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"Failure tracking failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
