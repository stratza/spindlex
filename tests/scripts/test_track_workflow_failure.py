import importlib.util
import sys
from argparse import Namespace
from pathlib import Path

SCRIPT_PATH = (
    Path(__file__).resolve().parents[2] / "scripts" / "track_workflow_failure.py"
)
SPEC = importlib.util.spec_from_file_location("track_workflow_failure", SCRIPT_PATH)
assert SPEC is not None
track_workflow_failure = importlib.util.module_from_spec(SPEC)
sys.modules["track_workflow_failure"] = track_workflow_failure
assert SPEC.loader is not None
SPEC.loader.exec_module(track_workflow_failure)


class FakeClient:
    def __init__(self, matches=None, runs=None):
        self.matches = matches or []
        self.runs = runs or []
        self.created = []
        self.comments = []
        self.closed = []
        self.ensured_labels = []

    def search_open_issues(self, labels, key):
        self.last_search = (labels, key)
        return self.matches

    def search_open_issues_by_text(self, labels, text):
        self.last_text_search = (labels, text)
        return self.matches

    def create_issue(self, title, body, labels):
        self.ensure_labels(labels)
        issue = {
            "number": 123,
            "html_url": "https://github.example/issues/123",
            "title": title,
            "body": body,
            "labels": labels,
        }
        self.created.append(issue)
        return issue

    def ensure_labels(self, labels):
        self.ensured_labels.extend(labels)

    def comment_issue(self, issue_number, body):
        self.comments.append((issue_number, body))
        return {}

    def close_issue(self, issue_number):
        self.closed.append(issue_number)
        return {}

    def workflow_runs(self, workflow_file, branch, status, per_page=10):
        self.last_runs_request = (workflow_file, branch, status, per_page)
        return self.runs


def record(**overrides):
    values = {
        "repository": "stratza/spindlex",
        "workflow": "Release",
        "failed_stage": "integration",
        "failure_class": "release-blocked",
        "signature": "Release:integration:patch:0.6.7",
        "run_url": "https://github.example/runs/1",
        "source_sha": "abc123",
        "branch": "main",
        "source_pr": "131",
        "release_type": "patch",
        "planned_version": "0.6.7",
        "next_action": "Fix forward.",
    }
    values.update(overrides)
    return track_workflow_failure.FailureRecord(**values)


def test_failure_key_is_stable():
    first = record().key
    second = record().key

    assert first == second
    assert len(first) == 16


def test_classifies_pull_request_as_summary_only_failure():
    failure_class = track_workflow_failure.classify_failure(
        "pull_request", "unit-tests", False
    )

    assert failure_class == "pr-failure"


def test_classifies_publish_partial_before_release_blocked():
    failure_class = track_workflow_failure.classify_failure("push", "publish", True)

    assert failure_class == "publish-partial"


def test_ensure_issue_creates_when_no_match(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    client = FakeClient()

    url = track_workflow_failure.ensure_issue(client, record())

    assert url == "https://github.example/issues/123"
    assert client.created
    assert "failure-key" in client.created[0]["body"]
    assert "release-blocked" in client.created[0]["labels"]
    assert "release-blocked" in client.ensured_labels


def test_ensure_issue_updates_existing_match(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    client = FakeClient(
        matches=[{"number": 45, "html_url": "https://github.example/issues/45"}]
    )

    url = track_workflow_failure.ensure_issue(client, record())

    assert url == "https://github.example/issues/45"
    assert not client.created
    assert client.comments[0][0] == 45


def test_close_matching_issues_uses_planned_version():
    client = FakeClient(
        matches=[{"number": 78, "html_url": "https://github.example/issues/78"}]
    )

    closed = track_workflow_failure.close_matching_issues(client, record())

    assert closed == ["https://github.example/issues/78"]
    assert client.closed == [78]
    assert client.last_text_search[1] == "0.6.7"


def test_previous_failed_runs_excludes_current_run():
    client = FakeClient(runs=[{"id": 1}, {"id": 2}, {"id": 3}])

    count = track_workflow_failure.previous_failed_runs(
        client, "ci-matrix.yml", "main", "2"
    )

    assert count == 2


def release_args(**overrides):
    values = {
        "repository": "stratza/spindlex",
        "token": "token",
        "workflow_name": "Release",
        "run_url": "https://github.example/runs/1",
        "branch": "main",
        "source_pr": "131",
        "source_sha": "abc123",
        "release_type": "patch",
        "planned_version": "0.6.7",
        "compatibility_result": "success",
        "integration_result": "success",
        "publish_result": "success",
        "release_complete": "true",
    }
    values.update(overrides)
    return Namespace(**values)


def test_handle_release_closes_only_when_release_completion_is_verified(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    client = FakeClient(
        matches=[{"number": 78, "html_url": "https://github.example/issues/78"}]
    )
    monkeypatch.setattr(track_workflow_failure, "GitHubClient", lambda *_: client)

    result = track_workflow_failure.handle_release(release_args())

    assert result == 0
    assert client.closed == [78]


def test_handle_release_does_not_close_when_publish_skipped_existing_tag(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    client = FakeClient(
        matches=[{"number": 78, "html_url": "https://github.example/issues/78"}]
    )
    monkeypatch.setattr(track_workflow_failure, "GitHubClient", lambda *_: client)

    result = track_workflow_failure.handle_release(release_args(release_complete=""))

    assert result == 0
    assert client.closed == []
    assert client.comments == []
