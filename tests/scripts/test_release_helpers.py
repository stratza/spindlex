import importlib.util
import json
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parents[2] / "scripts"


def load_script(name: str):
    path = SCRIPT_DIR / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


sync_project_version = load_script("sync_project_version")
validate_pr_body = load_script("validate_pr_body")
plan_release = load_script("plan_release")


def write_event(tmp_path: Path, payload: dict) -> Path:
    path = tmp_path / "event.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def pr_body(change_type: str) -> str:
    return f"""## Description

Release planner test.

## Type of Change

- [x] {change_type} - selected change

## How Has This Been Tested?

- [x] Unit Tests: pytest tests/scripts
"""


def test_bump_version_by_release_type():
    assert plan_release.bump_version("1.2.3", "patch") == "1.2.4"
    assert plan_release.bump_version("1.2.3", "minor") == "1.3.0"
    assert plan_release.bump_version("1.2.3", "major") == "2.0.0"


def test_pull_request_feature_plans_patch_release_during_beta(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    event_path = write_event(
        tmp_path,
        {
            "pull_request": {
                "number": 130,
                "html_url": "https://github.com/stratza/spindlex/pull/130",
                "body": pr_body("feature"),
            }
        },
    )

    plan = plan_release.create_plan(event_path)

    assert plan.release_needed == "true"
    assert plan.release_type == "patch"
    assert plan.dry_run == "true"
    assert plan.next_version == plan_release.bump_version(plan.current_version, "patch")
    assert plan.tag == f"v{plan.next_version}"
    assert plan.source_pr == "130"


def test_pull_request_feature_minor_plans_minor_release_during_beta(
    monkeypatch, tmp_path
):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    event_path = write_event(
        tmp_path,
        {
            "pull_request": {
                "number": 132,
                "html_url": "https://github.com/stratza/spindlex/pull/132",
                "body": pr_body("feature-minor"),
            }
        },
    )

    plan = plan_release.create_plan(event_path)

    assert plan.release_needed == "true"
    assert plan.release_type == "minor"
    assert plan.change_type == "feature-minor"
    assert plan.next_version == plan_release.bump_version(plan.current_version, "minor")


def test_pull_request_breaking_plans_minor_release_during_beta(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    event_path = write_event(
        tmp_path,
        {
            "pull_request": {
                "number": 133,
                "html_url": "https://github.com/stratza/spindlex/pull/133",
                "body": pr_body("breaking"),
            }
        },
    )

    plan = plan_release.create_plan(event_path)

    assert plan.release_needed == "true"
    assert plan.release_type == "minor"
    assert plan.change_type == "breaking"
    assert plan.next_version == plan_release.bump_version(plan.current_version, "minor")


def test_pull_request_docs_plans_no_release(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "pull_request")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    event_path = write_event(
        tmp_path,
        {
            "pull_request": {
                "number": 131,
                "html_url": "https://github.com/stratza/spindlex/pull/131",
                "body": pr_body("docs"),
            }
        },
    )

    plan = plan_release.create_plan(event_path)

    assert plan.release_needed == "false"
    assert plan.release_type == "none"
    assert plan.next_version == plan.current_version


def test_workflow_dispatch_is_forced_to_dry_run(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    event_path = write_event(
        tmp_path, {"inputs": {"dry_run": "true", "release_type": "patch"}}
    )

    plan = plan_release.create_plan(event_path)

    assert plan.release_needed == "true"
    assert plan.release_type == "patch"
    assert plan.dry_run == "true"


def test_workflow_dispatch_rejects_real_release(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    event_path = write_event(
        tmp_path, {"inputs": {"dry_run": "false", "release_type": "patch"}}
    )

    try:
        plan_release.create_plan(event_path)
    except ValueError as exc:
        assert "dry-run only" in str(exc)
    else:
        raise AssertionError("workflow_dispatch real releases must be rejected")


def test_push_skip_release_commit_plans_no_release(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_SHA", "abc123")
    event_path = write_event(
        tmp_path, {"head_commit": {"message": "chore(release): v1.2.3 [skip release]"}}
    )

    plan = plan_release.create_plan(event_path)

    assert plan.release_needed == "false"
    assert plan.reason == "head commit contains [skip release]"


def test_push_falls_back_to_merge_commit_pr_number(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_SHA", "merge-sha")
    monkeypatch.setenv("GITHUB_REPOSITORY", "stratza/spindlex")
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(plan_release, "_last_merged_pull_request", lambda *a, **k: None)
    monkeypatch.setattr(
        plan_release,
        "_pull_request_by_number",
        lambda *a, **k: {
            "number": 170,
            "html_url": "https://github.com/stratza/spindlex/pull/170",
            "merged_at": "2026-05-09T06:57:47Z",
            "merge_commit_sha": "merge-sha",
            "body": pr_body("feature"),
        },
    )
    event_path = write_event(
        tmp_path,
        {"head_commit": {"message": "v0.6.10: Stabilization work (#170)"}},
    )

    plan = plan_release.create_plan(event_path)

    assert plan.release_needed == "true"
    assert plan.release_type == "patch"
    assert plan.source_pr == "170"


def test_push_fallback_rejects_wrong_merge_commit_sha(monkeypatch, tmp_path):
    monkeypatch.setenv("GITHUB_EVENT_NAME", "push")
    monkeypatch.setenv("GITHUB_SHA", "merge-sha")
    monkeypatch.setenv("GITHUB_REPOSITORY", "stratza/spindlex")
    monkeypatch.setenv("GITHUB_TOKEN", "token")
    monkeypatch.setattr(plan_release, "_last_merged_pull_request", lambda *a, **k: None)
    monkeypatch.setattr(
        plan_release,
        "_pull_request_by_number",
        lambda *a, **k: {
            "number": 170,
            "merged_at": "2026-05-09T06:57:47Z",
            "merge_commit_sha": "different-sha",
            "body": pr_body("feature"),
        },
    )
    event_path = write_event(
        tmp_path,
        {"head_commit": {"message": "v0.6.10: Stabilization work (#170)"}},
    )

    plan = plan_release.create_plan(event_path)

    assert plan.release_needed == "false"
    assert plan.reason == "no merged PR associated with push SHA"


def test_render_version_file_matches_expected_shape():
    rendered = sync_project_version.render_version_file("1.2.3")

    assert '__version__ = "1.2.3"' in rendered
    assert "__version_info__ = (1, 2, 3)" in rendered
    assert "def get_version() -> str:" in rendered
