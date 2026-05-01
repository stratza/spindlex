# Before `1.0.0`: Lifecycle Epics

These epics must be completed before SpindleX can reasonably claim a stable
`1.0.0` lifecycle.

## Epic 1: Protected Trunk-Based Development

Goal: make `main` the only long-term integration branch and protect it with PR
gates.

Scope:

- Use feature branches for all development.
- Open PRs into `main`.
- Require CI before merge.
- Keep `dev` temporary only while implementing lifecycle changes.

Implementation tasks:

- Configure branch protection for `main`.
- Require pull request before merge.
- Require conversation resolution.
- Disable direct human pushes.
- Prefer squash merge.
- Add required status checks:
  - `pr-validate`
  - `ruff`
  - `mypy`
  - `unit-tests`
  - `docs-build`
  - `security-fast`
  - `quality-gate`
- Decide whether "branch must be up to date" is enabled after CI stability is
  proven.
- Document the branch flow in contributing docs.

Acceptance criteria:

- A direct push to `main` is blocked for normal users.
- A PR with failing required checks cannot merge.
- A PR with unresolved conversations cannot merge.
- Developers can follow docs from branch creation to merge.

Dependencies:

- `ci-pr.yml` exists.
- PR validation exists.
- Maintainers have admin/bypass path for emergency recovery.

## Epic 2: PR Template As Lifecycle Interface

Goal: make PR body data reliable enough for release automation.

Scope:

- `.github/pull_request_template.md` remains the default PR template.
- CI validates the body because GitHub only pre-fills; it does not enforce.
- `Type of Change` controls release behavior.

Implementation tasks:

- Update the PR template to include stable parse tokens:

  ```md
  ## Type of Change

  - [ ] bug
  - [ ] feature
  - [ ] breaking
  - [ ] docs
  - [ ] refactor
  - [ ] test
  ```

- Keep human-readable explanations near the checkbox list.
- Add a PR validation script or workflow step.
- Fail validation if zero type boxes are selected.
- Fail validation if more than one type box is selected.
- Fail validation if description is empty or still placeholder-only.
- For `bug`, `feature`, and `breaking`, require test evidence.
- Output parsed values:
  - `change_type`
  - `release_needed`
  - `release_type`

Acceptance criteria:

- New PRs show the template automatically.
- Invalid PR type selection fails CI.
- Valid no-release PRs pass validation.
- Valid release-impact PRs expose release metadata for downstream jobs.

Dependencies:

- Default branch contains `.github/pull_request_template.md`.
- Workflow has `pull-requests: read` permission.

## Epic 3: Fast PR Quality Gate

Goal: keep the required pre-merge path fast, deterministic, and useful.

Scope:

- Required on every PR to `main`.
- Covers code quality, type safety, unit behavior, docs build, and fast security.
- Does not run every expensive matrix job for docs-only changes.

Implementation tasks:

- Create `ci-pr.yml`.
- Trigger on:

  ```yaml
  pull_request:
    branches: [main]
    types: [opened, synchronize, reopened, edited, ready_for_review]
  ```

- Add concurrency:

  ```yaml
  concurrency:
    group: ci-pr-${{ github.event.pull_request.number }}
    cancel-in-progress: true
  ```

- Add jobs:
  - `pr-validate`
  - `ruff`
  - `mypy`
  - `unit-tests`
  - `docs-build`
  - `security-fast`
  - `workflow-lint`
  - `script-lint`
  - `quality-gate`

Required commands:

```bash
ruff check spindlex tests
ruff format --check spindlex tests
mypy spindlex
pytest tests -m "not integration and not real_server and not slow and not performance"
mkdocs build --strict
bandit -r spindlex -c pyproject.toml
pip-audit
gitleaks detect --source . --no-git
```

Acceptance criteria:

- PRs receive a single required aggregate gate.
- Failed lint/type/unit/docs/security-fast blocks merge.
- Workflow/script lint runs only on relevant path changes.
- No job rewrites files in CI.

Dependencies:

- Dev dependencies install successfully on Python 3.11.
- Security tools are installed by workflow or preinstalled in CI.

## Epic 4: Compatibility Matrix Before Release

Goal: verify supported Python and OS behavior without making every PR slow.

Scope:

- Official pre-`1.0.0` Python support: `3.9-3.13`.
- Python `3.9` is legacy support because it is upstream EOL.
- Python `3.14` is not official until CI tests it.

Implementation tasks:

- Create `ci-matrix.yml`.
- Run on runtime-code PRs, push to `main`, nightly schedule, manual dispatch,
  and release gate.
- Use matrix:
  - Python: `3.9`, `3.10`, `3.11`, `3.12`, `3.13`
  - OS: `ubuntu-latest`, `windows-latest`, `macos-15-intel`
- Run no-Docker unit tests:

  ```bash
  pytest tests -m "not integration and not real_server and not slow and not performance"
  ```

- Use path filters so docs-only PRs skip full matrix.
- Require Ubuntu Python `3.9-3.13` before release.
- Use Windows/macOS Python 3.11 smoke in release gate.

Acceptance criteria:

- Runtime-code changes receive compatibility signal.
- Full matrix runs on schedule.
- Release gate includes the required compatibility subset.
- Python support claims match the matrix.

Dependencies:

- Package installs on all supported Python versions.
- Tests do not assume Linux-only paths unless guarded.

## Epic 5: Integration And Real Protocol Coverage

Goal: validate actual SSH/SFTP behavior against real daemons.

Scope:

- Docker OpenSSH and Dropbear integration remain the baseline.
- Canary real-host validation is added as a pre-`1.0.0` readiness layer.

Implementation tasks:

- Create `integration.yml`.
- Use existing `tests/integration/docker-compose.yml`.
- Run:

  ```bash
  pytest tests/integration tests/real_server tests/misc/test_functional_integration.py \
    -v \
    -m "integration or real_server" \
    --tb=short \
    --timeout=120 \
    --cov=spindlex \
    --cov-report=xml
  ```

- Set job timeout to `20` minutes.
- Install `pytest-docker` and `pytest-timeout`.
- Do not auto-retry assertion failures.
- Allow maintainer rerun for Docker pull or runner network failures.

Acceptance criteria:

- OpenSSH and Dropbear tests run in CI.
- Integration jobs are timeout-protected.
- Release gate includes integration tests.
- Failure classification distinguishes test failures from infra failures.

Dependencies:

- Docker is available on GitHub Linux runner.
- Integration tests are stable enough for release gating.
