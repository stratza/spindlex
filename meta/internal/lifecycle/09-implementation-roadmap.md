# Lifecycle Implementation Roadmap

This roadmap orders the epics so work can be implemented safely.

## Phase 0: Current Beta Cleanup

Goal: remove contradictions before adding more automation.

Epics:

- Repository drift cleanup.
- Documentation drift enforcement design.
- PR template parse-token update.
- Contributor docs alignment.

Tasks:

- Fix README Python version claim.
- Remove or validate unsupported Python classifiers.
- Fix `.readthedocs.yaml` missing `async` extra.
- Replace legacy script-level development commands with canonical root commands.
- Retire the legacy manual release helper.
- Replace stale CLI command names with actual entry points.
- Update contributing docs with canonical local commands.

Done when:

- Docs, CLI names, and package metadata agree.
- Drift check requirements are known.

## Phase 1: PR Gates

Goal: make PRs safe before merge.

Epics:

- Protected trunk-based development.
- PR template as lifecycle interface.
- Fast PR quality gate.

Tasks:

- Add PR body validation.
- Add `ci-pr.yml`.
- Add aggregate `quality-gate`.
- Configure branch protection.
- Confirm PR template auto-fills on new PRs.

Done when:

- Invalid PR type fails.
- Failed PR gate blocks merge.
- Maintainers can merge only after required checks pass.

## Phase 2: Matrix And Integration

Goal: split fast PR checks from deeper confidence checks.

Epics:

- Compatibility matrix before release.
- Integration and real protocol coverage.

Tasks:

- Add `ci-matrix.yml`.
- Add `integration.yml`.
- Add path filters.
- Add Docker timeouts.
- Add scheduled confidence runs.

Done when:

- Runtime-code changes get compatibility checks.
- Docker OpenSSH/Dropbear integration works in CI.
- Release gate can call or reproduce the required checks.

## Phase 3: Security And Trust

Goal: build a credible security posture.

Epics:

- Security workflow.
- Security and trust documentation.
- Local tooling alignment.

Tasks:

- Keep CodeQL.
- Add Semgrep, pip-audit/OSV, Gitleaks, Trivy, Scorecard.
- Upload SARIF where supported.
- Add security blocker policy.
- Update security docs and threat model.

Done when:

- Fast security blocks obvious PR issues.
- Full security runs on schedule.
- Security docs explain trust boundaries.

## Phase 4: Release Automation

Goal: safely publish PyPI releases from merged PRs.

Epics:

- Release planner.
- Version source of truth.
- Release gate.
- Version bump, tag, and GitHub Release.
- PyPI publish and verification.
- Release documentation.

Tasks:

- Add `release.yml`.
- Find last merged PR for push SHA.
- Parse release type.
- Compute next version from `pyproject.toml`.
- Derive `spindlex/_version.py`.
- Add release gate.
- Add version bump commit.
- Add tag and GitHub Release creation.
- Add build, `twine check`, PyPI publish.
- Add post-release verification.

Done when:

- Bug PR creates patch release.
- Feature PR creates minor release.
- Breaking PR creates major release.
- Docs/refactor/test PRs do not release.
- Rerun does not duplicate tag/release.

## Phase 5: Failure Tracking

Goal: make post-merge and release failures visible without creating noise.

Epics:

- Failure issue templates.
- Deduplicated issue create/update.
- Flaky pipeline close policy.

Tasks:

- Add CI/release issue templates.
- Add failure key calculation.
- Add issue search/update/create logic.
- Add workflow summaries.
- Add close conditions.

Done when:

- Release gate failure opens or updates one issue.
- Repeated flaky failures are tracked.
- One-off PR failures do not create issues.

## Phase 6: Product Readiness Before `1.0.0`

Goal: make the project usable and trustworthy.

Epics:

- Developer experience.
- Documentation strategy.
- Compatibility strategy.
- Canary and real usage validation.
- Benchmark and performance validation.
- Distribution and adoption.

Tasks:

- Add compatibility docs.
- Add canary runbook and fallback policy.
- Add benchmark entry point docs:

  ```bash
  spindlex-benchmark --scenario basic --output results.json
  ```

- Add performance methodology.
- Add comparison page.
- Add migration guide.
- Add security threat model.
- Add production-readiness checklist.

Done when:

- Users can install, connect, transfer files, handle errors, and understand
  security from docs.
- Maintainers can run benchmark and canary flows.

## Phase 7: `1.0.0` Release Candidate

Goal: cut stable release only after the lifecycle and product contract are ready.

Tasks:

- Run full release gate.
- Run canary validation or approve fallback.
- Run benchmark baseline.
- Freeze public API unless critical fixes are required.
- Publish `0.x -> 1.0` migration guide.
- Publish compatibility matrix.
- Publish known limitations.
- Cut `1.0.0`.

Done when:

- `1.0.0` installs from PyPI.
- Runtime version equals `1.0.0`.
- Release notes and migration docs are published.

## Phase 8: After `1.0.0`

Goal: operate the project as a stable open-source library.

Epics:

- Semantic versioning discipline.
- Deprecation policy.
- Compatibility operations.
- Canary expansion.
- Distribution expansion.
- Feedback loop operations.

Tasks:

- Enforce semantic versioning.
- Maintain compatibility matrix.
- Add conda-forge after PyPI flow is stable.
- Add Docker Hub only after supported server CLI exists.
- Convert repeated user reports into docs, tests, compatibility entries, or
  benchmarks.

Done when:

- Stable users can upgrade predictably.
- New distribution channels do not weaken release trust.
