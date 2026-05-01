# Before `1.0.0`: Release Process Epics

These epics implement the pre-`1.0.0` release path from merged PR to PyPI.

## Epic 1: Release Planner

Goal: decide whether a merge to `main` should publish a release.

Scope:

- Trigger on `push` to `main`.
- Use only the last merged PR associated with the push SHA.
- Skip release for commits marked `[skip release]`.

Implementation tasks:

- Create or replace `release.yml`.
- Trigger on:

  ```yaml
  push:
    branches: [main]
  workflow_dispatch:
  ```

- Add release-plan job.
- Find the last merged PR associated with `github.sha`.
- Parse the PR body.
- Determine:
  - `release_needed`
  - `release_type`
  - `source_pr`
  - `source_sha`
  - `current_version`
  - `next_version`
- Use `pyproject.toml` as the current version source.
- Exit successfully with no publish when type is `docs`, `refactor`, or `test`.

Acceptance criteria:

- A docs-only merged PR exits with no release.
- A bug PR plans a patch release.
- A feature PR plans a minor release.
- A breaking PR plans a major release.
- A `[skip release]` release-bump commit does not trigger a second release.

Dependencies:

- PR template parser exists.
- Workflow has `pull-requests: read` and `contents: read`.

## Epic 2: Version Source Of Truth

Goal: make version handling deterministic.

Scope:

- `pyproject.toml` is the single source of truth.
- `spindlex/_version.py` is derived during release.

Implementation tasks:

- Implement version read from `pyproject.toml`.
- Compute next semantic version from current `pyproject.toml` version and PR
  release type.
- Update `pyproject.toml`.
- Derive `spindlex/_version.py` from the new `pyproject.toml` value.
- Update `docs/changelog.md` with release notes and migration notes where
  applicable.
- Validate:
  - `pyproject.toml` version equals runtime `spindlex.__version__`
  - tag equals version with `v` prefix
  - GitHub Release name matches tag

Acceptance criteria:

- Version cannot drift between metadata and runtime.
- Release fails before publishing if versions mismatch.
- Manual version changes outside release process are detected.

Dependencies:

- Release automation can push a version bump commit.

## Epic 3: Release Gate

Goal: prevent broken releases from reaching PyPI.

Required release gate scope:

- Ubuntu Python `3.9-3.13` unit tests.
- Integration tests.
- Build and import validation.

Optional release gate checks:

- Windows Python 3.11 smoke.
- macOS Python 3.11 smoke.
- Full security scan.
- Canary validation.
- Benchmark smoke.

Implementation tasks:

- Add release-gate job that runs only if `release_needed=true`.
- Run Ubuntu Python matrix:

  ```bash
  pytest tests -m "not integration and not real_server and not slow and not performance"
  ```

- Run integration tests:

  ```bash
  pytest tests/integration tests/real_server tests/misc/test_functional_integration.py \
    -v \
    -m "integration or real_server" \
    --tb=short \
    --timeout=120
  ```

- Run build validation:

  ```bash
  python -m build
  twine check dist/*
  ```

- Run import validation from built wheel.
- Fail release before tag creation if required gate fails.

Acceptance criteria:

- No version bump occurs before the required release gate passes.
- Release gate failure creates or updates `release-blocked`.
- Optional checks are clearly marked as blocking or non-blocking.

Dependencies:

- Matrix and integration workflows are callable or reusable.
- Issue tracking automation exists or can be deferred to failure epic.

## Epic 4: Version Bump, Tag, And GitHub Release

Goal: create immutable release coordinates safely.

Scope:

- Version bump commit.
- Annotated tag.
- GitHub Release.

Implementation tasks:

- After release gate passes, update version files and changelog.
- Commit:

  ```text
  chore(release): vX.Y.Z [skip release]
  ```

- Push the version bump to `main`.
- Create annotated tag:

  ```text
  vX.Y.Z
  ```

- Create GitHub Release from the tag.
- Include in release notes:
  - source PR number
  - source PR title
  - release type
  - summary
  - test summary
  - artifact links after upload

Idempotency rules:

- If version bump commit already exists, verify expected file contents and continue.
- If tag exists, continue only when it points to the expected commit.
- If GitHub Release exists, continue only when it matches the tag/version.

Acceptance criteria:

- Rerunning release does not create duplicate tags or releases.
- Mismatched existing tag fails hard.
- Release notes identify the source PR.

Dependencies:

- Release automation has `contents: write`.
- Protected branch permits version-bump automation.

## Epic 5: PyPI Publish And Verification

Goal: publish only verified Python package artifacts.

Scope:

- Wheel and sdist.
- Twine validation.
- PyPI trusted publishing.
- Post-release verification.

Implementation tasks:

- Build:

  ```bash
  python -m build
  twine check dist/*
  ```

- Generate SBOM where tooling is available.
- Create artifact attestations where configured.
- Publish using PyPI trusted publishing.
- Do not store `PYPI_TOKEN`.
- Verify from a clean environment:

  ```bash
  python -m venv /tmp/spindlex-verify
  source /tmp/spindlex-verify/bin/activate
  pip install spindlex==X.Y.Z
  python -c "import spindlex; assert spindlex.__version__ == 'X.Y.Z'"
  spindlex-keygen --help
  spindlex-benchmark --help
  ```

Idempotency rules:

- If PyPI version exists, do not upload again.
- If the existing PyPI artifact is valid, mark release complete.
- If the existing PyPI artifact is broken, fix forward with a new patch release.

Acceptance criteria:

- PyPI package installs successfully.
- Runtime version matches release version.
- CLI entry points are present.
- Failed publish or verification opens or updates `publish-partial`.

Dependencies:

- PyPI trusted publishing configured for repository/environment.

## Epic 6: Release Documentation

Goal: make release behavior clear for maintainers and contributors.

Implementation tasks:

- Document release mapping from PR type.
- Document no-release PR behavior.
- Document version source of truth.
- Document release gate scope.
- Document rollback and fix-forward policy.
- Document PyPI trusted publishing setup.
- Document release failure issue handling.

Acceptance criteria:

- Maintainers can diagnose release failures from docs.
- Contributors understand which PR type causes which release.
- Docs state that PyPI is immutable and broken releases are fixed forward.
