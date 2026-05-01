# After `1.0.0`: Operations Epics

After stable release, the lifecycle shifts from stabilization to compatibility,
support, and controlled evolution.

## Epic 1: Semantic Versioning Discipline

Goal: keep user trust after stable release.

Rules:

- Patch releases contain bug fixes, docs, and security fixes only.
- Minor releases may add backwards-compatible features.
- Major releases are required for breaking API changes.
- Breaking behavior must not be hidden in patch/minor releases.

Implementation tasks:

- Keep PR type validation.
- Require explicit maintainer review for `breaking`.
- Require migration notes for breaking changes.
- Require release notes to state compatibility impact.

Acceptance criteria:

- Users can rely on semantic versioning after `1.0.0`.

## Epic 2: Deprecation Policy

Goal: avoid surprise breakage.

Rules:

- Deprecated APIs emit warnings first.
- Docs include replacement guidance.
- Deprecations remain for at least one minor release unless security requires
  faster removal.
- Removal happens only in a major release.

Implementation tasks:

- Add deprecation section to docs.
- Add release note template section for deprecations.
- Add tests for warnings where practical.

Acceptance criteria:

- Users get warning and migration path before removal.

## Epic 3: Compatibility Operations

Goal: keep compatibility matrix current and actionable.

Implementation tasks:

- Maintain `docs/compatibility.md`.
- Track:
  - Python versions
  - OS versions
  - OpenSSH versions
  - Dropbear support
  - known incompatibilities
  - behavior differences vs Paramiko and AsyncSSH
- Convert repeated compatibility reports into tests or canaries.
- Review compatibility before each minor release.

Acceptance criteria:

- Compatibility claims are current.
- User reports improve test coverage or docs.

## Epic 4: Post-`1.0.0` Canary Expansion

Goal: catch real-world issues earlier.

Implementation tasks:

- Run canaries on schedule.
- Run canaries before important releases.
- Add additional OpenSSH versions only when value is clear.
- Add latency/network scenarios only when stable enough.
- Track canary failures through issue templates.

Acceptance criteria:

- Canary failures are visible and classified.
- Canary data informs compatibility docs.

## Epic 5: Distribution Expansion

Goal: add channels only when the core release flow is reliable.

Conda-forge:

- Start after PyPI release flow is stable.
- Submit recipe to conda-forge staged-recipes.
- Prefer `noarch: python` while package remains pure Python.
- Maintain feedstock after acceptance.

Docker Hub:

- Add only after a supported `spindlex-server` CLI exists.
- Required before official image:
  - server CLI
  - Dockerfile
  - healthcheck
  - documented env vars
  - image E2E tests
  - image scan
  - SBOM/provenance

Acceptance criteria:

- New channels do not bypass existing release trust controls.

## Epic 6: Feedback Loop Operations

Goal: turn user and pipeline feedback into product quality.

Feedback sources:

- GitHub issues.
- GitHub Discussions.
- PyPI download trends.
- GitHub traffic if available.
- CI failure issues.
- Canary failure issues.
- Compatibility reports.
- Performance reports.

Labels:

- `bug`
- `compatibility`
- `security`
- `performance`
- `docs`
- `api`
- `regression`
- `flake`

Rules:

- Repeated questions become docs.
- Repeated compatibility reports become tests or known incompatibility entries.
- Repeated performance reports become benchmarks.
- Release-blocking feedback is handled before publish when practical.

Acceptance criteria:

- Feedback is visible, categorized, and converted into maintenance work.
