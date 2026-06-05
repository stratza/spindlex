# CI and Required Check Policy

SpindleX uses GitHub-hosted free-tier runners. Workflows should avoid consuming
unnecessary parallel capacity. PR and release validation run through one
orchestrating workflow at a time so runners are consumed sequentially.

## PR Checks

The required merge check is `quality-gate`. It is the final status in the PR
orchestrator and is required by the `main-protected-pr-gate` ruleset.

The PR gate runs in phases:

1. PR metadata validation.
2. Lint, type check, unit tests, docs build, security-fast, workflow lint, and
   script compile checks.
3. Compatibility matrix.
4. Docker OpenSSH/Dropbear integration.
5. Bounded property tests.
6. Aggregate `quality-gate`.

Compatibility, integration, and property workflows are reusable workflows. They
do not trigger independently on PRs or `main` pushes, which prevents duplicate
runs and skipped release-only jobs from cluttering PR status.

## Advisory Checks

Scheduled security, CodeQL, compatibility, integration, property tests, and
benchmarks may be advisory during beta unless they are called by the PR or
release orchestrator. CodeQL and the full security scan are called by the
`main` push release orchestrator so post-merge code is scanned without launching
parallel workflows.

## Release-Blocking Checks

Before publishing release artifacts, these must pass:

- release planning
- compatibility matrix
- Docker OpenSSH/Dropbear integration
- distribution build and `twine check`
- wheel import/version validation
- PyPI install verification
- artifact integrity generation when promoted from advisory to blocking

## Free-Tier Runner Policy

Workflows use concurrency groups and avoid overlapping expensive jobs. Release
validation runs jobs one after another:

1. plan
2. CodeQL
3. full security scan
4. compatibility matrix
5. integration
6. property tests
7. benchmark baseline
8. build and artifact verification
9. publish

The compatibility matrix itself is also serialized: Ubuntu versions run in one
job, then Windows, then macOS.

Windows and macOS smoke jobs pin explicit GitHub-hosted runner images instead
of floating `*-latest` labels. Windows validates on `windows-2025-vs2026`, and
macOS validates on `macos-26`, so hosted-runner image migrations do not change
the tested platform silently.

GitHub's Automatic Dependency Submission workflow is repository-managed rather
than checked into `.github/workflows`. The repository-level `.python-version`
pins that dynamic workflow to Python `3.11`, matching the primary CI and
release tooling version.

## Promotion Rules

During beta, new heavy checks can start as manual or scheduled. Before v1 RC,
maintainers decide whether each check is required, advisory, or release-blocking
and update this page plus repository settings when needed.
