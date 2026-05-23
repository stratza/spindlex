# CI and Required Check Policy

SpindleX uses GitHub-hosted free-tier runners. Workflows should avoid consuming
unnecessary parallel capacity and should prefer sequential jobs unless parallel
fan-out is needed for compatibility evidence.

## PR Checks

The required merge check is `quality-gate`. It aggregates the PR validation
surface and is the status required by the `main-protected-pr-gate` ruleset.

The PR gate runs in phases:

1. PR metadata validation.
2. Lint, type check, unit tests, docs build, security-fast, workflow lint, and
   script compile checks.
3. Aggregate `quality-gate`.

## Advisory Checks

Scheduled security, compatibility, integration, property tests, and benchmarks
may be advisory during beta unless they are called by the release gate.

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

Workflows should use concurrency groups and avoid overlapping expensive jobs.
Where possible, release validation runs jobs one after another:

1. plan
2. compatibility matrix
3. integration
4. property tests
5. benchmark baseline
6. build and artifact verification
7. publish

Compatibility fan-out is allowed only where the matrix itself is the evidence.

## Promotion Rules

During beta, new heavy checks can start as manual or scheduled. Before v1 RC,
maintainers decide whether each check is required, advisory, or release-blocking
and update this page plus repository settings when needed.
