# Maintainer Release Runbook

This runbook explains the beta release flow and the target v1 activation path.

## Current Beta Flow

1. A PR targets `main` and selects exactly one change type in the template.
2. The PR gate validates metadata, code, docs, security-fast, workflows, and
   scripts.
3. After merge, release planning reads the merged PR metadata.
4. If a release is needed, compatibility, integration, property, and benchmark
   gates run sequentially to avoid unnecessary free-tier runner contention.
5. The workflow opens a protected release-version PR instead of pushing a
   version bump directly to `main`.
6. After a maintainer merges the release PR, publishing builds wheel and sdist
   artifacts, validates them, creates integrity artifacts, creates a tag and
   GitHub Release, publishes to PyPI through trusted publishing, and verifies
   install from PyPI.

## Protected Release-Version PR Flow

The release-version PR flow avoids direct version-bump commits to protected
`main`:

1. A feature/fix PR merges to `main`.
2. Release planning computes the next version.
3. A workflow opens `release/vX.Y.Z`.
4. The release PR updates `pyproject.toml` and `spindlex/_version.py`.
5. Normal PR gates run.
6. A maintainer reviews and merges the release PR.
7. Publishing runs from the protected `main` release commit.

## Dry Runs

Use workflow dispatch with `dry_run=true` to validate release planning, build,
and artifact checks without publishing.

## Fix Forward

If PyPI upload succeeds but later GitHub release steps fail, do not delete public
artifacts automatically. Verify artifact state and fix forward with a patch
release if the public package is broken.

## Failure Issues

Release failures should use the release-blocked template and include workflow
run URL, planned version, failed stage, and artifact state.

## v1 Activation Checklist

- Public API stability reviewed.
- Compatibility docs match CI and integration evidence.
- Artifact verification strategy documented and implemented at least
  non-blocking.
- Protected release-version PR flow active.
- Required checks match repository settings.
- Security and vulnerability response docs linked from README/docs.
