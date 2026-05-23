# 0001 - Release Policy

Status: Accepted

## Context

SpindleX is pre-`1.0.0` and uses PR metadata to decide whether a merge should
produce a beta release. After `1.0.0`, users need a stable SemVer contract and
maintainers need a release process that works without direct commits to
protected `main`.

## Decision

Before `1.0.0`, PR type checkboxes continue to drive beta release planning:
`bug` and `feature` produce patch releases, `feature-minor` and `breaking`
produce minor releases, and `docs`, `refactor`, and `test` produce no release.

Before stable release, version bumps move into a protected release-version PR.
The release PR carries the `pyproject.toml` and `spindlex/_version.py` changes,
runs normal PR gates, and is reviewed before publishing from `main`.

After `1.0.0`, SpindleX follows SemVer. Breaking changes require a major
release unless they are explicitly outside the documented stable API boundary.

## Consequences

Release behavior stays fast during beta, but the stable release path has normal
review and required checks. Contributors must keep PR type metadata accurate
because it controls release planning.

## Related

- [Release policy](../release-policy.md)
- [Release runbook](../release-runbook.md)
- [Artifact verification](../release-verification.md)
