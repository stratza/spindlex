# Versioning, Deprecation, and Support Policy

## Before 1.0.0 (historical)

During the `0.x` beta line, compatibility-affecting changes were allowed when
needed for protocol correctness, security, or v1 readiness.

PR type metadata controlled beta release planning:

| PR type | Beta release behavior |
| --- | --- |
| `bug` | patch release |
| `feature` | patch release |
| `feature-minor` | minor release |
| `breaking` | minor release |
| `docs` | no release |
| `refactor` | no release |
| `test` | no release |

## After 1.0.0

SpindleX follows SemVer:

- Patch releases fix bugs, security issues, documentation drift, and compatible
  behavior defects.
- Minor releases add compatible functionality and may introduce deprecations.
- Major releases are required for breaking changes to the stable public API.

## Support Window

The default support policy is latest stable minor only. Security fixes target
the latest supported release unless maintainers explicitly announce an extended
support window.

## Deprecation Expectations

Deprecations should include:

- the affected API or behavior
- the replacement path
- release-note coverage
- migration guidance when the change is user visible

## Release Notes

Release notes should call out compatibility, security, and performance impact
when relevant. Material `0.x -> 1.0` changes require migration notes before the
stable release.

## Related

- [Release runbook](release-runbook.md)
- [API stability](api-stability.md)
- [ADR 0001](adr/0001-release-policy.md)
