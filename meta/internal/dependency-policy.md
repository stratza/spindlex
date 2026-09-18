# Dependency Monitoring and Update Policy

## Scope

This policy covers runtime dependencies, development dependencies, documentation
tooling, and GitHub Actions.

## Runtime Dependencies

Runtime dependencies receive the highest scrutiny because they ship to users.
Runtime vulnerability fixes should include:

- advisory and affected version range
- patched version
- release impact
- evidence from unit, integration, and security checks

High or critical runtime vulnerabilities with a practical exploit path should
block release until fixed or explicitly accepted by a maintainer.

## Development and Documentation Dependencies

Development and documentation updates may be grouped when they do not affect
runtime artifacts. They still need CI evidence because docs and release tooling
are part of the public project surface.

## GitHub Actions

Actions should remain pinned by SHA in workflows. Dependabot may propose action
updates monthly. Updates require actionlint and the relevant workflow checks.

## Dependabot Cadence

Dependabot runs:

- weekly for Python dependencies
- monthly for GitHub Actions

Runtime-impacting security updates may be merged outside the normal cadence.

## Emergency Path

For high-impact security issues:

1. Confirm the dependency is reachable in supported usage.
2. Patch or constrain the dependency.
3. Run security, unit, integration, and release dry-run checks.
4. Publish a patch release if the vulnerable version is public.
5. Update the advisory or vulnerability report.
