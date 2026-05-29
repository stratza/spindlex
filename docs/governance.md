# Governance and Maintainer Model

SpindleX is a small production-facing open-source project. Governance should be
clear without creating support commitments that exceed maintainer capacity.

## Maintainers

Repository maintainers are listed in `pyproject.toml` and enforced for reviews
through `.github/CODEOWNERS`.

Maintainers are responsible for:

- reviewing security-sensitive changes
- maintaining release and compatibility policy
- triaging issues and pull requests
- deciding when ADRs are needed
- handling private vulnerability reports

## Decision Rules

Most changes can be decided in PR review. Use an ADR when a decision affects:

- release policy
- public API stability
- supported platforms
- security posture
- documentation ownership
- long-term maintainer workflow

## Review Expectations

- Runtime changes require tests or a documented reason tests are not practical.
- Security-sensitive changes require maintainer review.
- Release automation and workflow changes require evidence from script tests,
  actionlint, or dry-run behavior where practical.
- Public docs should link related policy pages instead of duplicating them.

## Escalation

- Security vulnerabilities use GitHub Security Advisories.
- Release failures use release-blocked issue templates and the release runbook.
- Repeated CI failures become tracked issues.
- Community moderation follows `CODE_OF_CONDUCT.md`.
