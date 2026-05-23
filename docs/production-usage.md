# Production Usage Expectations

SpindleX v1 is intended for production-facing SSH and SFTP automation when the
application owner can validate server compatibility, manage credentials safely,
and keep host key verification enabled.

## Supported Usage Patterns

- SSH command execution against known servers.
- SFTP upload, download, and directory automation against tested servers.
- Synchronous and asynchronous client workflows.
- Server-side use for controlled environments where the application owner can
  review the current server feature set.

## User Responsibilities

- Pin exact SpindleX versions in production deployments.
- Keep host key verification enabled and manage trusted host keys explicitly.
- Store credentials and private keys outside source control.
- Run integration tests against the actual SSH servers used in production.
- Review release notes before upgrading.
- Monitor compatibility notes for OpenSSH, Dropbear, and unsupported features.

## Unsupported or Out of Scope

- Treating `AutoAddPolicy` as a safe production host-key policy.
- Relying on undocumented internal modules as stable APIs.
- Using SpindleX as a complete replacement for deployment-specific security
  review.
- Expecting universal compatibility with every SSH server, appliance, or legacy
  algorithm.
- Relying on benchmark numbers without validating local network and server
  conditions.

## Production-Impacting Bugs

Maintainers treat the following as production-impacting when reproducible:

- Host key verification bypasses or unsafe defaults.
- Authentication regressions for supported key/password flows.
- SFTP data corruption, truncation, or unreported write failure.
- Protocol deadlocks, resource leaks, or unbounded malformed-input handling.
- Compatibility regressions against documented tested environments.

## Related

- [Security Guide](security.md)
- [Compatibility](compatibility.md)
- [API stability](api-stability.md)
- [Release policy](release-policy.md)
