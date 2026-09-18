# Compatibility & API Stability

This page defines the supported and tested environments for SpindleX, what
usage patterns are supported in production, and the public API surface users
can rely on after `1.0.0`.

## Python Versions

SpindleX supports Python `3.9` through `3.13`.

This matches package metadata and the Linux compatibility matrix. Python `3.11`
is the primary CI and release tooling version.

## Operating Systems

SpindleX is intended to be OS independent at the library layer.

| Platform | Current validation |
| --- | --- |
| Linux | full unit matrix and Docker-backed SSH/SFTP integration |
| macOS | Python 3.11 unit smoke coverage on `macos-26` |
| Windows | Python 3.11 unit smoke coverage on `windows-2025-vs2026` |

OS independent does not mean every operating-system SSH setup is validated. It
means the runtime library avoids platform-specific assumptions where practical.

## SSH Server Compatibility

Current integration validation uses Docker-backed OpenSSH and Dropbear services.
Compatibility claims should name the server family and version or image when
recorded.

Known-compatible reports should include:

- SpindleX version
- Python version
- operating system
- server family and version
- authentication method
- affected API or CLI
- minimal reproduction or confirming test

## Unsupported Features and Known Incompatibilities

Use this format for known incompatibilities:

```text
Server/version:
Affected SpindleX version:
Feature:
Symptom:
Workaround:
Tracking issue:
Validation needed:
```

Current unsupported or limited areas:

- universal compatibility with legacy or appliance-specific SSH behavior
- production use of unknown-host auto-acceptance policies
- unsupported or disabled legacy algorithms listed in [Algorithms](algorithms.md)

Repeated compatibility reports should become one of: a regression test, a
Docker or canary validation target, a known incompatibility entry, or an
update to the public support boundary.

---

## Supported and Unsupported Usage

SpindleX v1 is intended for production-facing SSH and SFTP automation when the
application owner can validate server compatibility, manage credentials safely,
and keep host key verification enabled.

**Supported usage patterns:**

- SSH command execution against known servers.
- SFTP upload, download, and directory automation against tested servers.
- Synchronous and asynchronous client workflows.
- Server-side use for controlled environments where the application owner can
  review the current server feature set.

**Unsupported or out of scope:**

- Treating `AutoAddPolicy` as a safe production host-key policy.
- Relying on undocumented internal modules as stable APIs.
- Using SpindleX as a complete replacement for deployment-specific security
  review.
- Expecting universal compatibility with every SSH server, appliance, or legacy
  algorithm.
- Relying on benchmark numbers without validating local network and server
  conditions.

See the [Security Guide](security.md) for the operational practices (version
pinning, host key verification, credential handling) expected of production
deployments.

---

## API Stability

The stable v1 surface includes documented imports from:

- `spindlex.SSHClient`
- `spindlex.AsyncSSHClient`
- `spindlex.client`
- `spindlex.hostkeys`
- `spindlex.exceptions`
- documented logging helpers from `spindlex.logging`
- documented key generation and benchmark command-line tools

The [API reference](api_reference/index.md) pages are the authoritative list
for documented public objects.

**Command-line tools:** `spindlex-keygen` and `spindlex-benchmark` are public
CLI entry points. After v1, option removal or incompatible output changes
require deprecation or a major release unless the option is documented as
experimental.

**Exceptions:** public exception classes documented in
[Exceptions](api_reference/exceptions.md) are part of the compatibility
surface. Error messages may be clarified in patch or minor releases, but
exception categories should not change incompatibly without migration
guidance.

**Provisional APIs:** server-side APIs, lower-level logging/monitoring
helpers, and benchmark output formats may change before this page explicitly
marks them stable.

**Internal APIs** are not compatibility promises:

- underscore-prefixed modules, classes, functions, and attributes
- protocol packet internals
- transport state-machine internals
- crypto backend implementation details
- test helpers and scripts not exposed as project CLI entry points
- `meta/internal/` planning material
