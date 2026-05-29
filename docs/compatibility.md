# Compatibility

This page defines the supported and tested environments for SpindleX v1
planning.

## Python Versions

SpindleX supports Python `3.9` through `3.13`.

This matches package metadata and the Linux compatibility matrix. Python `3.11`
is the primary CI and release tooling version.

## Operating Systems

SpindleX is intended to be OS independent at the library layer.

| Platform | Current validation |
| --- | --- |
| Linux | full unit matrix and Docker-backed SSH/SFTP integration |
| macOS | Python 3.11 unit smoke coverage |
| Windows | Python 3.11 unit smoke coverage |

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

## Report Handling

Repeated compatibility reports should become one of:

- a regression test
- a Docker or canary validation target
- a known incompatibility entry
- an update to the public support boundary
