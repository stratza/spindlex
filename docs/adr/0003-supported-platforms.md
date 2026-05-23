# 0003 - Supported Platforms

Status: Accepted

## Context

SpindleX is advertised as OS independent, but compatibility claims must match
CI, package metadata, and integration evidence.

## Decision

The v1 support target is Python `3.9` through `3.13`, matching package metadata
and CI. Linux is the primary integration platform. Windows and macOS receive
unit smoke coverage. SSH interoperability claims are limited to tested OpenSSH
and Dropbear Docker-backed integration environments unless additional canary
evidence is recorded.

## Consequences

Compatibility docs remain conservative. New compatibility reports become tests,
known incompatibility entries, or canary candidates before they become support
claims.

## Related

- [Compatibility](../compatibility.md)
