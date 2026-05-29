# API Stability

This page defines the public API surface users can rely on after `1.0.0`.

## Stable Public APIs

The stable v1 surface includes documented imports from:

- `spindlex.SSHClient`
- `spindlex.AsyncSSHClient`
- `spindlex.client`
- `spindlex.hostkeys`
- `spindlex.exceptions`
- documented logging helpers from `spindlex.logging`
- documented key generation and benchmark command-line tools

The API reference pages are the authoritative list for documented public
objects.

## Command-Line Tools

`spindlex-keygen` and `spindlex-benchmark` are public CLI entry points. After
v1, option removal or incompatible output changes require deprecation or a major
release unless the option is documented as experimental.

## Exceptions

Public exception classes documented in [Exceptions](api_reference/exceptions.md)
are part of the compatibility surface. Error messages may be clarified in patch
or minor releases, but exception categories should not change incompatibly
without migration guidance.

## Provisional APIs

Server-side APIs, lower-level logging/monitoring helpers, and benchmark output
formats may change before v1 unless this page or the API reference explicitly
marks them stable.

## Internal APIs

These are not compatibility promises:

- underscore-prefixed modules, classes, functions, and attributes
- protocol packet internals
- transport state-machine internals
- crypto backend implementation details
- test helpers and scripts not exposed as project CLI entry points
- `meta/internal/` planning material

Public docs should not present internals as stable unless this page is updated
and an ADR records the decision.
