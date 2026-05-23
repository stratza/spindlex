# 0004 - API Stability Boundaries

Status: Accepted

## Context

SpindleX exposes user-facing clients, servers, host-key helpers, exceptions,
logging helpers, and command-line tools. It also contains protocol, transport,
and crypto internals that must remain changeable while the implementation
stabilizes.

## Decision

The documented APIs under [API stability](../api-stability.md) are the v1
compatibility surface. Underscore-prefixed modules, undocumented internals, test
helpers, and protocol implementation details are not stable unless a public doc
explicitly says otherwise.

## Consequences

Users can rely on documented public imports and command-line tools after v1.
Maintainers can continue to improve internals without treating every import path
as part of the compatibility contract.

## Related

- [API stability](../api-stability.md)
- Issue `#155`
