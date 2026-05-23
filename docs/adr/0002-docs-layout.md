# 0002 - Documentation Layout

Status: Accepted

## Context

The repository has public MkDocs pages, GitHub-recognized root files, and
internal lifecycle documents. Duplicating the same policy across those locations
causes drift.

## Decision

`docs/` is the canonical public documentation source. Root files are short
GitHub entry points. `meta/internal/` is internal planning material and is not
the public roadmap.

## Consequences

Most long-form docs live in one place and Read the Docs can publish the complete
user-facing surface. Root and `meta/` files should link instead of duplicating.

## Related

- [Documentation ownership](../docs-layout.md)
- Issue `#151`
