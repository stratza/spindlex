# Documentation Ownership

This page defines where public, GitHub-facing, and internal project material
lives.

## Canonical Public Documentation

`docs/` is the canonical public documentation source. Pages under `docs/` are
published by MkDocs and Read the Docs, and should be the destination for long
form user, contributor, compatibility, security, release, and maintainer
guidance.

When content belongs in public docs, update `docs/` first and link to that page
from other entry points.

## GitHub Entry Points

Root files exist because GitHub and packaging tools recognize them:

- `README.md` introduces the project and links to maintained docs.
- `SECURITY.md` provides the private vulnerability reporting path.
- `CONTRIBUTING.md` points contributors to the maintained guide.
- `CODE_OF_CONDUCT.md` defines community conduct expectations.
- `SUPPORT.md` points users to support, compatibility, and security guidance.

Root files should stay short unless GitHub needs the content directly.

## Internal Planning

`meta/internal/` contains planning material, lifecycle notes, and internal
roadmaps. It is useful maintainer context, but it is not the public roadmap or a
user-facing compatibility promise.

`meta/` files outside `meta/internal/` are compatibility pointers for old links.
They should not duplicate maintained public guidance.

## Change Rule

If two pages appear to conflict, the public page under `docs/` wins unless the
root file is a GitHub-specific policy entry point such as `SECURITY.md`.
