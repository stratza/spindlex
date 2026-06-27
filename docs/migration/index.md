# Migration Guides

This section covers what you need to change when upgrading SpindleX across major
version boundaries.

## Available Guides

- [0.x to 1.0](0.x-to-1.0.md) — upgrading from any 0.x beta release to the
  stable v1.0.0 release.

## General Upgrade Advice

- Pin to an exact version in production (`spindlex==1.0.0`, not `>=1.0.0`).
- Read the relevant migration guide before upgrading.
- Run your integration tests against your actual SSH servers after upgrading.
- Check the [Changelog](../changelog.md) for the full list of changes between
  your current version and the target.
- Review the [Compatibility](../compatibility.md) page for any known
  incompatibilities with the SSH server you connect to.
