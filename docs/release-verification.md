# Artifact Integrity and Release Verification

SpindleX releases should provide enough evidence for maintainers and users to
verify what was published.

## Integrity Signals

The release process should provide:

- wheel and sdist built from the release commit
- `twine check` output
- wheel import/version validation
- PyPI install verification
- annotated Git tag
- release notes linked to changelog
- SHA-256 hashes for release artifacts
- SBOM artifact where tooling is practical
- GitHub artifact attestations when available

## User Verification

Users can verify a release by:

1. Installing an exact version, for example `spindlex==0.7.0`.
2. Checking `python -c "import spindlex; print(spindlex.__version__)"`.
3. Comparing wheel or sdist hashes from the GitHub Release when published.
4. Reviewing the tag and release notes.

## Maintainer Policy

During beta, SBOM, hash, and attestation generation may start as non-blocking.
Before v1 RC, maintainers decide which integrity failures block release.

PyPI trusted publishing should remain the preferred publishing path. Long-lived
PyPI tokens should not be required for the normal release process.
