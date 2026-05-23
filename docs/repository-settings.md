# Repository Settings Checklist

Some GitHub settings cannot be fully represented in source control. Maintainers
should keep this checklist aligned with repository reality before v1.

## Current Repository State

Last audited for the v1 readiness work:

- default branch: `main`
- issues: enabled
- discussions: enabled
- wiki: disabled
- security policy: enabled
- homepage URL: `https://spindlex.readthedocs.io/`
- branch protection API: no classic branch protection
- ruleset: active `main-protected-pr-gate`
- required check: `quality-gate`
- CODEOWNERS review: required
- resolved review threads: required
- linear history: required
- merge methods: squash and rebase
- GitHub Actions: enabled, allowed actions set to all
- SHA pinning enforcement: disabled
- Dependabot alerts: enabled
- secret scanning: enabled
- environments: none

## Expected v1 Settings

- Keep `main-protected-pr-gate` active.
- Keep `quality-gate` required for merge.
- Keep CODEOWNERS review required.
- Keep wiki disabled so public docs live in MkDocs.
- Keep repository homepage set to the Read the Docs URL.
- Keep secret scanning enabled.
- Keep private vulnerability reporting enabled.
- Define release environments if PyPI trusted publishing requires environment
  protection.
- Keep Actions pinned by SHA in source even if repository-level enforcement is
  unavailable.

## Manual Follow-Up

When a setting cannot be changed in a PR, record the expected value here and
confirm it in the relevant maintainer checklist before closing the work.
