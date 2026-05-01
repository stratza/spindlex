# Before `1.0.0`: Quality, Security, And Trust Epics

These epics cover code quality, security scanning, trust communication, and
documentation drift enforcement before stable release.

## Epic 1: Security Workflow

Goal: provide layered security checks without relying on one scanner.

Scope:

- Keep CodeQL.
- Add practical open-source security tools.
- Split fast PR checks from scheduled full checks.

Implementation tasks:

- Keep or create `security.yml`.
- Run on PR, push to `main`, schedule, and manual dispatch.
- Add:
  - CodeQL
  - Semgrep CE
  - pip-audit or OSV Scanner
  - Gitleaks
  - Trivy filesystem/config scan
  - OpenSSF Scorecard
  - SARIF upload where supported
- Keep fast subset in `ci-pr.yml`.
- Run full scan weekly and before release where marked release-blocking.

Blocking policy:

- PR-blocking:
  - obvious secret leaks
  - high-confidence Python security findings
  - dependency vulnerabilities with direct runtime impact
- Release-blocking:
  - critical/high dependency vulnerabilities without mitigation
  - release artifact integrity failures
  - secrets or signing/provenance failures
- Advisory only:
  - low-confidence scanner noise
  - hygiene findings not affecting release safety

Acceptance criteria:

- Security workflow runs on schedule.
- Fast security failures block PRs.
- Full security results are visible in GitHub code scanning where possible.
- False positives are documented or suppressed with justification.

## Epic 2: Security And Trust Documentation

Goal: make security posture understandable to users.

Required docs:

- `docs/security.md`
- `meta/SECURITY.md`
- supported versions
- vulnerability reporting
- host key verification model
- supported algorithms
- disabled legacy algorithms
- known limitations
- dependency and release trust posture

Minimal threat model:

- Protects against passive network observation when modern SSH algorithms are
  negotiated.
- Protects against MITM only when host key verification is correctly configured.
- Does not protect users who disable verification with `AutoAddPolicy`.
- Does not replace SSH server hardening.
- Does not replace key rotation, vaulting, or OS-level controls.
- Does not claim formal verification.

Implementation tasks:

- Update security docs with cryptography dependency model.
- State that SpindleX uses `cryptography` for primitives.
- Document host key policy and unsafe test-only shortcuts.
- Document security reporting path.
- Keep beta warning until `1.0.0`.
- Add trust signals to README:
  - CI badge
  - CodeQL/security badge
  - PyPI badge
  - coverage badge
  - security policy link

Acceptance criteria:

- Users can understand the security model without reading source code.
- Docs do not overclaim cryptographic guarantees.
- Unsafe examples are not presented as production defaults.

## Epic 3: Documentation Drift Enforcement

Goal: prevent docs from contradicting package metadata and entry points.

CI must fail if:

- CLI names in documentation do not match actual entry points.
- Python version claims in documentation do not match package metadata and
  classifiers.

Implementation tasks:

- Add a drift-check script or CI step.
- Read entry points from `pyproject.toml`.
- Search docs, README, examples, and metadata for CLI names.
- Fail if docs mention obsolete commands such as `spindle-keygen` when the real
  command is `spindlex-keygen`.
- Read `requires-python` and classifiers from `pyproject.toml`.
- Search docs and README for Python support claims.
- Fail if docs claim unsupported versions such as Python `3.8+`.
- Fail if classifiers include untested versions such as Python `3.14`.

Acceptance criteria:

- CI catches CLI name drift.
- CI catches Python version drift.
- README, docs, and package metadata agree.

Dependencies:

- `pyproject.toml` remains the metadata source.

## Epic 4: Repository Drift Cleanup

Goal: remove known contradictions before `1.0.0`.

Known drift to fix:

- README says Python `3.8+`; package requires `>=3.9`.
- `pyproject.toml` has Python `3.14` classifier without official CI support.
- `.readthedocs.yaml` references missing `async` extra.
- `scripts/Makefile` uses `pflake8` and Sphinx while repo uses Ruff and MkDocs.
- `scripts/release.py` describes manual PyPI jobs that do not exist.
- Contributing docs still describe older Black/isort/flake8/tox-first flow.
- `spindle-keygen` appears in examples but actual command is `spindlex-keygen`.
- Deployment docs imply Dockerized use but no official product image exists yet.

Acceptance criteria:

- Drift list is either fixed or intentionally documented.
- CI drift check prevents recurrence.

## Epic 5: Local Tooling Alignment

Goal: make local developer checks match CI.

Implementation tasks:

- Update pre-commit to favor Ruff:
  - `ruff check --fix`
  - `ruff format`
- Keep basic hygiene hooks:
  - trailing whitespace
  - end-of-file-fixer
  - check-yaml
  - check-toml
  - check-added-large-files
- Keep Mypy in CI as authoritative.
- Add optional local hooks for:
  - gitleaks
  - shellcheck
  - actionlint

Canonical local commands:

```bash
python -m pip install -e ".[dev,docs,test]"
pre-commit install
ruff check spindlex tests
ruff format --check spindlex tests
mypy spindlex
pytest tests -m "not integration and not real_server and not slow and not performance"
mkdocs build --strict
```

Acceptance criteria:

- Contributor docs list the same commands CI runs.
- Pre-commit does not conflict with CI formatting/linting.
