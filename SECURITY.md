# Security Policy

## Supported Versions

Only the latest version of SpindleX is currently supported for security updates.

| Version | Supported |
| ------- | --------- |
| 0.7.x   | Yes       |
| 0.6.x   | No        |
| < 0.6   | No        |

## Reporting a Vulnerability

Please report suspected vulnerabilities privately. Do not report security
vulnerabilities through public GitHub issues.

Use GitHub Security Advisories:

https://github.com/stratza/spindlex/security/advisories/new

If GitHub Security Advisories are unavailable to you, open a minimal public
issue requesting a private security contact and do not include exploit details
in that issue.

Maintainer triage, severity, embargo, advisory, CVE, and patch-release handling
are documented in [docs/vulnerability-response.md](docs/vulnerability-response.md).

## What to Include

A useful report should include:

- A descriptive title.
- Affected SpindleX version, Python version, and operating system.
- A clear description of the vulnerability.
- Steps to reproduce, including a minimal proof of concept if possible.
- Expected impact, affected APIs, and required attacker capabilities.
- Any known mitigations or suggested fixes.

## Disclosure Timeline

When a vulnerability is reported, maintainers aim to:

1. Acknowledge receipt within 48 hours.
2. Confirm scope and severity after reproducing the report.
3. Share an expected fix timeline with the reporter.
4. Prepare a patch release for supported versions when the issue is confirmed.
5. Publish advisory details after a fix is available, unless coordinated
   disclosure requires a different timeline.

## Security Practices

SpindleX follows these security principles:

- **Cryptography dependency model**: SpindleX uses the Python `cryptography`
  package for low-level primitives and implements SSH protocol behavior,
  negotiation, host key policy, authentication flow, and SFTP behavior around
  those primitives.
- **Modern cryptography**: Prefer modern algorithms such as Ed25519, AES-CTR,
  and HMAC-SHA2 where supported by both client and server.
- **Secure defaults**: Insecure algorithms and protocols are disabled by
  default.
- **Host key verification**: Unknown host keys should be rejected by default.
  `AutoAddPolicy` is for disposable tests and controlled development
  environments only.
- **Input validation**: Protocol inputs are validated before use.
- **Dependency scanning**: Runtime dependencies are scanned for known
  vulnerabilities and license policy issues.
- **Layered security scanning**: CodeQL, Semgrep CE, Bandit, pip-audit,
  Gitleaks, Trivy, and OpenSSF Scorecard are used where appropriate.
- **Type safety**: Type hints and static checks are used to prevent classes of
  logic errors.

The broader security model and trust boundaries are documented in
[docs/security.md](docs/security.md) and
[docs/architecture-security.md](docs/architecture-security.md).

## Minimal Threat Model

SpindleX is intended to protect SSH and SFTP sessions from passive observation
and active network interception when host key verification is correctly
configured. It validates SSH/SFTP protocol data and avoids known-weak defaults
where practical.

SpindleX does not protect against compromised hosts, stolen credentials,
malicious commands intentionally executed by the caller, disabled host key
verification, vulnerabilities in the operating system, vulnerabilities in the
Python runtime, or vulnerabilities in third-party cryptographic backends.

Thank you for helping keep SpindleX secure.
