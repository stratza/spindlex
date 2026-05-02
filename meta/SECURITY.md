# Security Policy

## Supported Versions

Only the latest version of SpindleX is currently supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.6.x   | :white_check_mark: |
| < 0.6   | :x:                |

## Reporting a Vulnerability

I take the security of SpindleX seriously. If you believe you have found a security vulnerability, please report it privately.

**Please do not report security vulnerabilities via public GitHub issues.**

### Reporting Channels

You can report security vulnerabilities through the following channels:

1. **GitHub Advisory**: Use the [GitHub Security Advisory](https://github.com/stratza/spindlex/security/advisories/new) system to report vulnerabilities privately.
2. **GitHub Issue (with 'security' label)**: Only if you cannot use the advisory system. Please mark it as private if GitHub allows, or request a private reporting channel first.

### What to Include in Your Report

A good security report should include:

- A descriptive title.
- A detailed description of the vulnerability.
- Steps to reproduce the issue (including a minimal proof-of-concept if possible).
- Potential impact of the vulnerability.
- Any suggested fixes or mitigations.

## Security Practices

SpindleX follows these security principles:

- **Cryptography Dependency Model**: SpindleX uses the Python `cryptography` package for low-level primitives and implements SSH protocol behavior, negotiation, host key policy, authentication flow, and SFTP behavior around those primitives.
- **Modern Cryptography**: Prefer modern algorithms such as Ed25519, AES-CTR, and HMAC-SHA2 where supported by both client and server.
- **Secure Defaults**: Insecure algorithms and protocols are disabled by default.
- **Host Key Verification**: Unknown host keys should be rejected by default. `AutoAddPolicy` is for disposable tests and controlled development environments only.
- **Input Validation**: Rigorous validation of all protocol inputs.
- **Dependency Scanning**: Regular automated scanning for vulnerable runtime dependencies.
- **Layered Security Scanning**: CodeQL, Semgrep CE, Bandit, pip-audit, Gitleaks, Trivy, and OpenSSF Scorecard are used where appropriate.
- **Type Safety**: Use of type hints to prevent entire classes of logic errors.

## Minimal Threat Model

SpindleX is intended to protect SSH and SFTP sessions from passive observation
and active network interception when host key verification is correctly
configured. It validates SSH/SFTP protocol data and avoids known-weak defaults
where practical.

SpindleX does not protect against compromised hosts, stolen credentials,
malicious commands intentionally executed by the caller, disabled host key
verification, or vulnerabilities in the operating system, Python runtime, or
third-party cryptographic backend.

## Disclosure Policy

When a vulnerability is reported, I will:

1. Acknowledge receipt of the report within 48 hours.
2. Investigate the issue and confirm its impact.
3. Work on a fix or mitigation.
4. Provide a timeline for the fix and public disclosure.
5. Credit the reporter (unless they wish to remain anonymous).

Thank you for helping keep SpindleX secure!
