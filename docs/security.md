# Security Guide

This guide explains SpindleX security expectations, trust boundaries, and
security best practices. It is documentation for using the library safely; it is
not a claim that every SSH feature or deployment environment is risk-free.

## Security Status

SpindleX is still pre-`1.0.0` beta software. Treat it as a library under active
stabilization:

* Pin exact versions in production-facing automation.
* Review changelog entries before upgrading.
* Run your own integration tests against the SSH servers you operate.
* Keep host key verification enabled.

## Threat Model

SpindleX is designed to help applications establish SSH and SFTP sessions,
authenticate users, verify server identity, and transfer data over encrypted
transport channels.

### In Scope

* Passive network observers.
* Active network attackers attempting man-in-the-middle interception.
* Malformed SSH/SFTP protocol messages from remote peers.
* Accidental leakage of secrets through common logs.
* Vulnerable runtime dependencies.

### Out of Scope

* Compromised client or server hosts.
* Stolen private keys, passwords, or tokens.
* Malicious commands intentionally executed by the application.
* Weak host key policies chosen by the caller.
* Bugs in operating-system networking, OpenSSL, or Python runtime components.

SpindleX protects against MITM attacks only when host key verification is
correctly configured. If an application accepts unknown host keys without
verification, the SSH transport can be encrypted but the server identity is not
trusted.

## Cryptography Dependency Model

SpindleX does not implement low-level cryptographic primitives directly. It uses
the Python `cryptography` package for supported primitives and key operations.
SpindleX is responsible for SSH protocol framing, algorithm negotiation, host key
policy behavior, authentication flow, SFTP behavior, and safe defaults around
those features.

Security-sensitive changes should therefore consider both layers:

* `cryptography` version and vulnerability status.
* SpindleX protocol handling, algorithm selection, and verification logic.

Do not treat this project as a replacement for a cryptographic review of your
deployment. For high-assurance environments, review the exact algorithms,
configuration, dependencies, and server compatibility used in your system.

## Security Best Practices for Users

To ensure the highest level of security when using SpindleX, follow these best practices:

### 1. Key-Based Authentication

Always prefer public key authentication over password authentication.

*   **Use Modern Key Types**: Prefer `Ed25519` keys for new deployments. They offer better security and performance than RSA or ECDSA.
*   **Use Strong Passphrases**: Always protect your private keys with a strong passphrase.
*   **Secure File Permissions**: Ensure your private key files have restricted permissions (e.g., `chmod 600` on Unix systems).

### 2. Host Key Verification

Host key verification is critical to prevent man-in-the-middle (MITM) attacks.

*   **Avoid `AutoAddPolicy` in Production**: `AutoAddPolicy` is for disposable tests and controlled development environments only. It trusts first-seen host keys and can hide MITM attacks.
*   **Use `RejectPolicy` (Default)**: Use the default `RejectPolicy` and manage your `known_hosts` file or `HostKeyStorage` securely.
*   **Verify Host Keys**: Always verify the server's host key fingerprint before connecting for the first time.

### 3. Transport Security

*   **Set Connection Timeouts**: Use reasonable timeouts for connections and authentication to prevent resource exhaustion attacks.
*   **Monitor Connection State**: Regularly check if connections are still active and authenticated.
*   **Rekeying**: For long-running sessions, ensure rekeying is enabled (it is by default in SpindleX).

### 4. Application Security

*   **Sensitive Data**: Never hardcode passwords or private keys in your source code. Use environment variables or a secure vault.
*   **Input Sanitization**: If you are building a server that executes commands based on user input, rigorously sanitize all inputs to prevent command injection.
*   **Logging**: Be careful not to log sensitive information like passwords or private key data. SpindleX's built-in logging sanitizes most sensitive data by default.

---

## Supported Cryptographic Algorithms

SpindleX prioritizes modern, secure cryptographic algorithms and disables legacy, weak primitives by default.

### Key Exchange Algorithms

-   `curve25519-sha256@libssh.org`
-   `ecdh-sha2-nistp256`
-   `ecdh-sha2-nistp384`
-   `ecdh-sha2-nistp521`
-   `diffie-hellman-group14-sha256`
-   `diffie-hellman-group14-sha1` (Deprecated, but available)

### Encryption Ciphers

-   `aes256-ctr`
-   `aes192-ctr`
-   `aes128-ctr`

### Message Authentication Codes (MAC)

-   `hmac-sha2-512`
-   `hmac-sha2-256`
-   `hmac-sha1` (Deprecated)

### Public Key Algorithms

-   `ssh-ed25519`
-   `ecdsa-sha2-nistp256`
-   `ecdsa-sha2-nistp384`
-   `ecdsa-sha2-nistp521`
-   `ssh-rsa` (Requires SHA-2 signatures: `rsa-sha2-256`, `rsa-sha2-512`)

---

## Security Policy

For information on how to report vulnerabilities or our disclosure policy, please see our [Responsible Disclosure Policy](https://github.com/stratza/spindlex/blob/main/meta/SECURITY.md).

## Security Scanning and Blocker Policy

The repository uses layered automated checks:

* CodeQL for Python static analysis.
* Semgrep CE for Python and security-audit rules.
* Bandit for Python security patterns.
* `pip-audit` for runtime dependency vulnerabilities.
* Gitleaks for secret detection.
* Trivy for filesystem, dependency, secret, and config scanning.
* OpenSSF Scorecard for repository supply-chain posture.

PR gates block high-confidence fast findings such as Bandit failures, Semgrep
`ERROR` findings, vulnerable runtime dependencies, and committed secrets. The
full security workflow runs on `main`, on schedule, and on demand. Supported
tools upload SARIF to GitHub code scanning.

### Release-Blocking Findings

These findings block releases until fixed or explicitly accepted by a maintainer:

* Confirmed secret exposure.
* High or critical vulnerable runtime dependency with a practical exploit path.
* High-confidence CodeQL, Semgrep, Bandit, or Trivy finding in runtime code.
* Host key verification bypass or unsafe default behavior.
* Supply-chain finding that weakens release integrity.

### False Positives

Suppressions must be narrow and documented near the relevant configuration or
code. A suppression is acceptable only when the finding is understood, not
exploitable in the project context, and cheaper to document than to restructure.
Broad scanner disables are not acceptable for runtime code.

### Supported Versions

Only the latest version of SpindleX is currently supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.6.x   | :white_check_mark: |
| < 0.6   | :x:                |

### Reporting a Vulnerability

If you believe you have found a security vulnerability, please report it privately through [GitHub Security Advisories](https://github.com/stratza/spindlex/security/advisories/new).
