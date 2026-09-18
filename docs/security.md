# Security Guide

This guide explains SpindleX security expectations, trust boundaries, and
security best practices. It is documentation for using the library safely; it is
not a claim that every SSH feature or deployment environment is risk-free.

## Security Status

SpindleX `1.0.0` is the first stable release: the public API surface is frozen
under semantic versioning. Stable does not mean risk-free - apply the same
operational discipline you would to any security-sensitive dependency:

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

## Architecture and Trust Boundaries

**Data flow:**

1. Client code configures host keys, credentials, algorithms, and connection
   options.
2. Transport opens a TCP socket and performs SSH version exchange.
3. Key exchange negotiates KEX, host key, cipher, and MAC or AEAD behavior.
4. Host key policy verifies server identity.
5. Authentication establishes the user session.
6. Channels carry command execution, forwarding, and SFTP subsystem traffic.
7. SFTP clients and servers encode and decode file-operation messages.

**Trust boundaries:**

* Remote SSH peers are untrusted until host key verification succeeds.
* Credentials and private keys are caller-owned secrets.
* Protocol bytes from the network are untrusted input.
* `cryptography` owns low-level primitive correctness.
* SpindleX owns SSH framing, negotiation, host key policy, authentication flow,
  channel behavior, and SFTP message handling.

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

For a full reference of all supported KEX, host key, cipher, and MAC algorithms - including preference order, deprecation status, and what is explicitly not supported - see the [Algorithms](algorithms.md) page.

---

## Logging and Observability

SpindleX loggers use the `spindlex` namespace. Module loggers should remain
under that namespace so sanitizing filters and application log configuration can
target the whole library.

Important categories:

- `spindlex.*` for runtime library events
- `spindlex.security` for security-relevant events
- `spindlex.performance` for timing and throughput metrics

**Levels:**

- `ERROR`: operation failed and the caller likely needs to handle it.
- `WARNING`: degraded behavior, unsafe user configuration, retryable issue, or
  compatibility warning.
- `INFO`: lifecycle events useful during normal operations.
- `DEBUG`: protocol diagnostics and detailed troubleshooting data.

**Redaction guarantees:** sanitizers are expected to redact common passwords,
tokens, private-key blocks, and sensitive key/value fields. They are defense in
depth, not permission to log raw secrets. Avoid logging passwords, private keys,
raw authorization tokens, full known-host files, or unredacted environment
dumps.

**Safe debug fields** include algorithm names, packet/message type names, byte
counts, channel identifiers, elapsed time, and server version family when
already visible on the wire. Avoid logging full payloads, command arguments
that may contain secrets, or private filesystem paths unless the caller
explicitly controls the log.

**Debugging a production incident:**

1. Enable `DEBUG` only for the narrow process or logger needed.
2. Reproduce with sanitized logs.
3. Capture Python, SpindleX, OS, and SSH server versions.
4. Include correlation context from the application when available.
5. Remove logs after triage according to local retention policy.

Useful operational metrics include connect time, authentication time, command
latency, SFTP throughput, retry counts, error counts, and packet-level profiler
summaries when `SPINDLEX_PROFILE=1` is enabled.

---

## Security Scanning

The repository uses layered automated checks:

* CodeQL for Python static analysis.
* Semgrep CE for Python and security-audit rules.
* Bandit for Python security patterns.
* `pip-audit` for runtime dependency vulnerabilities.
* Gitleaks for secret detection.
* Trivy for filesystem, dependency, secret, and config scanning.
* OpenSSF Scorecard for repository supply-chain posture.

PR gates block high-confidence fast findings such as Bandit failures, Semgrep
`ERROR` findings, vulnerable runtime dependencies, and committed secrets.

These findings block releases until fixed or explicitly accepted by a maintainer:

* Confirmed secret exposure.
* High or critical vulnerable runtime dependency with a practical exploit path.
* High-confidence CodeQL, Semgrep, Bandit, or Trivy finding in runtime code.
* Host key verification bypass or unsafe default behavior.
* Supply-chain finding that weakens release integrity.

---

## Reporting a Vulnerability

For how to report vulnerabilities and our disclosure timeline, see the
repository [Security Policy](https://github.com/stratza/spindlex/blob/main/SECURITY.md).
