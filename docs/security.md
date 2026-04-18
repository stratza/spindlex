# Security Guide

This guide provides security best practices for using SpindleX and information about our security policy.

## Security Best Practices for Users

To ensure the highest level of security when using SpindleX, follow these best practices:

### 1. Key-Based Authentication

Always prefer public key authentication over password authentication.

*   **Use Modern Key Types**: Prefer `Ed25519` keys for new deployments. They offer better security and performance than RSA or ECDSA.
*   **Use Strong Passphrases**: Always protect your private keys with a strong passphrase.
*   **Secure File Permissions**: Ensure your private key files have restricted permissions (e.g., `chmod 600` on Unix systems).

### 2. Host Key Verification

Host key verification is critical to prevent man-in-the-middle (MITM) attacks.

*   **Avoid `AutoAddPolicy` in Production**: While convenient for testing, `AutoAddPolicy` automatically accepts any host key, making you vulnerable to MITM attacks.
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

## Security Policy

For information on how to report vulnerabilities or our disclosure policy, please see our [Responsible Disclosure Policy](https://github.com/Di3Z1E/spindlex/blob/main/meta/SECURITY.md).

### Supported Versions

Only the latest version of SpindleX is currently supported for security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.5.x   | :white_check_mark: |
| < 0.5   | :x:                |

### Reporting a Vulnerability

If you believe you have found a security vulnerability, please report it privately through [GitHub Security Advisories](https://github.com/Di3Z1E/spindlex/security/advisories/new).
