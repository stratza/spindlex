# Security Guidelines

> **Canonical document:** [meta/SECURITY.md](../meta/SECURITY.md)

For the full security policy — including supported versions, vulnerability reporting, security practices, and the disclosure policy — please refer to the canonical file linked above.

---

## Quick Reference: Best Practices

1.  **Use key-based authentication** whenever possible.
2.  **Implement strict host key verification** in production (`RejectPolicy`).
3.  **Use modern algorithms** like Ed25519 and AES-256-CTR with HMAC-SHA2.
4.  **Regularly rotate keys** and monitor connection logs.
5.  **Set appropriate timeouts** for all network operations.
6.  **Report vulnerabilities** via [GitHub Security Advisory](https://github.com/Di3Z1E/spindlex/security/advisories/new).
