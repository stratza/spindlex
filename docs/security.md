# Security Guidelines

SpindleX is designed with security as a primary concern. This document outlines security best practices and guidelines for using the library safely.

## Secure Defaults

SpindleX uses secure defaults to protect against common security issues:

*   **:shield: Modern Cryptography**: Defaults to Ed25519 keys and ChaCha20-Poly1305 encryption.
*   **:link: Strong Key Exchange**: Uses Curve25519 and ECDH key exchange algorithms.
*   **:no_entry: Host Key Verification**: Requires explicit host key policies (`RejectPolicy`, `WarningPolicy`, or `AutoAddPolicy`).
*   **:game_die: Secure Random**: Uses cryptographically secure random number generation.

## Authentication Security

### Key-Based Authentication

Always prefer key-based authentication over passwords. You can use the built-in `spindlex-keygen` tool to generate modern cryptographic keys:

```bash
spindlex-keygen -t ed25519 -f my_key
```

To use keys in your code:

```python
from spindlex import SSHClient
from spindlex.crypto.pkey import load_key_from_file

# Load key securely
private_key = load_key_from_file('/path/to/key', password='strong_passphrase')

# Use for authentication
with SSHClient() as client:
    client.connect(hostname='server.com', username='user', pkey=private_key)
```

## Host Key Verification

### Strict Host Key Checking

Always verify host keys in production using `RejectPolicy`:

```python
from spindlex import SSHClient
from spindlex.hostkeys.policy import RejectPolicy
from spindlex.exceptions import BadHostKeyException

with SSHClient() as client:
    # Reject unknown host keys (secure default)
    client.set_missing_host_key_policy(RejectPolicy())
    
    try:
        client.connect(hostname='server.com', username='user', pkey=key)
    except BadHostKeyException:
        print("Host key verification failed! Connection aborted.")
```

## Network Security

### Connection Security

Use secure connection practices:

```python
from spindlex import SSHClient

with SSHClient() as client:
    # Set reasonable timeouts
    client.connect(
        hostname='server.com',
        username='user',
        pkey=private_key,
        timeout=30
    )
```

## Data Protection

### Log Security

Sanitize logs to prevent information leakage. SpindleX includes built-in log sanitizers to ensure that credentials and sensitive protocol data never reach your logs.

## Best Practices Summary

1.  **Use key-based authentication** whenever possible.
2.  **Implement strict host key verification** in production.
3.  **Use modern algorithms** like Ed25519 and ChaCha20-Poly1305.
4.  **Regularly rotate keys** and monitor connection logs.
5.  **Set appropriate timeouts** for all network operations.
