# Authentication Guide

SpindleX supports multiple authentication methods to provide secure access to remote systems. This guide covers all supported authentication methods and best practices.

## Supported Authentication Methods

1.  **:key: Public Key Authentication** (Recommended)
2.  **:lock: Password Authentication**
3.  **:shield: GSSAPI/Kerberos Authentication**
4.  **:keyboard: Keyboard-Interactive Authentication**

## Public Key Authentication

Public key authentication is the most secure method and is recommended for production use.

### Key Generation

SpindleX includes a dedicated CLI tool, `spindlex-keygen`, for generating modern cryptographic keys:

```bash
spindlex-keygen -t ed25519 -f ~/.ssh/id_ed25519_spindlex
```

### Loading Existing Keys

Load private keys from files using the utility functions in `spindlex.crypto.pkey`:

```python
from spindlex.crypto.pkey import load_key_from_file

# Load key with passphrase
private_key = load_key_from_file(
    '/path/to/private_key',
    password='passphrase'
)
```

### Using Keys for Authentication

=== "Sync"

    ```python
    from spindlex import SSHClient
    from spindlex.crypto.pkey import load_key_from_file

    private_key = load_key_from_file('/path/to/key')

    with SSHClient() as client:
        client.connect(
            hostname='server.example.com',
            username='user',
            pkey=private_key
        )
    ```

=== "Async"

    ```python
    from spindlex import AsyncSSHClient
    from spindlex.crypto.pkey import load_key_from_file

    private_key = load_key_from_file('/path/to/key')

    async with AsyncSSHClient() as client:
        await client.connect(
            hostname='server.example.com',
            username='user',
            pkey=private_key
        )
    ```

## Password Authentication

### Basic Password Authentication

```python
from spindlex import SSHClient
import getpass

# Get password securely
password = getpass.getpass("Enter SSH password: ")

with SSHClient() as client:
    client.connect(
        hostname='server.example.com',
        username='user',
        password=password
    )
```

## GSSAPI/Kerberos Authentication

GSSAPI authentication provides single sign-on capabilities in Kerberos environments. This is fully supported in the asynchronous client.

### Async GSSAPI Authentication

```python
from spindlex import AsyncSSHClient

async def connect_gssapi():
    async with AsyncSSHClient() as client:
        await client.connect(
            hostname='server.example.com',
            username='user',
            gss_auth=True,          # Enable GSSAPI authentication
            gss_host='server.example.com', # Target service name
            gss_deleg_creds=True    # Delegate credentials if needed
        )
```

## Keyboard-Interactive Authentication

Keyboard-interactive authentication is used when the server requires the user to respond to one or more prompts. This is common for multi-factor authentication (MFA).

=== "Sync"

    ```python
    from spindlex import SSHClient

    with SSHClient() as client:
        client.connect(
            hostname="server.example.com",
            username="user"
        )
        # If handler is omitted, SpindleX uses a default terminal-based handler
        client.auth_keyboard_interactive("user")
    ```

    You can also provide a custom handler for more complex scenarios:

    ```python
    def my_handler(title, instruction, prompts):
        responses = []
        for prompt, echo in prompts:
            responses.append(input(prompt) if echo else getpass.getpass(prompt))
        return responses

    client.auth_keyboard_interactive("user", my_handler)
    ```

=== "Async"

    ```python
    from spindlex import AsyncSSHClient

    async def main():
        async with AsyncSSHClient() as client:
            await client.connect(
                hostname="server.example.com",
                username="user"
            )
            # Both sync and async handlers are supported
            await client.auth_keyboard_interactive("user")
    ```

## Security Best Practices

### Key Management

1.  **Use Ed25519 keys** for new deployments.
2.  **Use strong passphrases** for private keys.
3.  **Rotate keys regularly** (annually or bi-annually).
4.  **Store keys securely** with proper file permissions (`600`).
5.  **Use different keys** for different purposes/environments.

### Password Security

1.  **Avoid password authentication** when possible.
2.  **Use strong passwords** (12+ characters, mixed case, numbers, symbols).
3.  **Never hardcode passwords** in source code.
4.  **Clear passwords** from memory after use.

## Troubleshooting Authentication

### Common Issues

1.  **Permission denied (publickey)**: Check private key file permissions (should be `600`) and verify public key is in server's `authorized_keys`.
2.  **Host key verification failed**: Server's host key has changed. Use proper host key policy.
3.  **Connection timeout**: Network connectivity issues or firewall blocking SSH port.

### Debug Authentication

Enable debug logging to see detailed authentication info:

```python
from spindlex.logging import configure_logging
from spindlex import SSHClient

# Enable debug logging
configure_logging(level='DEBUG')

with SSHClient() as client:
    client.connect(
        hostname='server.example.com',
        username='user',
        pkey=private_key
    )
```
