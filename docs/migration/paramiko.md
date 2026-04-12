# Migrating from Paramiko

SpindleX was designed to be a modern, high-performance alternative to Paramiko. While it retains some familiarity for ease of migration, it offers several improvements in API design, performance, and security.

## Why Switch?

*   **:zap: Performance**: SpindleX offers a highly efficient protocol implementation with optimized internal read buffering.
*   **:package: Lean Design**: SpindleX is a modern library that leverages the standard `cryptography` package for secure primitives.
*   **:cyclone: Native Async**: SpindleX has first-class `asyncio` support.
*   **:shield: Modern Security**: SpindleX prioritizes modern, secure algorithms by default.
*   **:label: Better DX**: Full type hints and a cleaner API.

## Side-by-Side Comparison

### Basic Connection

=== "Paramiko"

    ```python
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect('example.com', username='user', password='pass')

    stdin, stdout, stderr = client.exec_command('ls')
    print(stdout.read().decode())
    client.close()
    ```

=== "SpindleX"

    ```python
    from spindlex import SSHClient
    from spindlex.hostkeys.policy import AutoAddPolicy

    # Context manager support!
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect('example.com', username='user', password='pass')

        stdin, stdout, stderr = client.exec_command('ls')
        print(stdout.read().decode())
    ```

### SFTP Transfer

=== "Paramiko"

    ```python
    sftp = client.open_sftp()
    sftp.put('local.txt', 'remote.txt')
    sftp.get('remote.txt', 'local.txt')
    sftp.close()
    ```

=== "SpindleX"

    ```python
    # Better buffering and error handling by default
    with client.open_sftp() as sftp:
        sftp.put('local.txt', 'remote.txt')
        sftp.get('remote.txt', 'local.txt')
    ```

### Key Management

=== "Paramiko"

    ```python
    key = paramiko.RSAKey.from_private_key_file('/path/to/key')
    client.connect(..., pkey=key)
    ```

=== "SpindleX"

    ```python
    from spindlex.crypto.pkey import PKey

    # Automatically detects key type (RSA, Ed25519, etc.)
    key = PKey.from_private_key_file('/path/to/key')
    client.connect(..., pkey=key)
    ```

## Key Differences

1.  **Context Managers**: SpindleX provides native context manager support for `SSHClient`, `SFTPClient`, and their async counterparts, ensuring resources are always cleaned up.
2.  **Native Async**: No need for third-party wrappers like `parallel-ssh` for async operations.
3.  **Performance Tuning**: SpindleX handles window size and buffer management automatically to maximize throughput.
4.  **Exceptions**: SpindleX has a cleaner exception hierarchy under `spindlex.exceptions`.

## Migration Checklist

- [ ] Replace `import paramiko` with `from spindlex import SSHClient`.
- [ ] Use `PKey.from_private_key_file` instead of specific key classes like `RSAKey`.
- [ ] Wrap your client usage in `with SSHClient() as client:`.
- [ ] Check `spindlex.exceptions` if you were catching specific Paramiko errors.
