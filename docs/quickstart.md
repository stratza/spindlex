# Quick Start Guide

This guide will help you get started with SpindleX quickly.

## Installation

Install SpindleX using pip:

```bash
pip install spindlex
```

For development features:

```bash
pip install spindlex[dev]
```

For GSSAPI authentication (Unix only):

```bash
pip install spindlex[gssapi]
```

## Basic SSH Client

=== "Sync"

    ```python
    from spindlex import SSHClient
    from spindlex.hostkeys.policy import AutoAddPolicy

    # Create and configure client
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())

    try:
        # Connect to server
        client.connect(
            hostname='example.com',
            username='myuser',
            password='mypassword'
        )

        # Execute a command (returns stdin, stdout, stderr)
        stdin, stdout, stderr = client.exec_command('uname -a')
        
        # Read the output
        output = stdout.read().decode('utf-8')
        print(f"Server info: {output}")
        
        # Get exit status
        exit_status = stdout.get_exit_status()
        print(f"Exit status: {exit_status}")

    finally:
        # Always close the connection
        client.close()
    ```

=== "Async"

    ```python
    import asyncio
    from spindlex import AsyncSSHClient

    async def run_command():
        async with AsyncSSHClient() as client:
            await client.connect(
                hostname='example.com',
                username='myuser',
                password='mypassword'
            )
            
            stdin, stdout, stderr = await client.exec_command('uname -a')
            print(f"Server info: {await stdout.read()}")

    asyncio.run(run_command())
    ```

## Using SSH Keys

=== "Password"

    ```python
    client.connect(
        hostname='example.com',
        username='myuser',
        password='mypassword'
    )
    ```

=== "SSH Key"

    ```python
    from spindlex.crypto import PKey

    # Load private key (auto-detects type)
    private_key = PKey.from_private_key_file('/path/to/private_key')

    client.connect(
        hostname='example.com',
        username='myuser',
        pkey=private_key
    )
    ```

## SFTP File Transfer

=== "Sync"

    ```python
    from spindlex import SSHClient

    with SSHClient() as client:
        client.connect('example.com', username='user', password='pass')

        with client.open_sftp() as sftp:
            # Upload a file
            sftp.put('/local/file.txt', '/remote/file.txt')
            
            # Download a file
            sftp.get('/remote/data.csv', '/local/data.csv')
            
            # List directory contents
            files = sftp.listdir('/remote/directory')
            for filename in files:
                print(filename)
    ```

=== "Async"

    ```python
    import asyncio
    from spindlex import AsyncSSHClient

    async def transfer_files():
        async with AsyncSSHClient() as client:
            await client.connect('example.com', username='user', password='pass')
            
            async with client.open_sftp() as sftp:
                await sftp.put('/local/file.txt', '/remote/file.txt')
                await sftp.get('/remote/data.csv', '/local/data.csv')
    
    asyncio.run(transfer_files())
    ```

## Error Handling

```python
from spindlex import (
    SSHClient, 
    AuthenticationException, 
    BadHostKeyException,
    SSHException
)

client = SSHClient()

try:
    client.connect('example.com', username='user', password='wrong')
except AuthenticationException:
    print("Authentication failed - check credentials")
except BadHostKeyException:
    print("Host key verification failed")
except SSHException as e:
    print(f"SSH error: {e}")
except Exception as e:
    print(f"Unexpected error: {e}")
```

## Next Steps

* Read the [**User Guide**](user_guide/index.md) for detailed usage information
* Check out the [**Cookbook**](cookbook/index.md) for more code examples
* Review [**Security**](security.md) for security best practices
* See the [**API Reference**](api_reference/index.md) for complete API documentation
