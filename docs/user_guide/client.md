# SSH Client

The SSH client is the primary interface for connecting to SSH servers and executing remote operations. SpindleX provides both a synchronous `SSHClient` and an asynchronous `AsyncSSHClient`.

## Basic Usage

### Creating and Configuring a Client

=== "Sync"

    ```python
    from spindlex import SSHClient
    from spindlex.hostkeys.policy import AutoAddPolicy

    # Create client
    client = SSHClient()

    # Configure host key policy
    client.set_missing_host_key_policy(AutoAddPolicy())
    ```

=== "Async"

    ```python
    from spindlex import AsyncSSHClient

    # AsyncSSHClient uses a similar configuration but is designed for asyncio
    async with AsyncSSHClient() as client:
        # Configuration is often handled during connect
        pass
    ```

## Connection Methods

### Password Authentication

=== "Sync"

    ```python
    client.connect(
        hostname='example.com',
        port=22,
        username='myuser',
        password='mypassword',
        timeout=30
    )
    ```

=== "Async"

    ```python
    await client.connect(
        hostname='example.com',
        username='myuser',
        password='mypassword'
    )
    ```

### Public Key Authentication

=== "Sync"

    ```python
    from spindlex.crypto import PKey

    # Load key from file
    private_key = PKey.from_private_key_file('/path/to/key')

    client.connect(
        hostname='example.com',
        username='myuser',
        pkey=private_key
    )
    ```

=== "Async"

    ```python
    from spindlex.crypto import PKey

    private_key = PKey.from_private_key_file('/path/to/key')

    await client.connect(
        hostname='example.com',
        username='myuser',
        pkey=private_key
    )
    ```

## Command Execution

### Simple Commands

=== "Sync"

    ```python
    # Execute a simple command
    stdin, stdout, stderr = client.exec_command('ls -la')
    
    # Read output
    output = stdout.read().decode('utf-8')
    error = stderr.read().decode('utf-8')
    
    # Get exit status
    exit_status = stdout.get_exit_status()
    ```

=== "Async"

    ```python
    # Execute a simple command
    stdin, stdout, stderr = await client.exec_command('ls -la')
    
    # Read output
    output = await stdout.read()
    error = await stderr.read()
    
    # Get exit status
    exit_status = await stdout.recv_exit_status()
    ```

### Commands with Input

=== "Sync"

    ```python
    stdin, stdout, stderr = client.exec_command('cat > /tmp/test.txt')
    
    # Send input to the command
    stdin.write('Hello, World!\n')
    stdin.flush()
    stdin.close()
    ```

=== "Async"

    ```python
    stdin, stdout, stderr = await client.exec_command('cat > /tmp/test.txt')
    
    # Send input
    await stdin.write('Hello, World!\n')
    await stdin.close()
    ```

## Host Key Management

### Host Key Policies

```python
from spindlex.hostkeys.policy import (
    AutoAddPolicy, RejectPolicy, WarningPolicy
)

# Automatically add unknown host keys (not recommended for production)
client.set_missing_host_key_policy(AutoAddPolicy())

# Reject all unknown host keys (secure default)
client.set_missing_host_key_policy(RejectPolicy())

# Log warning but accept unknown host keys
client.set_missing_host_key_policy(WarningPolicy())
```

## Port Forwarding

SpindleX supports both local and remote port forwarding (SSH tunneling).

### Local Port Forwarding

Local port forwarding allows you to forward a port on your local machine to a port on a remote server.

=== "Sync"

    ```python
    with SSHClient() as client:
        client.connect('jump-host.example.com', username='user')
        
        # Forward local port 8080 to remote-server.internal:80
        tunnel_id = client.create_local_port_forward(
            local_port=8080,
            remote_host='remote-server.internal',
            remote_port=80
        )
        
        print(f"Tunnel {tunnel_id} established. Connect to localhost:8080")
        
        # Keep the connection open while you use the tunnel
        import time
        while True:
            time.sleep(1)
    ```

=== "Async"

    ```python
    from spindlex import AsyncSSHClient

    async def main():
        async with AsyncSSHClient() as client:
            await client.connect('jump-host.example.com', username='user')
            
            # Forward local port 8080 to remote-server.internal:80
            tunnel_id = await client.create_local_port_forward(
                local_port=8080,
                remote_host='remote-server.internal',
                remote_port=80
            )
            
            print(f"Tunnel {tunnel_id} established.")
            
            # Keep the connection open while you use the tunnel
            while True:
                await asyncio.sleep(1)
    ```

### Remote Port Forwarding

Remote port forwarding allows you to forward a port on the remote server to a port on your local machine.

=== "Sync"

    ```python
    with SSHClient() as client:
        client.connect('server.example.com', username='user')
        
        # Forward remote port 9090 to localhost:3000
        tunnel_id = client.create_remote_port_forward(
            remote_port=9090,
            local_host='127.0.0.1',
            local_port=3000
        )
        
        print(f"Remote tunnel {tunnel_id} established on server:9090")
    ```

=== "Async"

    ```python
    async def main():
        async with AsyncSSHClient() as client:
            await client.connect('server.example.com', username='user')
            
            # Forward remote port 9090 to localhost:3000
            tunnel_id = await client.create_remote_port_forward(
                remote_port=9090,
                local_host='127.0.0.1',
                local_port=3000
            )
            
            print(f"Remote tunnel {tunnel_id} established.")
    ```

## Error Handling

### Common Exceptions

```python
from spindlex.exceptions import (
    SSHException,
    AuthenticationException,
    BadHostKeyException,
    TransportException
)

try:
    client.connect('example.com', username='user', password='pass')
except AuthenticationException as e:
    print(f"Authentication failed: {e}")
except BadHostKeyException as e:
    print(f"Host key verification failed: {e}")
except TransportException as e:
    print(f"Transport error: {e}")
except SSHException as e:
    print(f"General SSH error: {e}")
```

## Best Practices

1.  **Always close connections**: Use context managers (`with` or `async with`).
2.  **Use key-based authentication**: More secure than passwords.
3.  **Implement proper host key verification**: Don't use `AutoAddPolicy` in production.
4.  **Handle timeouts appropriately**: Set reasonable timeout values.
5.  **Monitor connection health**: Check `transport.active` periodically.
