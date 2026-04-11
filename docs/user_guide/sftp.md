# SFTP Guide

The SSH File Transfer Protocol (SFTP) provides secure file transfer capabilities over SSH connections. This guide covers all aspects of using SFTP with SpindleX.

## Basic SFTP Operations

### Opening SFTP Connection

=== "Sync"

    ```python
    from spindlex import SSHClient
    
    with SSHClient() as client:
        client.connect('server.example.com', username='user', password='password')
        
        with client.open_sftp() as sftp:
            files = sftp.listdir('.')
            print(f"Found {len(files)} files")
    ```

=== "Async"

    ```python
    from spindlex import AsyncSSHClient
    
    async with AsyncSSHClient() as client:
        await client.connect('server.example.com', username='user', password='password')
        
        async with client.open_sftp() as sftp:
            files = await sftp.listdir('.')
            print(f"Found {len(files)} files")
    ```

## File Transfer Operations

### Uploading Files

=== "Sync"

    ```python
    with client.open_sftp() as sftp:
        sftp.put('/local/path/file.txt', '/remote/path/file.txt')
    ```

=== "Async"

    ```python
    async with client.open_sftp() as sftp:
        await sftp.put('/local/path/file.txt', '/remote/path/file.txt')
    ```

### Downloading Files

=== "Sync"

    ```python
    with client.open_sftp() as sftp:
        sftp.get('/remote/path/file.txt', '/local/path/file.txt')
    ```

=== "Async"

    ```python
    async with client.open_sftp() as sftp:
        await sftp.get('/remote/path/file.txt', '/local/path/file.txt')
    ```

## Directory Operations

### Listing Directories

=== "Sync"

    ```python
    with client.open_sftp() as sftp:
        files = sftp.listdir('.')
        for filename in files:
            print(filename)
    ```

=== "Async"

    ```python
    async with client.open_sftp() as sftp:
        files = await sftp.listdir('.')
        for filename in files:
            print(filename)
    ```

### Creating and Removing Directories

=== "Sync"

    ```python
    with client.open_sftp() as sftp:
        sftp.mkdir('/remote/new_directory')
        sftp.remove('/remote/file_to_delete.txt')
        sftp.rename('/remote/old_name.txt', '/remote/new_name.txt')
    ```

=== "Async"

    ```python
    async with client.open_sftp() as sftp:
        await sftp.mkdir('/remote/new_directory')
        await sftp.remove('/remote/file_to_delete.txt')
        await sftp.rename('/remote/old_name.txt', '/remote/new_name.txt')
    ```

## File Attributes and Permissions

### Reading File Attributes

```python
import stat

with client.open_sftp() as sftp:
    attrs = sftp.stat('/remote/file.txt')
    print(f"File size: {attrs.st_size} bytes")
    print(f"Permissions: {oct(attrs.st_mode)}")
```

### Setting File Permissions

```python
with client.open_sftp() as sftp:
    sftp.chmod('/remote/file.txt', 0o644)  # rw-r--r--
```

## Best Practices

### Security Considerations

1.  **Use secure authentication**: Prefer public key over password.
2.  **Validate file paths**: Prevent directory traversal attacks.
3.  **Set proper permissions**: Use restrictive file permissions.
4.  **Implement access controls**: Limit user access to specific directories.

### Performance Tips

1.  **Use appropriate chunk sizes**: Balance memory usage and performance.
2.  **Use concurrent transfers**: For multiple files using `asyncio.gather`.
3.  **Clean up resources**: Always use context managers to close SFTP sessions and files.
