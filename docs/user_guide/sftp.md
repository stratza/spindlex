# SFTP Guide

The SSH File Transfer Protocol (SFTP) provides secure file transfer capabilities over SSH connections. This guide covers all aspects of using SFTP with SpindleX.

## Basic SFTP Operations

### Opening SFTP Connection

=== "Sync"

    ```python
    from spindlex import SSHClient

    with SSHClient() as client:
        client.get_host_keys().load()
        client.connect('server.example.com', username='user', password='password')

        with client.open_sftp() as sftp:
            files = sftp.listdir('.')
            print(f"Found {len(files)} files")
    ```

=== "Async"

    ```python
    from spindlex import AsyncSSHClient

    async with AsyncSSHClient() as client:
        client.get_host_keys().load()
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

### Working with Remote Files

`open()` returns a file object. Modes follow Python's `open()`: `r`, `w`,
`a`, `x`, each optionally with `+` (read and write) and `b`.

```python
with client.open_sftp() as sftp:
    with sftp.open('/remote/data.bin', 'w+') as f:
        f.write(b'hello world')
        f.seek(0)              # reads and writes share one position
        print(f.read(5))       # b'hello'
        print(f.tell())        # 5
        f.flush()              # wait until written data is acknowledged

    sftp.truncate('/remote/data.bin', 5)
```

Writes are pipelined; `flush()`, `close()`, a read or a `seek()` wait for
outstanding writes. When the server does not advertise its limits
(`limits@openssh.com`), reads and writes use 32 KiB requests, and the client
adapts to servers that return less per read.

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

### Recursive Downloads

```python
with client.open_sftp() as sftp:
    sftp.get_recursive('/remote/project', '/local/project')
```

```python
async with client.open_sftp() as sftp:
    await sftp.get_recursive('/remote/project', '/local/project', max_concurrency=8)
```

Symbolic links to directories are not followed (links to files are downloaded
as files), entry names that could escape the local directory are rejected, and
very deep trees stop with an error. The async version transfers at most
`max_concurrency` files at once.

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

### Symbolic Links

```python
with client.open_sftp() as sftp:
    sftp.symlink('/remote/target.txt', '/remote/link.txt')
    print(sftp.readlink('/remote/link.txt'))  # /remote/target.txt
```

File names that are not valid UTF-8 on the server are returned with their
undecodable bytes escaped (`surrogateescape`), and are sent back unchanged when
you pass them to other SFTP calls.

## SFTP Server

In addition to the client, SpindleX provides an `SFTPServer` implementation that can be used within an `SSHServer` to provide secure file access.

### Implementing an SFTP Server

To enable SFTP in your custom SSH server, you need to handle the "sftp" subsystem request.

```python
from spindlex.server import SSHServer, SFTPServer

class MyServer(SSHServer):
    def check_channel_subsystem_request(self, channel, name):
        if name == "sftp":
            # root_path defines the base directory for SFTP clients
            handler = SFTPServer(channel, root_path="/srv/sftp/data")
            return True
        return False
```

The `SFTPServer` handler will automatically process all SFTP packets (reading, writing, directory listing, etc.) relative to the specified `root_path`.

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
