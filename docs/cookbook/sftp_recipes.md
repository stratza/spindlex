# SFTP Recipes

Practical recipes for common SFTP file transfer tasks.

## Recursive Upload

Upload an entire directory tree from your local machine to a remote server.

```python
import os
from spindlex import SSHClient

def put_recursive(sftp, local_path, remote_path):
    """
    Recursively uploads a directory to a remote server.
    """
    for item in os.listdir(local_path):
        local_item = os.path.join(local_path, item)
        # Ensure remote paths use forward slashes for compatibility
        remote_item = f"{remote_path}/{item}"

        if os.path.isfile(local_item):
            sftp.put(local_item, remote_item)
        elif os.path.isdir(local_item):
            try:
                sftp.mkdir(remote_item)
            except OSError:
                pass # Directory might already exist
            put_recursive(sftp, local_item, remote_item)

with SSHClient() as client:
    client.connect('example.com', username='user')
    with client.open_sftp() as sftp:
        put_recursive(sftp, './logs', '/home/user/backups/logs')
```

## Pattern-Based Deletion

Delete files on the remote server that match a certain pattern (e.g., all `.log` files older than 7 days).

```python
import time
from spindlex import SSHClient

def delete_old_logs(sftp, directory, pattern='.log', days=7):
    current_time = time.time()
    seconds_limit = days * 86400

    filenames = sftp.listdir(directory)
    for filename in filenames:
        if filename.endswith(pattern):
            full_path = f"{directory}/{filename}"
            # Get file attributes for each match
            attrs = sftp.stat(full_path)
            if current_time - attrs.st_mtime > seconds_limit:
                print(f"Deleting old log: {filename}")
                sftp.remove(full_path)

with SSHClient() as client:
    client.connect('example.com', username='user')
    with client.open_sftp() as sftp:
        delete_old_logs(sftp, '/var/log/myapp', days=30)
```
