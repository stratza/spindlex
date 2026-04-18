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
        remote_item = os.path.join(remote_path, item).replace("\\", "/") # Ensure forward slashes

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

## Progress Tracking

Add a progress bar or progress callback to your file transfers.

```python
from spindlex import SSHClient

def progress_callback(transferred, total):
    percentage = (transferred / total) * 100
    print(f"Transferred: {transferred}/{total} bytes ({percentage:.1f}%)", end='\r')

with SSHClient() as client:
    client.connect('example.com', username='user')
    with client.open_sftp() as sftp:
        sftp.put(
            'ubuntu.iso', 
            '/tmp/ubuntu.iso', 
            callback=progress_callback
        )
```

## Pattern-Based Deletion

Delete files on the remote server that match a certain pattern (e.g., all `.log` files older than 7 days).

```python
import time
from spindlex import SSHClient

def delete_old_logs(sftp, directory, pattern='.log', days=7):
    current_time = time.time()
    seconds_limit = days * 86400

    files = sftp.listdir_attr(directory)
    for f in files:
        if f.filename.endswith(pattern):
            if current_time - f.st_mtime > seconds_limit:
                print(f"Deleting old log: {f.filename}")
                sftp.remove(f"{directory}/{f.filename}")

with SSHClient() as client:
    client.connect('example.com', username='user')
    with client.open_sftp() as sftp:
        delete_old_logs(sftp, '/var/log/myapp', days=30)
```
