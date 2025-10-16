SFTP Guide
==========

The SSH File Transfer Protocol (SFTP) provides secure file transfer capabilities over SSH connections. This guide covers all aspects of using SFTP with SSH Library.

Basic SFTP Operations
---------------------

Opening SFTP Connection
~~~~~~~~~~~~~~~~~~~~~~~

::

    from ssh_library import SSHClient
    
    # Establish SSH connection
    client = SSHClient()
    client.connect('server.example.com', username='user', password='password')
    
    # Open SFTP session
    sftp = client.open_sftp()
    
    try:
        # Perform SFTP operations
        files = sftp.listdir('.')
        print(f"Found {len(files)} files")
    finally:
        # Always close SFTP session
        sftp.close()
        client.close()

Context Manager Usage
~~~~~~~~~~~~~~~~~~~~~

Use context managers for automatic cleanup::

    from ssh_library import SSHClient
    
    with SSHClient() as client:
        client.connect('server.example.com', username='user', password='password')
        
        with client.open_sftp() as sftp:
            # SFTP operations here
            files = sftp.listdir('.')
            for filename in files:
                print(filename)

File Transfer Operations
------------------------

Uploading Files
~~~~~~~~~~~~~~~

Upload single files::

    with client.open_sftp() as sftp:
        # Upload a file
        sftp.put('/local/path/file.txt', '/remote/path/file.txt')
        
        # Upload with progress callback
        def progress_callback(transferred, total):
            percent = (transferred / total) * 100
            print(f"Upload progress: {percent:.1f}%")
        
        sftp.put(
            '/local/large_file.zip',
            '/remote/large_file.zip',
            callback=progress_callback
        )

Upload with file attributes::

    from ssh_library.sftp import SFTPAttributes
    import stat
    
    with client.open_sftp() as sftp:
        # Create file attributes
        attrs = SFTPAttributes()
        attrs.st_mode = stat.S_IFREG | 0o644  # Regular file, rw-r--r--
        attrs.st_size = os.path.getsize('/local/file.txt')
        
        # Upload with attributes
        sftp.putfo(
            open('/local/file.txt', 'rb'),
            '/remote/file.txt',
            file_size=attrs.st_size,
            callback=progress_callback
        )

Downloading Files
~~~~~~~~~~~~~~~~~

Download single files::

    with client.open_sftp() as sftp:
        # Download a file
        sftp.get('/remote/path/file.txt', '/local/path/file.txt')
        
        # Download with progress callback
        def download_progress(transferred, total):
            percent = (transferred / total) * 100
            print(f"Download progress: {percent:.1f}%")
        
        sftp.get(
            '/remote/large_file.zip',
            '/local/large_file.zip',
            callback=download_progress
        )

Download to file-like object::

    import io
    
    with client.open_sftp() as sftp:
        # Download to BytesIO buffer
        buffer = io.BytesIO()
        sftp.getfo('/remote/file.txt', buffer)
        
        # Get file contents
        buffer.seek(0)
        file_contents = buffer.read()
        print(file_contents.decode('utf-8'))

Batch File Operations
~~~~~~~~~~~~~~~~~~~~~

Upload multiple files::

    import os
    from concurrent.futures import ThreadPoolExecutor, as_completed
    
    def upload_file(sftp, local_path, remote_path):
        """Upload a single file."""
        try:
            sftp.put(local_path, remote_path)
            return {'success': True, 'local': local_path, 'remote': remote_path}
        except Exception as e:
            return {'success': False, 'local': local_path, 'error': str(e)}
    
    def batch_upload(client, file_pairs, max_workers=4):
        """Upload multiple files concurrently."""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Create SFTP sessions for each worker
            sftp_sessions = [client.open_sftp() for _ in range(max_workers)]
            
            try:
                # Submit upload tasks
                future_to_file = {}
                for i, (local_path, remote_path) in enumerate(file_pairs):
                    sftp = sftp_sessions[i % max_workers]
                    future = executor.submit(upload_file, sftp, local_path, remote_path)
                    future_to_file[future] = (local_path, remote_path)
                
                # Collect results
                for future in as_completed(future_to_file):
                    result = future.result()
                    results.append(result)
                    
                    if result['success']:
                        print(f"Uploaded: {result['local']} -> {result['remote']}")
                    else:
                        print(f"Failed: {result['local']} - {result['error']}")
            
            finally:
                # Close all SFTP sessions
                for sftp in sftp_sessions:
                    sftp.close()
        
        return results
    
    # Usage
    files_to_upload = [
        ('/local/file1.txt', '/remote/file1.txt'),
        ('/local/file2.txt', '/remote/file2.txt'),
        ('/local/file3.txt', '/remote/file3.txt'),
    ]
    
    results = batch_upload(client, files_to_upload)
    successful = sum(1 for r in results if r['success'])
    print(f"Uploaded {successful}/{len(results)} files successfully")

Directory Operations
--------------------

Listing Directories
~~~~~~~~~~~~~~~~~~~

Basic directory listing::

    with client.open_sftp() as sftp:
        # List files in current directory
        files = sftp.listdir('.')
        for filename in files:
            print(filename)
        
        # List files with attributes
        file_attrs = sftp.listdir_attr('.')
        for attr in file_attrs:
            print(f"{attr.filename}: {attr.st_size} bytes, mode {oct(attr.st_mode)}")

Detailed directory listing::

    import stat
    from datetime import datetime
    
    def detailed_listing(sftp, path='.'):
        """Provide detailed directory listing similar to 'ls -la'."""
        try:
            file_attrs = sftp.listdir_attr(path)
            
            print(f"Directory listing for: {path}")
            print("Permissions  Size      Modified              Name")
            print("-" * 60)
            
            for attr in file_attrs:
                # Format permissions
                mode = attr.st_mode
                if stat.S_ISDIR(mode):
                    file_type = 'd'
                elif stat.S_ISLNK(mode):
                    file_type = 'l'
                else:
                    file_type = '-'
                
                perms = file_type + stat.filemode(mode)[1:]
                
                # Format size
                size = attr.st_size if attr.st_size is not None else 0
                
                # Format modification time
                if attr.st_mtime is not None:
                    mtime = datetime.fromtimestamp(attr.st_mtime)
                    time_str = mtime.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    time_str = 'Unknown'
                
                print(f"{perms:<12} {size:>8} {time_str} {attr.filename}")
        
        except Exception as e:
            print(f"Error listing directory: {e}")
    
    # Usage
    with client.open_sftp() as sftp:
        detailed_listing(sftp, '/home/user')

Recursive Directory Traversal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Walk directory tree::

    def walk_remote_directory(sftp, path):
        """Recursively walk remote directory tree."""
        try:
            file_attrs = sftp.listdir_attr(path)
            
            files = []
            dirs = []
            
            for attr in file_attrs:
                full_path = f"{path}/{attr.filename}".replace('//', '/')
                
                if stat.S_ISDIR(attr.st_mode):
                    dirs.append(attr.filename)
                else:
                    files.append(attr.filename)
            
            # Yield current directory info
            yield path, dirs, files
            
            # Recursively process subdirectories
            for dirname in dirs:
                subdir_path = f"{path}/{dirname}".replace('//', '/')
                yield from walk_remote_directory(sftp, subdir_path)
                
        except Exception as e:
            print(f"Error accessing {path}: {e}")
    
    # Usage
    with client.open_sftp() as sftp:
        for root, dirs, files in walk_remote_directory(sftp, '/home/user'):
            print(f"Directory: {root}")
            for filename in files:
                print(f"  File: {filename}")
            for dirname in dirs:
                print(f"  Dir:  {dirname}")

Creating and Removing Directories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Directory management::

    with client.open_sftp() as sftp:
        # Create directory
        sftp.mkdir('/remote/new_directory')
        
        # Create directory with specific permissions
        sftp.mkdir('/remote/secure_dir', mode=0o700)  # rwx------
        
        # Create nested directories
        def mkdir_p(sftp, path):
            """Create directory and any necessary parent directories."""
            parts = path.strip('/').split('/')
            current_path = ''
            
            for part in parts:
                current_path += '/' + part
                try:
                    sftp.mkdir(current_path)
                except IOError:
                    # Directory might already exist
                    pass
        
        mkdir_p(sftp, '/remote/deep/nested/directory')
        
        # Remove empty directory
        sftp.rmdir('/remote/empty_directory')
        
        # Remove directory tree
        def rmdir_recursive(sftp, path):
            """Recursively remove directory and all contents."""
            try:
                file_attrs = sftp.listdir_attr(path)
                
                for attr in file_attrs:
                    full_path = f"{path}/{attr.filename}"
                    
                    if stat.S_ISDIR(attr.st_mode):
                        rmdir_recursive(sftp, full_path)
                    else:
                        sftp.remove(full_path)
                
                sftp.rmdir(path)
                
            except Exception as e:
                print(f"Error removing {path}: {e}")
        
        # Use with caution!
        # rmdir_recursive(sftp, '/remote/directory_to_delete')

File Attributes and Permissions
-------------------------------

Reading File Attributes
~~~~~~~~~~~~~~~~~~~~~~~

::

    import stat
    from datetime import datetime
    
    with client.open_sftp() as sftp:
        # Get file attributes
        attrs = sftp.stat('/remote/file.txt')
        
        print(f"File size: {attrs.st_size} bytes")
        print(f"Permissions: {oct(attrs.st_mode)}")
        print(f"Owner UID: {attrs.st_uid}")
        print(f"Group GID: {attrs.st_gid}")
        
        if attrs.st_mtime:
            mtime = datetime.fromtimestamp(attrs.st_mtime)
            print(f"Modified: {mtime}")
        
        if attrs.st_atime:
            atime = datetime.fromtimestamp(attrs.st_atime)
            print(f"Accessed: {atime}")
        
        # Check file type
        if stat.S_ISREG(attrs.st_mode):
            print("Regular file")
        elif stat.S_ISDIR(attrs.st_mode):
            print("Directory")
        elif stat.S_ISLNK(attrs.st_mode):
            print("Symbolic link")

Setting File Permissions
~~~~~~~~~~~~~~~~~~~~~~~~

::

    with client.open_sftp() as sftp:
        # Change file permissions
        sftp.chmod('/remote/file.txt', 0o644)  # rw-r--r--
        sftp.chmod('/remote/script.sh', 0o755)  # rwxr-xr-x
        
        # Change ownership (if you have permission)
        sftp.chown('/remote/file.txt', uid=1000, gid=1000)
        
        # Update timestamps
        import time
        current_time = time.time()
        sftp.utime('/remote/file.txt', (current_time, current_time))

Working with Symbolic Links
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    with client.open_sftp() as sftp:
        # Create symbolic link
        sftp.symlink('/remote/target/file.txt', '/remote/link_to_file.txt')
        
        # Read symbolic link target
        target = sftp.readlink('/remote/link_to_file.txt')
        print(f"Link points to: {target}")
        
        # Get link attributes (not target attributes)
        link_attrs = sftp.lstat('/remote/link_to_file.txt')
        
        # Remove symbolic link
        sftp.remove('/remote/link_to_file.txt')

Advanced SFTP Operations
------------------------

File Streaming
~~~~~~~~~~~~~~

Stream large files without loading into memory::

    def stream_upload(sftp, local_path, remote_path, chunk_size=64*1024):
        """Stream upload large file."""
        with open(local_path, 'rb') as local_file:
            with sftp.open(remote_path, 'wb') as remote_file:
                while True:
                    chunk = local_file.read(chunk_size)
                    if not chunk:
                        break
                    remote_file.write(chunk)
    
    def stream_download(sftp, remote_path, local_path, chunk_size=64*1024):
        """Stream download large file."""
        with sftp.open(remote_path, 'rb') as remote_file:
            with open(local_path, 'wb') as local_file:
                while True:
                    chunk = remote_file.read(chunk_size)
                    if not chunk:
                        break
                    local_file.write(chunk)
    
    # Usage
    with client.open_sftp() as sftp:
        stream_upload(sftp, '/local/large_file.zip', '/remote/large_file.zip')
        stream_download(sftp, '/remote/large_file.zip', '/local/downloaded.zip')

Partial File Operations
~~~~~~~~~~~~~~~~~~~~~~~

Read/write specific parts of files::

    with client.open_sftp() as sftp:
        # Read specific bytes from file
        with sftp.open('/remote/file.txt', 'rb') as f:
            f.seek(100)  # Skip first 100 bytes
            data = f.read(50)  # Read next 50 bytes
            print(f"Read {len(data)} bytes from offset 100")
        
        # Append to existing file
        with sftp.open('/remote/log.txt', 'ab') as f:
            f.write(b"New log entry\n")
        
        # Random access write
        with sftp.open('/remote/data.bin', 'r+b') as f:
            f.seek(200)  # Go to offset 200
            f.write(b"Modified data")

File Synchronization
~~~~~~~~~~~~~~~~~~~~

Synchronize directories::

    import os
    import hashlib
    
    def calculate_md5(file_path):
        """Calculate MD5 hash of file."""
        hash_md5 = hashlib.md5()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def calculate_remote_md5(sftp, file_path):
        """Calculate MD5 hash of remote file."""
        hash_md5 = hashlib.md5()
        with sftp.open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    
    def sync_directory(sftp, local_dir, remote_dir, direction='upload'):
        """Synchronize local and remote directories."""
        if direction == 'upload':
            # Upload newer local files
            for root, dirs, files in os.walk(local_dir):
                for filename in files:
                    local_path = os.path.join(root, filename)
                    relative_path = os.path.relpath(local_path, local_dir)
                    remote_path = f"{remote_dir}/{relative_path}".replace('\\', '/')
                    
                    # Check if file needs updating
                    needs_update = True
                    
                    try:
                        remote_attrs = sftp.stat(remote_path)
                        local_mtime = os.path.getmtime(local_path)
                        
                        if remote_attrs.st_mtime and local_mtime <= remote_attrs.st_mtime:
                            # Remote file is newer or same age
                            local_md5 = calculate_md5(local_path)
                            remote_md5 = calculate_remote_md5(sftp, remote_path)
                            
                            if local_md5 == remote_md5:
                                needs_update = False
                    
                    except IOError:
                        # Remote file doesn't exist
                        pass
                    
                    if needs_update:
                        # Create remote directory if needed
                        remote_dir_path = os.path.dirname(remote_path)
                        try:
                            sftp.mkdir(remote_dir_path)
                        except IOError:
                            pass  # Directory might already exist
                        
                        # Upload file
                        sftp.put(local_path, remote_path)
                        print(f"Uploaded: {relative_path}")
        
        elif direction == 'download':
            # Download newer remote files
            for root, dirs, files in walk_remote_directory(sftp, remote_dir):
                for filename in files:
                    remote_path = f"{root}/{filename}"
                    relative_path = os.path.relpath(remote_path, remote_dir)
                    local_path = os.path.join(local_dir, relative_path)
                    
                    # Check if file needs updating
                    needs_update = True
                    
                    if os.path.exists(local_path):
                        remote_attrs = sftp.stat(remote_path)
                        local_mtime = os.path.getmtime(local_path)
                        
                        if remote_attrs.st_mtime and remote_attrs.st_mtime <= local_mtime:
                            # Local file is newer or same age
                            local_md5 = calculate_md5(local_path)
                            remote_md5 = calculate_remote_md5(sftp, remote_path)
                            
                            if local_md5 == remote_md5:
                                needs_update = False
                    
                    if needs_update:
                        # Create local directory if needed
                        local_dir_path = os.path.dirname(local_path)
                        os.makedirs(local_dir_path, exist_ok=True)
                        
                        # Download file
                        sftp.get(remote_path, local_path)
                        print(f"Downloaded: {relative_path}")
    
    # Usage
    with client.open_sftp() as sftp:
        sync_directory(sftp, '/local/project', '/remote/project', direction='upload')

Error Handling and Recovery
---------------------------

Common SFTP Errors
~~~~~~~~~~~~~~~~~~

Handle SFTP-specific errors::

    from ssh_library.exceptions import (
        SFTPError,
        SFTPFileNotFoundError,
        SFTPPermissionError,
        SFTPIOError
    )
    
    def robust_file_operation(sftp, operation, *args, **kwargs):
        """Perform SFTP operation with error handling."""
        max_retries = 3
        retry_delay = 1
        
        for attempt in range(max_retries):
            try:
                return operation(*args, **kwargs)
                
            except SFTPFileNotFoundError:
                print(f"File not found: {args[0] if args else 'unknown'}")
                return None
                
            except SFTPPermissionError:
                print(f"Permission denied: {args[0] if args else 'unknown'}")
                return None
                
            except SFTPIOError as e:
                print(f"I/O error (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    raise
                
            except SFTPError as e:
                print(f"SFTP error: {e}")
                return None
    
    # Usage
    with client.open_sftp() as sftp:
        result = robust_file_operation(sftp, sftp.get, '/remote/file.txt', '/local/file.txt')
        if result is None:
            print("File operation failed")

Connection Recovery
~~~~~~~~~~~~~~~~~~~

Recover from connection issues::

    def resilient_sftp_operation(client, operation_func, *args, **kwargs):
        """Perform SFTP operation with connection recovery."""
        max_attempts = 3
        
        for attempt in range(max_attempts):
            try:
                with client.open_sftp() as sftp:
                    return operation_func(sftp, *args, **kwargs)
                    
            except (ConnectionError, EOFError, OSError) as e:
                print(f"Connection error (attempt {attempt + 1}/{max_attempts}): {e}")
                
                if attempt < max_attempts - 1:
                    # Reconnect
                    try:
                        client.close()
                        client.connect(
                            hostname='server.example.com',
                            username='user',
                            password='password'
                        )
                    except Exception as reconnect_error:
                        print(f"Reconnection failed: {reconnect_error}")
                        time.sleep(2 ** attempt)  # Exponential backoff
                else:
                    raise
    
    def upload_with_recovery(sftp, local_path, remote_path):
        """Upload operation that can be retried."""
        sftp.put(local_path, remote_path)
        return f"Uploaded {local_path} to {remote_path}"
    
    # Usage
    try:
        result = resilient_sftp_operation(
            client,
            upload_with_recovery,
            '/local/file.txt',
            '/remote/file.txt'
        )
        print(result)
    except Exception as e:
        print(f"Operation failed after all retries: {e}")

Performance Optimization
------------------------

Concurrent Operations
~~~~~~~~~~~~~~~~~~~~~

Use multiple SFTP sessions for better performance::

    from concurrent.futures import ThreadPoolExecutor, as_completed
    import queue
    
    class SFTPPool:
        def __init__(self, ssh_client, pool_size=4):
            self.ssh_client = ssh_client
            self.pool_size = pool_size
            self.sftp_pool = queue.Queue()
            
            # Create SFTP sessions
            for _ in range(pool_size):
                sftp = ssh_client.open_sftp()
                self.sftp_pool.put(sftp)
        
        def get_sftp(self):
            return self.sftp_pool.get()
        
        def return_sftp(self, sftp):
            self.sftp_pool.put(sftp)
        
        def close_all(self):
            while not self.sftp_pool.empty():
                sftp = self.sftp_pool.get()
                sftp.close()
    
    def parallel_upload(sftp_pool, file_pairs):
        """Upload files in parallel using SFTP pool."""
        def upload_file(local_path, remote_path):
            sftp = sftp_pool.get_sftp()
            try:
                sftp.put(local_path, remote_path)
                return {'success': True, 'file': local_path}
            except Exception as e:
                return {'success': False, 'file': local_path, 'error': str(e)}
            finally:
                sftp_pool.return_sftp(sftp)
        
        with ThreadPoolExecutor(max_workers=sftp_pool.pool_size) as executor:
            futures = [
                executor.submit(upload_file, local, remote)
                for local, remote in file_pairs
            ]
            
            results = []
            for future in as_completed(futures):
                result = future.result()
                results.append(result)
                
                if result['success']:
                    print(f"Uploaded: {result['file']}")
                else:
                    print(f"Failed: {result['file']} - {result['error']}")
        
        return results
    
    # Usage
    sftp_pool = SFTPPool(client, pool_size=4)
    
    try:
        file_pairs = [
            ('/local/file1.txt', '/remote/file1.txt'),
            ('/local/file2.txt', '/remote/file2.txt'),
            ('/local/file3.txt', '/remote/file3.txt'),
        ]
        
        results = parallel_upload(sftp_pool, file_pairs)
        successful = sum(1 for r in results if r['success'])
        print(f"Uploaded {successful}/{len(results)} files")
        
    finally:
        sftp_pool.close_all()

Buffering and Chunking
~~~~~~~~~~~~~~~~~~~~~~

Optimize transfer performance::

    def optimized_transfer(sftp, local_path, remote_path, 
                          chunk_size=256*1024, buffer_size=8):
        """Transfer file with optimized buffering."""
        
        with open(local_path, 'rb') as local_file:
            with sftp.open(remote_path, 'wb', bufsize=buffer_size) as remote_file:
                # Set optimal buffer size for remote file
                remote_file.set_pipelined(True)
                
                while True:
                    chunk = local_file.read(chunk_size)
                    if not chunk:
                        break
                    remote_file.write(chunk)
    
    # Usage
    with client.open_sftp() as sftp:
        optimized_transfer(sftp, '/local/large_file.zip', '/remote/large_file.zip')

SFTP Server Implementation
--------------------------

Basic SFTP Server
~~~~~~~~~~~~~~~~~

Implement custom SFTP server::

    from ssh_library.server import SFTPServer, SFTPHandle, SFTPAttributes
    import os
    import stat
    import errno
    
    class CustomSFTPServer(SFTPServer):
        def __init__(self, server, *args, **kwargs):
            super().__init__(server, *args, **kwargs)
            self.root_path = '/srv/sftp'  # Chroot directory
        
        def _realpath(self, path):
            """Convert virtual path to real filesystem path."""
            # Remove leading slash and join with root
            path = path.lstrip('/')
            return os.path.join(self.root_path, path)
        
        def list_folder(self, path):
            """List directory contents."""
            real_path = self._realpath(path)
            
            try:
                file_list = []
                for filename in os.listdir(real_path):
                    file_path = os.path.join(real_path, filename)
                    attr = SFTPAttributes.from_stat(os.stat(file_path))
                    attr.filename = filename
                    file_list.append(attr)
                return file_list
                
            except OSError:
                return SFTPServer.convert_errno(errno.ENOENT)
        
        def stat(self, path):
            """Get file attributes."""
            real_path = self._realpath(path)
            
            try:
                return SFTPAttributes.from_stat(os.stat(real_path))
            except OSError:
                return SFTPServer.convert_errno(errno.ENOENT)
        
        def lstat(self, path):
            """Get file attributes (don't follow symlinks)."""
            real_path = self._realpath(path)
            
            try:
                return SFTPAttributes.from_stat(os.lstat(real_path))
            except OSError:
                return SFTPServer.convert_errno(errno.ENOENT)
        
        def open(self, path, flags, attr):
            """Open file for reading/writing."""
            real_path = self._realpath(path)
            
            try:
                # Convert SFTP flags to Python file mode
                if flags & os.O_WRONLY:
                    if flags & os.O_APPEND:
                        mode = 'ab'
                    else:
                        mode = 'wb'
                elif flags & os.O_RDWR:
                    if flags & os.O_APPEND:
                        mode = 'a+b'
                    else:
                        mode = 'r+b'
                else:
                    mode = 'rb'
                
                # Create directories if needed
                if flags & os.O_CREAT:
                    os.makedirs(os.path.dirname(real_path), exist_ok=True)
                
                f = open(real_path, mode)
                fobj = CustomSFTPHandle(flags)
                fobj.filename = real_path
                fobj.readfile = fobj.writefile = f
                
                return fobj
                
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
        
        def remove(self, path):
            """Remove file."""
            real_path = self._realpath(path)
            
            try:
                os.remove(real_path)
                return SFTP_OK
            except OSError:
                return SFTPServer.convert_errno(errno.ENOENT)
        
        def rename(self, oldpath, newpath):
            """Rename file."""
            real_oldpath = self._realpath(oldpath)
            real_newpath = self._realpath(newpath)
            
            try:
                os.rename(real_oldpath, real_newpath)
                return SFTP_OK
            except OSError:
                return SFTPServer.convert_errno(errno.ENOENT)
        
        def mkdir(self, path, attr):
            """Create directory."""
            real_path = self._realpath(path)
            
            try:
                os.mkdir(real_path)
                if attr.st_mode is not None:
                    os.chmod(real_path, attr.st_mode)
                return SFTP_OK
            except OSError:
                return SFTPServer.convert_errno(errno.EACCES)
        
        def rmdir(self, path):
            """Remove directory."""
            real_path = self._realpath(path)
            
            try:
                os.rmdir(real_path)
                return SFTP_OK
            except OSError:
                return SFTPServer.convert_errno(errno.ENOENT)
        
        def chattr(self, path, attr):
            """Change file attributes."""
            real_path = self._realpath(path)
            
            try:
                if attr.st_mode is not None:
                    os.chmod(real_path, attr.st_mode)
                if attr.st_uid is not None or attr.st_gid is not None:
                    os.chown(real_path, attr.st_uid or -1, attr.st_gid or -1)
                if attr.st_atime is not None or attr.st_mtime is not None:
                    os.utime(real_path, (attr.st_atime, attr.st_mtime))
                return SFTP_OK
            except OSError:
                return SFTPServer.convert_errno(errno.EACCES)
    
    class CustomSFTPHandle(SFTPHandle):
        def stat(self):
            try:
                return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))
            except OSError:
                return SFTPServer.convert_errno(errno.EACCES)
        
        def chattr(self, attr):
            try:
                if attr.st_mode is not None:
                    os.fchmod(self.readfile.fileno(), attr.st_mode)
                if attr.st_uid is not None or attr.st_gid is not None:
                    os.fchown(self.readfile.fileno(), attr.st_uid or -1, attr.st_gid or -1)
                return SFTP_OK
            except OSError:
                return SFTPServer.convert_errno(errno.EACCES)

Best Practices
--------------

Security Considerations
~~~~~~~~~~~~~~~~~~~~~~~

1. **Use secure authentication** - Prefer public key over password
2. **Validate file paths** - Prevent directory traversal attacks
3. **Set proper permissions** - Use restrictive file permissions
4. **Implement access controls** - Limit user access to specific directories
5. **Monitor file operations** - Log all SFTP activities

Performance Tips
~~~~~~~~~~~~~~~~

1. **Use appropriate chunk sizes** - Balance memory usage and performance
2. **Enable compression** - For text files over slow connections
3. **Use concurrent transfers** - For multiple files
4. **Implement resume capability** - For large file transfers
5. **Cache directory listings** - When possible

Error Handling
~~~~~~~~~~~~~~

1. **Always use try/except blocks** - Handle SFTP-specific exceptions
2. **Implement retry logic** - For transient network issues
3. **Validate file integrity** - Use checksums for important transfers
4. **Clean up resources** - Always close SFTP sessions and files
5. **Log errors appropriately** - For debugging and monitoring