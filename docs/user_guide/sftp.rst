SFTP Guide
==========

The SSH File Transfer Protocol (SFTP) provides secure file transfer capabilities over SSH connections. This guide covers all aspects of using SFTP with SpindleX.

Basic SFTP Operations
---------------------

Opening SFTP Connection
~~~~~~~~~~~~~~~~~~~~~~~

::

    from spindlex import SSHClient
    
    # Establish SSH connection
    client = SSHClient()
    client.connect('server.example.com', username='user', password='password')
    
    # Open SFTP session (returns SFTPClient)
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

    from spindlex import SSHClient
    
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

Downloading Files
~~~~~~~~~~~~~~~~~

Download single files::

    with client.open_sftp() as sftp:
        # Download a file
        sftp.get('/remote/path/file.txt', '/local/path/file.txt')

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

Creating and Removing Directories
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Directory management::

    with client.open_sftp() as sftp:
        # Create directory
        sftp.mkdir('/remote/new_directory')
        
        # Remove file
        sftp.remove('/remote/file_to_delete.txt')
        
        # Rename file
        sftp.rename('/remote/old_name.txt', '/remote/new_name.txt')

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

Setting File Permissions
~~~~~~~~~~~~~~~~~~~~~~~~

::

    with client.open_sftp() as sftp:
        # Change file permissions
        sftp.chmod('/remote/file.txt', 0o644)  # rw-r--r--

Server Support
--------------

SpindleX also provides support for creating custom SSH and SFTP servers.

SSH Server
~~~~~~~~~~

Brief documentation of `SSHServer` availability for creating custom SSH servers.

SFTP Server
~~~~~~~~~~~

Brief documentation of `SFTPServer` availability for creating custom SFTP servers.

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
2. **Use concurrent transfers** - For multiple files
3. **Clean up resources** - Always close SFTP sessions and files
