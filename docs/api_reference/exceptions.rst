Exceptions API
==============

Exception Hierarchy
-------------------

.. automodule:: spindlex.exceptions
   :members:
   :undoc-members:
   :show-inheritance:

Base Exceptions
---------------

.. autoexception:: spindlex.exceptions.SSHException
   :members:
   :undoc-members:
   :show-inheritance:

Authentication Exceptions
-------------------------

.. autoexception:: spindlex.exceptions.AuthenticationException
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: spindlex.exceptions.BadAuthenticationType
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: spindlex.exceptions.PartialAuthentication
   :members:
   :undoc-members:
   :show-inheritance:

Connection Exceptions
---------------------

.. autoexception:: spindlex.exceptions.BadHostKeyException
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: spindlex.exceptions.ChannelException
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: spindlex.exceptions.TransportException
   :members:
   :undoc-members:
   :show-inheritance:

Protocol Exceptions
-------------------

.. autoexception:: spindlex.exceptions.ProtocolException
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: spindlex.exceptions.ProxyCommandFailure
   :members:
   :undoc-members:
   :show-inheritance:

SFTP Exceptions
---------------

.. autoexception:: spindlex.exceptions.SFTPError
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: spindlex.exceptions.SFTPIOError
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: spindlex.exceptions.SFTPPermissionError
   :members:
   :undoc-members:
   :show-inheritance:

.. autoexception:: spindlex.exceptions.SFTPFileNotFoundError
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Basic Exception Handling::

    from spindlex import SSHClient
    from spindlex.exceptions import (
        SSHException,
        AuthenticationException,
        BadHostKeyException,
        ChannelException,
        SFTPError
    )
    
    client = SSHClient()
    
    try:
        client.connect('example.com', username='user', password='pass')
        
        # Execute command
        stdin, stdout, stderr = client.exec_command('ls -la')
        output = stdout.read()
        
        # SFTP operations
        sftp = client.open_sftp()
        sftp.get('/remote/file.txt', '/local/file.txt')
        
    except AuthenticationException as e:
        print(f"Authentication failed: {e}")
        # Handle authentication failure
        
    except BadHostKeyException as e:
        print(f"Host key verification failed: {e}")
        print(f"Host: {e.hostname}")
        print(f"Key: {e.key.get_fingerprint()}")
        # Handle host key verification failure
        
    except ChannelException as e:
        print(f"Channel operation failed: {e}")
        # Handle channel errors
        
    except SFTPError as e:
        print(f"SFTP operation failed: {e}")
        # Handle SFTP errors
        
    except SSHException as e:
        print(f"SSH error: {e}")
        # Handle general SSH errors
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        # Handle unexpected errors
        
    finally:
        client.close()

Specific SFTP Error Handling::

    from spindlex.exceptions import (
        SFTPFileNotFoundError,
        SFTPPermissionError,
        SFTPIOError
    )
    
    try:
        sftp.get('/remote/nonexistent.txt', '/local/file.txt')
        
    except SFTPFileNotFoundError:
        print("Remote file not found")
        
    except SFTPPermissionError:
        print("Permission denied")
        
    except SFTPIOError as e:
        print(f"I/O error: {e}")

Authentication Error Details::

    from spindlex.exceptions import (
        AuthenticationException,
        BadAuthenticationType,
        PartialAuthentication
    )
    
    try:
        client.connect('example.com', username='user', password='wrong')
        
    except BadAuthenticationType as e:
        print(f"Authentication method not supported: {e}")
        print(f"Allowed methods: {e.allowed_types}")
        
    except PartialAuthentication as e:
        print(f"Partial authentication successful: {e}")
        print(f"Remaining methods: {e.allowed_types}")
        
    except AuthenticationException as e:
        print(f"Authentication failed: {e}")

Custom Exception Handling::

    import logging
    from spindlex.exceptions import SSHException
    
    def safe_ssh_operation(func, *args, **kwargs):
        """Wrapper for safe SSH operations with logging."""
        try:
            return func(*args, **kwargs)
        except SSHException as e:
            logging.error(f"SSH operation failed: {e}")
            # Optionally re-raise or return default value
            raise
        except Exception as e:
            logging.error(f"Unexpected error in SSH operation: {e}")
            raise SSHException(f"Unexpected error: {e}") from e
    
    # Usage
    try:
        result = safe_ssh_operation(client.exec_command, 'ls -la')
    except SSHException:
        # Handle SSH-related errors uniformly
        pass

Exception Attributes::

    try:
        client.connect('badhost.com', username='user', password='pass')
    except BadHostKeyException as e:
        # Access exception attributes
        print(f"Hostname: {e.hostname}")
        print(f"Key type: {e.key.get_name()}")
        print(f"Fingerprint: {e.key.get_fingerprint()}")
        print(f"Expected key: {e.expected_key}")
        
    except AuthenticationException as e:
        # Check if partial authentication occurred
        if hasattr(e, 'allowed_types'):
            print(f"Try these methods: {e.allowed_types}")