Authentication Guide
====================

SpindleX supports multiple authentication methods to provide secure access to remote systems. This guide covers all supported authentication methods and best practices.

Supported Authentication Methods
--------------------------------

1. **Public Key Authentication** (Recommended)
2. **Password Authentication**
3. **GSSAPI/Kerberos Authentication**
4. **Keyboard-Interactive Authentication** (Currently not implemented)

Public Key Authentication
-------------------------

Public key authentication is the most secure method and is recommended for production use.

Key Generation
~~~~~~~~~~~~~~

SpindleX includes a dedicated CLI tool, `spindlex-keygen`, for generating modern cryptographic keys::

    spindlex-keygen -t ed25519 -f ~/.ssh/id_ed25519_spindlex

Loading Existing Keys
~~~~~~~~~~~~~~~~~~~~~

Load private keys from files using the utility functions in `spindlex.crypto.pkey`::

    from spindlex.crypto.pkey import load_key_from_file
    
    # Load key with passphrase
    private_key = load_key_from_file(
        '/path/to/private_key',
        password='passphrase'
    )

Using Keys for Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authenticate using private keys::

    from spindlex import SSHClient
    from spindlex.crypto.pkey import load_key_from_file
    
    # Load private key
    private_key = load_key_from_file('/path/to/key')
    
    # Connect using key
    client = SSHClient()
    client.connect(
        hostname='server.example.com',
        username='user',
        pkey=private_key
    )

Password Authentication
-----------------------

Password authentication is less secure but sometimes necessary.

Basic Password Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    from spindlex import SSHClient
    import getpass
    
    # Get password securely
    password = getpass.getpass("Enter SSH password: ")
    
    client = SSHClient()
    client.connect(
        hostname='server.example.com',
        username='user',
        password=password
    )
    
    # Clear password from memory
    password = None

GSSAPI/Kerberos Authentication
------------------------------

GSSAPI authentication provides single sign-on capabilities in Kerberos environments. This is fully supported in the asynchronous client.

Async GSSAPI Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The `AsyncSSHClient` supports GSSAPI authentication directly in the `connect()` method::

    from spindlex import AsyncSSHClient
    from spindlex.exceptions import AuthenticationException
    
    async def connect_gssapi():
        async with AsyncSSHClient() as client:
            try:
                await client.connect(
                    hostname='server.example.com',
                    username='user',
                    gss_auth=True,          # Enable GSSAPI authentication
                    gss_host='server.example.com', # Target service name
                    gss_deleg_creds=True    # Delegate credentials if needed
                )
                print("GSSAPI authentication successful")
            except AuthenticationException as e:
                print(f"GSSAPI authentication failed: {e}")

Synchronous GSSAPI
~~~~~~~~~~~~~~~~~~

.. note::
   The synchronous `SSHClient.connect()` method currently does not expose GSSAPI parameters directly. For GSSAPI support, it is recommended to use the `AsyncSSHClient`.

Keyboard-Interactive Authentication
-----------------------------------

.. warning::
   Keyboard-Interactive authentication is currently **not implemented** in SpindleX and will raise a `NotImplementedError` if attempted through the underlying authentication classes.

Security Best Practices
-----------------------

Key Management
~~~~~~~~~~~~~~

1. **Use Ed25519 keys** for new deployments
2. **Use strong passphrases** for private keys
3. **Rotate keys regularly** (annually or bi-annually)
4. **Store keys securely** with proper file permissions (600)
5. **Use different keys** for different purposes/environments

Password Security
~~~~~~~~~~~~~~~~~

1. **Avoid password authentication** when possible
2. **Use strong passwords** (12+ characters, mixed case, numbers, symbols)
3. **Never hardcode passwords** in source code
4. **Clear passwords** from memory after use
5. **Implement account lockout** policies on servers

Authentication Monitoring
~~~~~~~~~~~~~~~~~~~~~~~~~

Monitor authentication events::

    from spindlex.logging import get_logger
    from spindlex import SSHClient
    from spindlex.exceptions import AuthenticationException
    import time
    
    logger = get_logger(__name__)
    
    def monitored_connect(hostname, username, **auth_kwargs):
        """Connect with authentication monitoring."""
        client = SSHClient()
        
        try:
            start_time = time.time()
            client.connect(hostname=hostname, username=username, **auth_kwargs)
            
            # Log successful authentication
            logger.info("Authentication successful", extra={
                'hostname': hostname,
                'username': username,
                'auth_method': 'publickey' if 'pkey' in auth_kwargs else 'password',
                'duration': time.time() - start_time
            })
            
            return client
            
        except AuthenticationException as e:
            # Log authentication failure
            logger.warning("Authentication failed", extra={
                'hostname': hostname,
                'username': username,
                'error': str(e),
                'duration': time.time() - start_time
            })
            raise

Troubleshooting Authentication
------------------------------

Common Issues
~~~~~~~~~~~~~

1. **Permission denied (publickey)**
   - Check private key file permissions (should be 600)
   - Verify public key is in server's authorized_keys
   - Check server's SSH configuration

2. **Host key verification failed**
   - Server's host key has changed
   - Use proper host key policy (`RejectPolicy`, `WarningPolicy`, or `AutoAddPolicy`)
   - Verify host key fingerprint out-of-band

3. **Connection timeout**
   - Network connectivity issues
   - Firewall blocking SSH port
   - Server not responding

Debug Authentication
~~~~~~~~~~~~~~~~~~~~

Enable debug logging::

    from spindlex.logging import configure_logging
    from spindlex import SSHClient
    
    # Enable debug logging
    configure_logging(level='DEBUG')
    
    client = SSHClient()
    
    # This will show detailed authentication debug info
    client.connect(
        hostname='server.example.com',
        username='user',
        pkey=private_key
    )
