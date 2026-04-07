Authentication Guide
====================

SpindleX supports multiple authentication methods to provide secure access to remote systems. This guide covers all supported authentication methods and best practices.

Supported Authentication Methods
--------------------------------

1. **Public Key Authentication** (Recommended)
2. **Password Authentication**
3. **Keyboard-Interactive Authentication**
4. **GSSAPI/Kerberos Authentication** (Optional)

Public Key Authentication
-------------------------

Public key authentication is the most secure method and is recommended for production use.

Key Generation
~~~~~~~~~~~~~~

Currently, SpindleX focuses on key usage rather than generation. It is recommended to use standard tools like `ssh-keygen` to generate your keys.

Loading Existing Keys
~~~~~~~~~~~~~~~~~~~~~

Load private keys from files using the utility function::

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

Multiple Key Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Try multiple keys automatically::

    from spindlex import SSHClient
    from spindlex.crypto.pkey import load_key_from_file
    
    # Load multiple keys
    keys = [
        load_key_from_file('/path/to/ed25519_key'),
        load_key_from_file('/path/to/rsa_key')
    ]
    
    client = SSHClient()
    
    # Try each key until one works
    for key in keys:
        try:
            client.connect(
                hostname='server.example.com',
                username='user',
                pkey=key
            )
            print(f"Connected successfully")
            break
        except AuthenticationException:
            continue
    else:
        print("All key authentication attempts failed")

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

Secure Password Handling
~~~~~~~~~~~~~~~~~~~~~~~~

Best practices for password authentication::

    import os
    import getpass
    from spindlex import SSHClient
    from spindlex.exceptions import AuthenticationException
    
    def secure_password_auth(hostname, username, max_attempts=3):
        """Secure password authentication with retry logic."""
        
        for attempt in range(max_attempts):
            try:
                password = getpass.getpass(f"Password for {username}@{hostname}: ")
                
                client = SSHClient()
                client.connect(
                    hostname=hostname,
                    username=username,
                    password=password
                )
                
                # Clear password immediately
                password = None
                
                return client
                
            except AuthenticationException:
                password = None  # Clear failed password
                print(f"Authentication failed. Attempt {attempt + 1}/{max_attempts}")
                
                if attempt == max_attempts - 1:
                    raise AuthenticationException("Maximum authentication attempts exceeded")
            
            except Exception as e:
                password = None
                raise e
    
    # Usage
    try:
        client = secure_password_auth('server.example.com', 'user')
        print("Authentication successful")
    except AuthenticationException as e:
        print(f"Authentication failed: {e}")

Environment Variable Passwords
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using environment variables (not recommended for production)::

    import os
    from spindlex import SSHClient
    
    # Set password in environment (use secure methods in production)
    # export SSH_PASSWORD="your_password"
    
    password = os.environ.get('SSH_PASSWORD')
    if not password:
        raise ValueError("SSH_PASSWORD environment variable not set")
    
    client = SSHClient()
    client.connect(
        hostname='server.example.com',
        username='user',
        password=password
    )

Keyboard-Interactive Authentication
-----------------------------------

Keyboard-interactive authentication supports multi-factor authentication and custom prompts.

Basic Keyboard-Interactive
~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    from spindlex import SSHClient
    from spindlex.auth.keyboard_interactive import KeyboardInteractiveAuth
    
    def auth_handler(title, instructions, prompts):
        """Handle authentication prompts."""
        print(f"Title: {title}")
        print(f"Instructions: {instructions}")
        
        responses = []
        for prompt, echo in prompts:
            if echo:
                response = input(prompt)
            else:
                response = getpass.getpass(prompt)
            responses.append(response)
        
        return responses
    
    client = SSHClient()
    
    # Set up keyboard-interactive authentication
    auth = KeyboardInteractiveAuth(auth_handler)
    
    client.connect(
        hostname='server.example.com',
        username='user',
        auth_method=auth
    )

Multi-Factor Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Handle MFA prompts::

    import getpass
    from spindlex import SSHClient
    
    def mfa_auth_handler(title, instructions, prompts):
        """Handle MFA authentication."""
        responses = []
        
        for prompt, echo in prompts:
            prompt_lower = prompt.lower()
            
            if 'password' in prompt_lower:
                response = getpass.getpass("Enter password: ")
            elif 'token' in prompt_lower or 'code' in prompt_lower:
                response = input("Enter MFA token: ")
            elif 'verification' in prompt_lower:
                response = input("Enter verification code: ")
            else:
                # Generic prompt handling
                if echo:
                    response = input(prompt)
                else:
                    response = getpass.getpass(prompt)
            
            responses.append(response)
        
        return responses
    
    client = SSHClient()
    
    try:
        client.connect(
            hostname='server.example.com',
            username='user',
            keyboard_interactive_handler=mfa_auth_handler
        )
        print("MFA authentication successful")
    except AuthenticationException as e:
        print(f"MFA authentication failed: {e}")

GSSAPI/Kerberos Authentication
------------------------------

GSSAPI authentication provides single sign-on capabilities in Kerberos environments.

.. note::
   As of version 0.4.0, GSSAPI authentication is fully integrated into `AsyncSSHClient`. For the synchronous `SSHClient`, it can be performed by accessing the underlying `Transport`.

Async GSSAPI Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    from spindlex import AsyncSSHClient
    
    async def connect_gssapi():
        async with AsyncSSHClient() as client:
            try:
                await client.connect(
                    hostname='server.example.com',
                    username='user',
                    gss_auth=True  # Enable GSSAPI authentication
                )
                print("GSSAPI authentication successful")
            except AuthenticationException as e:
                print(f"GSSAPI authentication failed: {e}")

Synchronous GSSAPI (via Transport)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    from spindlex import SSHClient
    
    client = SSHClient()
    client.connect('server.example.com', username=None) # Connect without auth first
    
    transport = client.get_transport()
    if transport.auth_gssapi('user'):
        print("GSSAPI authentication successful")

Combined Authentication Methods
-------------------------------

SpindleX's `connect()` method automatically attempts provided credentials. For advanced multi-factor scenarios, you can use the transport layer directly or perform sequential authentication.

Authentication Configuration
----------------------------

SSH Client Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Configure host key policies and timeouts::

    from spindlex import SSHClient
    from spindlex.hostkeys.policy import RejectPolicy
    
    client = SSHClient()
    
    # Configure host key policy
    client.set_missing_host_key_policy(RejectPolicy())  # Strict host key checking
    
    # Connect with timeout
    client.connect(
        hostname='server.example.com',
        username='user',
        password='mypassword',
        timeout=60
    )

Agent Authentication
~~~~~~~~~~~~~~~~~~~~

Use SSH agent for key management::

    from spindlex import SSHClient
    from spindlex.auth.agent import SSHAgent
    
    # Connect to SSH agent
    agent = SSHAgent()
    
    if agent.is_available():
        # Get keys from agent
        agent_keys = agent.get_keys()
        print(f"Found {len(agent_keys)} keys in SSH agent")
        
        client = SSHClient()
        
        # Try each key from agent
        for key in agent_keys:
            try:
                client.connect(
                    hostname='server.example.com',
                    username='user',
                    pkey=key
                )
                print(f"Connected using agent key: {key.get_fingerprint()}")
                break
            except AuthenticationException:
                continue
        else:
            print("No agent keys worked")
    else:
        print("SSH agent not available")

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
   - Use proper host key policy
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

Test Authentication Methods
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Test which methods are available::

    from spindlex import SSHClient
    
    client = SSHClient()
    
    # Connect without authentication to get available methods
    try:
        client.connect(
            hostname='server.example.com',
            username='user',
            password='wrong_password'  # Intentionally wrong
        )
    except AuthenticationException as e:
        if hasattr(e, 'allowed_types'):
            print(f"Available authentication methods: {e.allowed_types}")
        else:
            print("Could not determine available methods")

Key Fingerprint Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Verify key fingerprints::

    from spindlex.crypto.pkey import Ed25519Key
    
    # Load server's public key
    server_key = Ed25519Key.from_public_key_file('/path/to/server_key.pub')
    
    # Get fingerprints in different formats
    md5_fingerprint = server_key.get_fingerprint()
    sha256_fingerprint = server_key.get_fingerprint('sha256')
    
    print(f"MD5: {md5_fingerprint}")
    print(f"SHA256: {sha256_fingerprint}")
    
    # Compare with expected fingerprint
    expected_fingerprint = "SHA256:abc123..."
    if sha256_fingerprint == expected_fingerprint:
        print("Host key verified!")
    else:
        print("Host key verification failed!")