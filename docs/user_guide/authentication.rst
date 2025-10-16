Authentication Guide
===================

SSH Library supports multiple authentication methods to provide secure access to remote systems. This guide covers all supported authentication methods and best practices.

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

Generate SSH keys using SSH Library::

    from ssh_library.crypto.pkey import Ed25519Key, RSAKey, ECDSAKey
    
    # Generate Ed25519 key (recommended)
    private_key = Ed25519Key.generate()
    
    # Save private key with passphrase
    private_key.save_to_file('/path/to/private_key', password='strong_passphrase')
    
    # Get public key for server configuration
    public_key = private_key.get_public_key()
    public_key_string = public_key.get_base64()
    
    print(f"ssh-ed25519 {public_key_string} user@hostname")

Alternative key types::

    # RSA key (minimum 2048 bits, recommend 4096)
    rsa_key = RSAKey.generate(4096)
    
    # ECDSA key
    ecdsa_key = ECDSAKey.generate()

Loading Existing Keys
~~~~~~~~~~~~~~~~~~~~~

Load private keys from files::

    from ssh_library.crypto.pkey import Ed25519Key
    
    # Load key with passphrase
    private_key = Ed25519Key.from_private_key_file(
        '/path/to/private_key',
        password='passphrase'
    )
    
    # Load key from string
    with open('/path/to/private_key', 'r') as f:
        key_data = f.read()
    
    private_key = Ed25519Key.from_private_key(key_data, password='passphrase')

Using Keys for Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Authenticate using private keys::

    from ssh_library import SSHClient
    from ssh_library.crypto.pkey import Ed25519Key
    
    # Load private key
    private_key = Ed25519Key.from_private_key_file('/path/to/key')
    
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

    from ssh_library import SSHClient
    from ssh_library.crypto.pkey import Ed25519Key, RSAKey
    
    # Load multiple keys
    keys = [
        Ed25519Key.from_private_key_file('/path/to/ed25519_key'),
        RSAKey.from_private_key_file('/path/to/rsa_key')
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
            print(f"Connected using {key.get_name()} key")
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

    from ssh_library import SSHClient
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
    from ssh_library import SSHClient
    from ssh_library.exceptions import AuthenticationException
    
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
    from ssh_library import SSHClient
    
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

    from ssh_library import SSHClient
    from ssh_library.auth.keyboard_interactive import KeyboardInteractiveAuth
    
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
    from ssh_library import SSHClient
    
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

Basic GSSAPI Authentication
~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    from ssh_library import SSHClient
    from ssh_library.auth.gssapi import GSSAPIAuth
    
    # Ensure Kerberos ticket is available
    # Run: kinit username@REALM.COM
    
    client = SSHClient()
    
    try:
        client.connect(
            hostname='server.example.com',
            username='user',
            gss_auth=True  # Enable GSSAPI authentication
        )
        print("GSSAPI authentication successful")
    except AuthenticationException as e:
        print(f"GSSAPI authentication failed: {e}")

Advanced GSSAPI Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    from ssh_library import SSHClient
    from ssh_library.auth.gssapi import GSSAPIAuth
    
    # Configure GSSAPI authentication
    gssapi_auth = GSSAPIAuth(
        target_name='host@server.example.com',  # Service principal
        mech_type='kerberos',  # Mechanism type
        delegate_credentials=True  # Delegate credentials
    )
    
    client = SSHClient()
    client.connect(
        hostname='server.example.com',
        username='user',
        auth_method=gssapi_auth
    )

Combined Authentication Methods
-------------------------------

Try Multiple Methods
~~~~~~~~~~~~~~~~~~~~

Attempt different authentication methods in order::

    from ssh_library import SSHClient
    from ssh_library.crypto.pkey import Ed25519Key
    from ssh_library.exceptions import AuthenticationException
    import getpass
    
    def multi_method_auth(hostname, username):
        """Try multiple authentication methods."""
        client = SSHClient()
        
        # Method 1: Try public key authentication
        try:
            private_key = Ed25519Key.from_private_key_file(
                f'/home/{username}/.ssh/id_ed25519'
            )
            client.connect(hostname=hostname, username=username, pkey=private_key)
            print("Authenticated using public key")
            return client
        except (AuthenticationException, FileNotFoundError):
            pass
        
        # Method 2: Try GSSAPI authentication
        try:
            client.connect(hostname=hostname, username=username, gss_auth=True)
            print("Authenticated using GSSAPI")
            return client
        except AuthenticationException:
            pass
        
        # Method 3: Fall back to password authentication
        try:
            password = getpass.getpass(f"Password for {username}@{hostname}: ")
            client.connect(hostname=hostname, username=username, password=password)
            print("Authenticated using password")
            return client
        except AuthenticationException:
            pass
        
        raise AuthenticationException("All authentication methods failed")
    
    # Usage
    try:
        client = multi_method_auth('server.example.com', 'user')
    except AuthenticationException as e:
        print(f"Authentication failed: {e}")

Partial Authentication
~~~~~~~~~~~~~~~~~~~~~~

Handle partial authentication scenarios::

    from ssh_library import SSHClient
    from ssh_library.exceptions import PartialAuthentication
    from ssh_library.crypto.pkey import Ed25519Key
    import getpass
    
    def handle_partial_auth(hostname, username):
        """Handle partial authentication."""
        client = SSHClient()
        
        try:
            # First authentication method (e.g., public key)
            private_key = Ed25519Key.from_private_key_file('/path/to/key')
            client.connect(hostname=hostname, username=username, pkey=private_key)
            
        except PartialAuthentication as e:
            print(f"Partial authentication successful. Remaining methods: {e.allowed_types}")
            
            # Continue with additional authentication
            if 'password' in e.allowed_types:
                password = getpass.getpass("Additional password required: ")
                client.auth_password(username, password)
            
            elif 'keyboard-interactive' in e.allowed_types:
                def ki_handler(title, instructions, prompts):
                    responses = []
                    for prompt, echo in prompts:
                        if echo:
                            response = input(prompt)
                        else:
                            response = getpass.getpass(prompt)
                        responses.append(response)
                    return responses
                
                client.auth_keyboard_interactive(username, ki_handler)
        
        return client

Authentication Configuration
----------------------------

SSH Client Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Configure authentication preferences::

    from ssh_library import SSHClient
    from ssh_library.hostkeys.policy import RejectPolicy
    
    client = SSHClient()
    
    # Configure authentication preferences
    client.set_auth_timeout(30)  # 30 second timeout
    client.set_auth_methods(['publickey', 'keyboard-interactive', 'password'])
    client.set_missing_host_key_policy(RejectPolicy())  # Strict host key checking
    
    # Disable less secure methods
    client.disable_auth_method('password')  # Disable password auth
    
    # Connect with configuration
    client.connect(
        hostname='server.example.com',
        username='user',
        pkey=private_key,
        timeout=60,
        banner_timeout=30
    )

Agent Authentication
~~~~~~~~~~~~~~~~~~~~

Use SSH agent for key management::

    from ssh_library import SSHClient
    from ssh_library.auth.agent import SSHAgent
    
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

    from ssh_library.logging import get_logger
    from ssh_library import SSHClient
    from ssh_library.exceptions import AuthenticationException
    
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

    from ssh_library.logging import configure_logging
    from ssh_library import SSHClient
    
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

    from ssh_library import SSHClient
    
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

    from ssh_library.crypto.pkey import Ed25519Key
    
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