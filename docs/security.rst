Security Guidelines
===================

SpindleX is designed with security as a primary concern. This document outlines security best practices and guidelines for using the library safely.

Secure Defaults
---------------

SpindleX uses secure defaults to protect against common security issues:

* **Modern Cryptography**: Defaults to Ed25519 keys and ChaCha20-Poly1305 encryption
* **Strong Key Exchange**: Uses Curve25519 and ECDH key exchange algorithms
* **Host Key Verification**: Requires explicit host key policies
* **Secure Random**: Uses cryptographically secure random number generation

Authentication Security
-----------------------

Key-Based Authentication
~~~~~~~~~~~~~~~~~~~~~~~~

Always prefer key-based authentication over passwords:

.. code-block:: python

   from spindlex import SSHClient
   from spindlex.crypto.pkey import Ed25519Key

   # Generate a strong key
   private_key = Ed25519Key.generate()
   
   # Save securely (with proper file permissions)
   private_key.save_to_file('/path/to/key', password='strong_passphrase')

   # Use for authentication
   client = SSHClient()
   client.connect(hostname='server.com', username='user', pkey=private_key)

Password Security
~~~~~~~~~~~~~~~~~

If you must use password authentication:

.. code-block:: python

   import getpass
   from spindlex import SSHClient

   # Never hardcode passwords
   password = getpass.getpass("Enter SSH password: ")
   
   client = SSHClient()
   client.connect(hostname='server.com', username='user', password=password)
   
   # Clear password from memory
   password = None

Host Key Verification
---------------------

Strict Host Key Checking
~~~~~~~~~~~~~~~~~~~~~~~~~

Always verify host keys in production:

.. code-block:: python

   from spindlex import SSHClient
   from spindlex.hostkeys.policy import RejectPolicy

   client = SSHClient()
   
   # Reject unknown host keys (secure default)
   client.set_missing_host_key_policy(RejectPolicy())
   
   try:
       client.connect(hostname='server.com', username='user', pkey=key)
   except BadHostKeyException:
       print("Host key verification failed!")
       # Handle appropriately - don't ignore!

Custom Host Key Verification
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Implement custom verification logic:

.. code-block:: python

   from spindlex.hostkeys.policy import MissingHostKeyPolicy
   from spindlex.exceptions import SSHException

   class SecureHostKeyPolicy(MissingHostKeyPolicy):
       def __init__(self, trusted_keys_db):
           self.trusted_keys_db = trusted_keys_db
       
       def missing_host_key(self, client, hostname, key):
           fingerprint = key.get_fingerprint()
           
           # Check against trusted database
           if not self.trusted_keys_db.is_trusted(hostname, fingerprint):
               # Log security event
               logger.warning(f"Untrusted host key for {hostname}: {fingerprint}")
               raise SSHException(f"Untrusted host key for {hostname}")
           
           # Add to client's host keys
           client.get_host_keys().add(hostname, key.get_name(), key)

Network Security
----------------

Connection Security
~~~~~~~~~~~~~~~~~~~

Use secure connection practices:

.. code-block:: python

   from spindlex import SSHClient
   import socket

   client = SSHClient()
   
   # Set reasonable timeouts
   client.connect(
       hostname='server.com',
       username='user',
       pkey=private_key,
       timeout=30,  # Connection timeout
       banner_timeout=30,  # Banner timeout
       auth_timeout=30  # Authentication timeout
   )

   # Verify connection security
   transport = client.get_transport()
   print(f"Cipher: {transport.get_cipher()}")
   print(f"MAC: {transport.get_mac()}")
   print(f"Compression: {transport.get_compression()}")

Firewall and Network Configuration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

* Use SSH on non-standard ports when possible
* Implement proper firewall rules
* Use VPN or private networks for sensitive connections
* Monitor SSH connection logs

Cryptographic Security
----------------------

Key Generation
~~~~~~~~~~~~~~

Generate strong keys:

.. code-block:: python

   from spindlex.crypto.pkey import Ed25519Key, RSAKey

   # Preferred: Ed25519 (fast and secure)
   ed25519_key = Ed25519Key.generate()

   # Alternative: RSA with sufficient key size
   rsa_key = RSAKey.generate(4096)  # Minimum 2048, prefer 4096

   # Save with strong passphrase
   ed25519_key.save_to_file('/path/to/key', password='very_strong_passphrase')

Algorithm Selection
~~~~~~~~~~~~~~~~~~~

Configure strong algorithms:

.. code-block:: python

   from spindlex.crypto.backend import default_crypto_backend

   backend = default_crypto_backend
   
   # Verify strong algorithms are available
   supported_ciphers = backend.get_supported_ciphers()
   preferred_ciphers = [
       'chacha20-poly1305@openssh.com',
       'aes256-gcm@openssh.com',
       'aes128-gcm@openssh.com'
   ]
   
   for cipher in preferred_ciphers:
       if cipher in supported_ciphers:
           print(f"Strong cipher available: {cipher}")

Data Protection
---------------

Sensitive Data Handling
~~~~~~~~~~~~~~~~~~~~~~~

Protect sensitive data in memory:

.. code-block:: python

   import os
   from spindlex import SSHClient

   def secure_connect(hostname, username, password):
       client = SSHClient()
       
       try:
           client.connect(hostname=hostname, username=username, password=password)
           return client
       except Exception:
           # Clear sensitive data on failure
           password = None
           raise
       finally:
           # Clear password from local variables
           if 'password' in locals():
               password = None

Log Security
~~~~~~~~~~~~

Sanitize logs to prevent information leakage:

.. code-block:: python

   from spindlex.logging import configure_logging, SSHLogger

   # Configure secure logging
   configure_logging(
       level='INFO',
       sanitize_secrets=True,  # Remove sensitive data from logs
       log_file='/var/log/spindlex.log',
       max_log_size=10*1024*1024,  # 10MB
       backup_count=5
   )

   logger = SSHLogger(__name__)
   
   # Logs will automatically sanitize sensitive data
   logger.info("Connection established", extra={
       'hostname': 'server.com',
       'username': 'user',
       # Password/keys automatically redacted
   })

Server Security
---------------

SSH Server Implementation
~~~~~~~~~~~~~~~~~~~~~~~~~

When implementing SSH servers:

.. code-block:: python

   from spindlex import SSHServer
   from spindlex.crypto.pkey import Ed25519Key

   class SecureSSHServer(SSHServer):
       def __init__(self):
           # Use strong host key
           self.host_key = Ed25519Key.generate()
           self.authorized_users = {}
       
       def check_auth_password(self, username, password):
           # Implement secure password checking
           # Use constant-time comparison
           if username in self.authorized_users:
               stored_hash = self.authorized_users[username]['password_hash']
               return self.verify_password(password, stored_hash)
           return self.AUTH_FAILED
       
       def check_auth_publickey(self, username, key):
           # Verify against authorized keys
           if username in self.authorized_users:
               authorized_keys = self.authorized_users[username]['keys']
               for auth_key in authorized_keys:
                   if key.get_fingerprint() == auth_key.get_fingerprint():
                       return self.AUTH_SUCCESSFUL
           return self.AUTH_FAILED

Monitoring and Auditing
-----------------------

Security Monitoring
~~~~~~~~~~~~~~~~~~~

Implement comprehensive monitoring:

.. code-block:: python

   from spindlex.logging import get_performance_monitor
   from spindlex.exceptions import AuthenticationException

   monitor = get_performance_monitor()

   def monitored_connect(hostname, username, **kwargs):
       start_time = time.time()
       
       try:
           client = SSHClient()
           client.connect(hostname=hostname, username=username, **kwargs)
           
           # Log successful connection
           monitor.record_event('ssh_connection_success', {
               'hostname': hostname,
               'username': username,
               'duration': time.time() - start_time
           })
           
           return client
           
       except AuthenticationException as e:
           # Log authentication failure
           monitor.record_event('ssh_auth_failure', {
               'hostname': hostname,
               'username': username,
               'error': str(e)
           })
           raise

Security Checklist
-------------------

Before deploying SpindleX in production:

**Authentication**
- [ ] Use key-based authentication
- [ ] Implement strong password policies if passwords are required
- [ ] Use multi-factor authentication when possible
- [ ] Regularly rotate keys and passwords

**Host Key Management**
- [ ] Implement strict host key verification
- [ ] Maintain a database of trusted host keys
- [ ] Monitor for host key changes
- [ ] Use certificate-based host authentication when possible

**Network Security**
- [ ] Use non-standard SSH ports
- [ ] Implement proper firewall rules
- [ ] Use VPN or private networks for sensitive connections
- [ ] Enable connection rate limiting

**Cryptography**
- [ ] Use strong key sizes (Ed25519 or RSA 4096+)
- [ ] Disable weak algorithms
- [ ] Regularly update cryptographic libraries
- [ ] Use hardware security modules when available

**Monitoring**
- [ ] Log all SSH connections and authentication attempts
- [ ] Monitor for suspicious activity
- [ ] Implement alerting for security events
- [ ] Regular security audits

**Data Protection**
- [ ] Encrypt sensitive data at rest
- [ ] Use secure channels for key distribution
- [ ] Implement proper access controls
- [ ] Regular backup and recovery testing

Common Security Pitfalls
-------------------------

Avoid these common mistakes:

1. **Using AutoAddPolicy in production** - Always verify host keys
2. **Hardcoding credentials** - Use secure credential management
3. **Ignoring certificate validation** - Always validate certificates
4. **Using weak algorithms** - Stick to modern, strong algorithms
5. **Insufficient logging** - Monitor all security-relevant events
6. **Not updating dependencies** - Keep cryptographic libraries current
7. **Storing keys insecurely** - Use proper file permissions and encryption

Security Resources
------------------

* `NIST Cybersecurity Framework <https://www.nist.gov/cyberframework>`_
* `OpenSSH Security Guidelines <https://www.openssh.com/security.html>`_
* `SSH Protocol RFCs <https://tools.ietf.org/rfc/rfc4251.txt>`_
* `Cryptography Best Practices <https://cryptography.io/en/latest/>`_