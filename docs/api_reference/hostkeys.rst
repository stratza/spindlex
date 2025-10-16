Host Keys API
=============

Host Key Policies
-----------------

.. automodule:: ssh_library.hostkeys.policy
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.hostkeys.policy.MissingHostKeyPolicy
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.hostkeys.policy.AutoAddPolicy
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.hostkeys.policy.RejectPolicy
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.hostkeys.policy.WarningPolicy
   :members:
   :undoc-members:
   :show-inheritance:

Host Key Storage
----------------

.. automodule:: ssh_library.hostkeys.storage
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.hostkeys.storage.HostKeys
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: ssh_library.hostkeys.storage.HostKeyEntry
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Basic Host Key Policy::

    from ssh_library import SSHClient
    from ssh_library.hostkeys.policy import AutoAddPolicy, RejectPolicy
    
    client = SSHClient()
    
    # Automatically add unknown host keys (development only)
    client.set_missing_host_key_policy(AutoAddPolicy())
    
    # Reject unknown host keys (production)
    client.set_missing_host_key_policy(RejectPolicy())

Custom Host Key Policy::

    from ssh_library.hostkeys.policy import MissingHostKeyPolicy
    from ssh_library.exceptions import SSHException
    import logging
    
    class CustomHostKeyPolicy(MissingHostKeyPolicy):
        def __init__(self, trusted_fingerprints):
            self.trusted_fingerprints = trusted_fingerprints
        
        def missing_host_key(self, client, hostname, key):
            fingerprint = key.get_fingerprint()
            
            if fingerprint in self.trusted_fingerprints:
                # Add to client's host keys
                client.get_host_keys().add(hostname, key.get_name(), key)
                logging.info(f"Added trusted host key for {hostname}")
            else:
                logging.warning(f"Rejected untrusted host key for {hostname}: {fingerprint}")
                raise SSHException(f"Untrusted host key for {hostname}")

Host Key Management::

    from ssh_library.hostkeys.storage import HostKeys
    
    # Load host keys from file
    host_keys = HostKeys()
    host_keys.load('/home/user/.ssh/known_hosts')
    
    # Check if host key exists
    if host_keys.check('example.com', key):
        print("Host key is known")
    
    # Add new host key
    host_keys.add('newserver.com', key.get_name(), key)
    
    # Save host keys
    host_keys.save('/home/user/.ssh/known_hosts')

Host Key Verification::

    from ssh_library import SSHClient, BadHostKeyException
    from ssh_library.hostkeys.policy import RejectPolicy
    
    client = SSHClient()
    client.set_missing_host_key_policy(RejectPolicy())
    
    try:
        client.connect('example.com', username='user', password='pass')
    except BadHostKeyException as e:
        print(f"Host key verification failed: {e}")
        # Handle appropriately - don't ignore!
        
        # Option 1: Manually verify and add
        # fingerprint = e.key.get_fingerprint()
        # if verify_fingerprint_out_of_band(fingerprint):
        #     client.get_host_keys().add(e.hostname, e.key.get_name(), e.key)
        #     client.connect('example.com', username='user', password='pass')
        
        # Option 2: Reject connection
        raise

Fingerprint Verification::

    from ssh_library.crypto.pkey import Ed25519Key
    
    # Load host key
    key = Ed25519Key.from_public_key_file('/etc/ssh/ssh_host_ed25519_key.pub')
    
    # Get different fingerprint formats
    md5_fingerprint = key.get_fingerprint()  # Default MD5
    sha256_fingerprint = key.get_fingerprint('sha256')
    
    print(f"MD5: {md5_fingerprint}")
    print(f"SHA256: {sha256_fingerprint}")
    
    # Compare fingerprints
    expected_fingerprint = "SHA256:abc123..."
    if sha256_fingerprint == expected_fingerprint:
        print("Host key verified!")
    else:
        print("Host key verification failed!")