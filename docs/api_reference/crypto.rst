Cryptography API
================

Crypto Backend
--------------

.. automodule:: spindlex.crypto.backend
   :members:
   :undoc-members:
   :show-inheritance:

Public Key Cryptography
-----------------------

.. automodule:: spindlex.crypto.pkey
   :members:
   :undoc-members:
   :show-inheritance:

Ciphers and Encryption
----------------------

.. automodule:: spindlex.crypto.ciphers
   :members:
   :undoc-members:
   :show-inheritance:

Example Usage
-------------

Key Generation::

    from spindlex.crypto.pkey import Ed25519Key, RSAKey, ECDSAKey
    
    # Generate Ed25519 key (recommended)
    ed25519_key = Ed25519Key.generate()
    
    # Generate RSA key
    rsa_key = RSAKey.generate(4096)
    
    # Generate ECDSA key
    ecdsa_key = ECDSAKey.generate()
    
    # Save key with passphrase
    ed25519_key.save_to_file('/path/to/key', password='passphrase')

Key Loading::

    # Load from file
    key = Ed25519Key.from_private_key_file('/path/to/key', password='passphrase')
    
    # Load from string
    key_data = open('/path/to/key').read()
    key = Ed25519Key.from_private_key(key_data, password='passphrase')
    
    # Get public key
    public_key = key.get_public_key()
    
    # Get fingerprint
    fingerprint = key.get_fingerprint()

Crypto Backend Usage::

    from spindlex.crypto.backend import get_crypto_backend
    
    backend = get_crypto_backend()
    
    # Get supported algorithms
    # ciphers = backend.ENCRYPTION_ALGORITHMS (in CipherSuite)
    
    # Create cipher
    cipher = backend.create_cipher('chacha20-poly1305@openssh.com', key, iv)
    
    # Encrypt/decrypt
    encrypted = backend.encrypt('aes256-ctr', key, iv, plaintext)
    decrypted = backend.decrypt('aes256-ctr', key, iv, encrypted)

Digital Signatures::

    from spindlex.crypto.pkey import Ed25519Key
    
    key = Ed25519Key.generate()
    
    # Sign data
    message = b"Hello, World!"
    signature = key.sign(message)
    
    # Verify signature
    is_valid = key.verify(message, signature)
