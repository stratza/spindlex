Cryptography API
================

Crypto Backend
--------------

.. automodule:: spindlex.crypto.backend
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.backend.CryptoBackend
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.backend.CryptographyBackend
   :members:
   :undoc-members:
   :show-inheritance:

Public Key Cryptography
-----------------------

.. automodule:: spindlex.crypto.pkey
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.pkey.PKey
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.pkey.Ed25519Key
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.pkey.ECDSAKey
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.pkey.RSAKey
   :members:
   :undoc-members:
   :show-inheritance:

Ciphers and Encryption
----------------------

.. automodule:: spindlex.crypto.ciphers
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.ciphers.Cipher
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.ciphers.ChaCha20Poly1305
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.ciphers.AESGCMCipher
   :members:
   :undoc-members:
   :show-inheritance:

.. autoclass:: spindlex.crypto.ciphers.AESCTRCipher
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
    ciphers = backend.get_supported_ciphers()
    macs = backend.get_supported_macs()
    kex_algorithms = backend.get_supported_kex()
    
    # Create cipher
    cipher = backend.create_cipher('chacha20-poly1305@openssh.com', key, iv)
    
    # Encrypt/decrypt
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)

Digital Signatures::

    from spindlex.crypto.pkey import Ed25519Key
    
    key = Ed25519Key.generate()
    
    # Sign data
    message = b"Hello, World!"
    signature = key.sign_ssh_data(message)
    
    # Verify signature
    public_key = key.get_public_key()
    is_valid = public_key.verify_ssh_sig(message, signature)