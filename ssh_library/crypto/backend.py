"""
Cryptographic Backend Abstraction

Provides pluggable cryptographic backend interface with
cryptography library implementation.
"""

import os
from typing import Any, Protocol, Optional, Tuple
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305, AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from ..exceptions import CryptoException


class CryptoBackend(Protocol):
    """
    Cryptographic backend interface.
    
    Defines the interface for pluggable cryptographic backends
    to support different crypto libraries and implementations.
    """
    
    def generate_random(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        ...
    
    def hash_data(self, algorithm: str, data: bytes) -> bytes:
        """Hash data using specified algorithm."""
        ...
    
    def encrypt(self, algorithm: str, key: bytes, iv: bytes, data: bytes) -> bytes:
        """Encrypt data using specified cipher."""
        ...
    
    def decrypt(self, algorithm: str, key: bytes, iv: bytes, data: bytes) -> bytes:
        """Decrypt data using specified cipher."""
        ...
    
    def create_cipher(self, algorithm: str, key: bytes, iv: bytes) -> Any:
        """Create cipher instance for streaming operations."""
        ...
    
    def compute_mac(self, algorithm: str, key: bytes, data: bytes) -> bytes:
        """Compute MAC using specified algorithm."""
        ...
    
    def derive_key(self, algorithm: str, shared_secret: bytes, 
                   exchange_hash: bytes, session_id: bytes, 
                   key_type: bytes, key_length: int) -> bytes:
        """Derive encryption/MAC keys from shared secret."""
        ...


class CryptographyBackend:
    """
    Cryptography library backend implementation.
    
    Implements CryptoBackend interface using the Python cryptography library
    for modern, secure cryptographic operations.
    """
    
    # Hash algorithm mapping
    HASH_ALGORITHMS = {
        'sha1': hashes.SHA1,
        'sha256': hashes.SHA256,
        'sha512': hashes.SHA512,
    }
    
    # MAC algorithm mapping
    MAC_ALGORITHMS = {
        'hmac-sha1': hashes.SHA1,
        'hmac-sha256': hashes.SHA256,
        'hmac-sha512': hashes.SHA512,
    }
    
    def __init__(self) -> None:
        """Initialize cryptography backend."""
        self.backend = default_backend()
    
    def generate_random(self, length: int) -> bytes:
        """
        Generate cryptographically secure random bytes.
        
        Args:
            length: Number of random bytes to generate
            
        Returns:
            Cryptographically secure random bytes
            
        Raises:
            CryptoException: If random generation fails
        """
        try:
            return os.urandom(length)
        except Exception as e:
            raise CryptoException(f"Failed to generate random bytes: {e}")
    
    def hash_data(self, algorithm: str, data: bytes) -> bytes:
        """
        Hash data using specified algorithm.
        
        Args:
            algorithm: Hash algorithm name (sha1, sha256, sha512)
            data: Data to hash
            
        Returns:
            Hash digest
            
        Raises:
            CryptoException: If hashing fails or algorithm unsupported
        """
        try:
            if algorithm not in self.HASH_ALGORITHMS:
                raise CryptoException(f"Unsupported hash algorithm: {algorithm}")
            
            hash_class = self.HASH_ALGORITHMS[algorithm]
            digest = hashes.Hash(hash_class(), backend=self.backend)
            digest.update(data)
            return digest.finalize()
        except Exception as e:
            raise CryptoException(f"Hash operation failed: {e}")
    
    def encrypt(self, algorithm: str, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Encrypt data using specified cipher.
        
        Args:
            algorithm: Cipher algorithm name
            key: Encryption key
            iv: Initialization vector or nonce
            data: Data to encrypt
            
        Returns:
            Encrypted data
            
        Raises:
            CryptoException: If encryption fails or algorithm unsupported
        """
        try:
            if algorithm == "chacha20-poly1305@openssh.com":
                cipher = ChaCha20Poly1305(key)
                return cipher.encrypt(iv, data, None)
            elif algorithm in ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]:
                cipher = AESGCM(key)
                return cipher.encrypt(iv, data, None)
            elif algorithm == "aes256-ctr":
                cipher_algo = algorithms.AES(key)
                mode = modes.CTR(iv)
                cipher = Cipher(cipher_algo, mode, backend=self.backend)
                encryptor = cipher.encryptor()
                return encryptor.update(data) + encryptor.finalize()
            else:
                raise CryptoException(f"Unsupported cipher algorithm: {algorithm}")
        except Exception as e:
            raise CryptoException(f"Encryption failed: {e}")
    
    def decrypt(self, algorithm: str, key: bytes, iv: bytes, data: bytes) -> bytes:
        """
        Decrypt data using specified cipher.
        
        Args:
            algorithm: Cipher algorithm name
            key: Decryption key
            iv: Initialization vector or nonce
            data: Data to decrypt
            
        Returns:
            Decrypted data
            
        Raises:
            CryptoException: If decryption fails or algorithm unsupported
        """
        try:
            if algorithm == "chacha20-poly1305@openssh.com":
                cipher = ChaCha20Poly1305(key)
                return cipher.decrypt(iv, data, None)
            elif algorithm in ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]:
                cipher = AESGCM(key)
                return cipher.decrypt(iv, data, None)
            elif algorithm == "aes256-ctr":
                cipher_algo = algorithms.AES(key)
                mode = modes.CTR(iv)
                cipher = Cipher(cipher_algo, mode, backend=self.backend)
                decryptor = cipher.decryptor()
                return decryptor.update(data) + decryptor.finalize()
            else:
                raise CryptoException(f"Unsupported cipher algorithm: {algorithm}")
        except Exception as e:
            raise CryptoException(f"Decryption failed: {e}")
    
    def create_cipher(self, algorithm: str, key: bytes, iv: bytes) -> Any:
        """
        Create cipher instance for streaming operations.
        
        Args:
            algorithm: Cipher algorithm name
            key: Encryption/decryption key
            iv: Initialization vector
            
        Returns:
            Cipher instance for streaming operations
            
        Raises:
            CryptoException: If cipher creation fails
        """
        try:
            if algorithm == "aes256-ctr":
                cipher_algo = algorithms.AES(key)
                mode = modes.CTR(iv)
                return Cipher(cipher_algo, mode, backend=self.backend)
            else:
                raise CryptoException(f"Streaming cipher not supported for: {algorithm}")
        except Exception as e:
            raise CryptoException(f"Cipher creation failed: {e}")
    
    def compute_mac(self, algorithm: str, key: bytes, data: bytes) -> bytes:
        """
        Compute MAC using specified algorithm.
        
        Args:
            algorithm: MAC algorithm name
            key: MAC key
            data: Data to authenticate
            
        Returns:
            MAC digest
            
        Raises:
            CryptoException: If MAC computation fails
        """
        try:
            if algorithm not in self.MAC_ALGORITHMS:
                raise CryptoException(f"Unsupported MAC algorithm: {algorithm}")
            
            hash_class = self.MAC_ALGORITHMS[algorithm]
            h = hmac.HMAC(key, hash_class(), backend=self.backend)
            h.update(data)
            return h.finalize()
        except Exception as e:
            raise CryptoException(f"MAC computation failed: {e}")
    
    def derive_key(self, algorithm: str, shared_secret: bytes, 
                   exchange_hash: bytes, session_id: bytes, 
                   key_type: bytes, key_length: int) -> bytes:
        """
        Derive encryption/MAC keys from shared secret using SSH key derivation.
        
        Args:
            algorithm: Hash algorithm for key derivation
            shared_secret: Shared secret from key exchange
            exchange_hash: Hash of key exchange
            session_id: Session identifier
            key_type: Key type identifier (A, B, C, D, E, F)
            key_length: Required key length
            
        Returns:
            Derived key
            
        Raises:
            CryptoException: If key derivation fails
        """
        try:
            if algorithm not in self.HASH_ALGORITHMS:
                raise CryptoException(f"Unsupported hash algorithm: {algorithm}")
            
            hash_class = self.HASH_ALGORITHMS[algorithm]
            
            # SSH key derivation: K || H || key_type || session_id
            initial_data = shared_secret + exchange_hash + key_type + session_id
            
            # Hash the initial data
            digest = hashes.Hash(hash_class(), backend=self.backend)
            digest.update(initial_data)
            key_material = digest.finalize()
            
            # Extend key material if needed
            while len(key_material) < key_length:
                digest = hashes.Hash(hash_class(), backend=self.backend)
                digest.update(shared_secret + exchange_hash + key_material)
                key_material += digest.finalize()
            
            return key_material[:key_length]
        except Exception as e:
            raise CryptoException(f"Key derivation failed: {e}")


# Default backend instance
default_crypto_backend = CryptographyBackend()