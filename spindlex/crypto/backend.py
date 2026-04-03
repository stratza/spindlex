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
        'hmac-sha2-256': hashes.SHA256,
        'hmac-sha2-512': hashes.SHA512,
        'hmac-sha256': hashes.SHA256,  # Alias
        'hmac-sha512': hashes.SHA512,  # Alias
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
            
            # Ensure data is bytes (not bytearray)
            data_bytes = bytes(data)
            
            hash_class = self.HASH_ALGORITHMS[algorithm]
            digest = hashes.Hash(hash_class(), backend=self.backend)
            digest.update(data_bytes)
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
            # Ensure all inputs are bytes
            key_bytes = bytes(key)
            iv_bytes = bytes(iv)
            data_bytes = bytes(data)
            
            if algorithm == "chacha20-poly1305@openssh.com":
                cipher = ChaCha20Poly1305(key_bytes)
                return cipher.encrypt(iv_bytes, data_bytes, None)
            elif algorithm in ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]:
                cipher = AESGCM(key_bytes)
                return cipher.encrypt(iv_bytes, data_bytes, None)
            elif algorithm == "aes256-ctr":
                cipher_algo = algorithms.AES(key_bytes)
                mode = modes.CTR(iv_bytes)
                cipher = Cipher(cipher_algo, mode, backend=self.backend)
                encryptor = cipher.encryptor()
                return encryptor.update(data_bytes) + encryptor.finalize()
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
            # Ensure all inputs are bytes
            key_bytes = bytes(key)
            iv_bytes = bytes(iv)
            data_bytes = bytes(data)
            
            if algorithm == "chacha20-poly1305@openssh.com":
                cipher = ChaCha20Poly1305(key_bytes)
                return cipher.decrypt(iv_bytes, data_bytes, None)
            elif algorithm in ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]:
                cipher = AESGCM(key_bytes)
                return cipher.decrypt(iv_bytes, data_bytes, None)
            elif algorithm == "aes256-ctr":
                cipher_algo = algorithms.AES(key_bytes)
                mode = modes.CTR(iv_bytes)
                cipher = Cipher(cipher_algo, mode, backend=self.backend)
                decryptor = cipher.decryptor()
                return decryptor.update(data_bytes) + decryptor.finalize()
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
            # Ensure all inputs are bytes
            key_bytes = bytes(key)
            iv_bytes = bytes(iv)
            
            if algorithm in ["aes128-ctr", "aes192-ctr", "aes256-ctr"]:
                cipher_algo = algorithms.AES(key_bytes)
                mode = modes.CTR(iv_bytes)
                return Cipher(cipher_algo, mode, backend=self.backend)
            elif algorithm == "chacha20-poly1305@openssh.com":
                return ChaCha20Poly1305(key_bytes)
            elif algorithm in ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]:
                return AESGCM(key_bytes)
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
            
            # Ensure all inputs are bytes
            key_bytes = bytes(key)
            data_bytes = bytes(data)
            
            hash_class = self.MAC_ALGORITHMS[algorithm]
            h = hmac.HMAC(key_bytes, hash_class(), backend=self.backend)
            h.update(data_bytes)
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
            
            # Ensure all inputs are bytes
            shared_secret_bytes = bytes(shared_secret)
            exchange_hash_bytes = bytes(exchange_hash)
            key_type_bytes = bytes(key_type)
            session_id_bytes = bytes(session_id)
            
            # SSH key derivation: K || H || key_type || session_id
            initial_data = shared_secret_bytes + exchange_hash_bytes + key_type_bytes + session_id_bytes
            
            # Hash the initial data
            digest = hashes.Hash(hash_class(), backend=self.backend)
            digest.update(initial_data)
            key_material = digest.finalize()
            
            # Extend key material if needed
            while len(key_material) < key_length:
                digest = hashes.Hash(hash_class(), backend=self.backend)
                digest.update(shared_secret_bytes + exchange_hash_bytes + key_material)
                key_material += digest.finalize()
            
            return key_material[:key_length]
        except Exception as e:
            raise CryptoException(f"Key derivation failed: {e}")


# Default backend instance
default_crypto_backend = CryptographyBackend()


def get_crypto_backend() -> CryptoBackend:
    """
    Get the default cryptographic backend.

    Returns:
        Default CryptoBackend instance
    """
    return default_crypto_backend