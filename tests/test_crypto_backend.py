"""
Tests for SSH cryptographic backend functionality.

Tests crypto backend abstraction, cipher operations, and key derivation.
"""

import pytest
import os
from ssh_library.crypto.backend import CryptographyBackend, default_crypto_backend
from ssh_library.exceptions import CryptoException


class TestCryptographyBackend:
    """Test CryptographyBackend implementation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.backend = CryptographyBackend()
    
    def test_generate_random(self):
        """Test random byte generation."""
        # Test different lengths
        for length in [16, 32, 64]:
            random_bytes = self.backend.generate_random(length)
            assert len(random_bytes) == length
            assert isinstance(random_bytes, bytes)
        
        # Test that different calls produce different results
        random1 = self.backend.generate_random(32)
        random2 = self.backend.generate_random(32)
        assert random1 != random2
    
    def test_hash_data(self):
        """Test hash operations."""
        test_data = b"Hello, SSH!"
        
        # Test SHA-256
        hash_sha256 = self.backend.hash_data("sha256", test_data)
        assert len(hash_sha256) == 32
        
        # Test SHA-512
        hash_sha512 = self.backend.hash_data("sha512", test_data)
        assert len(hash_sha512) == 64
        
        # Test SHA-1
        hash_sha1 = self.backend.hash_data("sha1", test_data)
        assert len(hash_sha1) == 20
        
        # Test consistency
        hash2 = self.backend.hash_data("sha256", test_data)
        assert hash_sha256 == hash2
        
        # Test unsupported algorithm
        with pytest.raises(CryptoException):
            self.backend.hash_data("md4", test_data)
    
    def test_aes_ctr_encryption(self):
        """Test AES-CTR encryption/decryption."""
        key = os.urandom(32)  # AES-256 key
        iv = os.urandom(16)   # AES block size
        plaintext = b"This is a test message for AES-CTR encryption!"
        
        # Encrypt
        ciphertext = self.backend.encrypt("aes256-ctr", key, iv, plaintext)
        assert len(ciphertext) == len(plaintext)
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = self.backend.decrypt("aes256-ctr", key, iv, ciphertext)
        assert decrypted == plaintext
    
    def test_chacha20_poly1305_encryption(self):
        """Test ChaCha20-Poly1305 AEAD encryption/decryption."""
        key = os.urandom(32)  # ChaCha20 key
        nonce = os.urandom(12)  # ChaCha20-Poly1305 nonce
        plaintext = b"This is a test message for ChaCha20-Poly1305!"
        
        # Encrypt (includes authentication tag)
        ciphertext = self.backend.encrypt("chacha20-poly1305@openssh.com", key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext) + 16  # +16 for auth tag
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = self.backend.decrypt("chacha20-poly1305@openssh.com", key, nonce, ciphertext)
        assert decrypted == plaintext
    
    def test_aes_gcm_encryption(self):
        """Test AES-GCM AEAD encryption/decryption."""
        key = os.urandom(32)  # AES-256 key
        nonce = os.urandom(12)  # GCM nonce
        plaintext = b"This is a test message for AES-GCM!"
        
        # Encrypt (includes authentication tag)
        ciphertext = self.backend.encrypt("aes256-gcm@openssh.com", key, nonce, plaintext)
        assert len(ciphertext) == len(plaintext) + 16  # +16 for auth tag
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = self.backend.decrypt("aes256-gcm@openssh.com", key, nonce, ciphertext)
        assert decrypted == plaintext
    
    def test_unsupported_cipher(self):
        """Test unsupported cipher algorithm."""
        key = os.urandom(32)
        iv = os.urandom(16)
        data = b"test data"
        
        with pytest.raises(CryptoException):
            self.backend.encrypt("unsupported-cipher", key, iv, data)
        
        with pytest.raises(CryptoException):
            self.backend.decrypt("unsupported-cipher", key, iv, data)
    
    def test_create_cipher(self):
        """Test cipher instance creation for streaming."""
        key = os.urandom(32)
        iv = os.urandom(16)
        
        # Test AES-CTR cipher creation
        cipher = self.backend.create_cipher("aes256-ctr", key, iv)
        assert cipher is not None
        
        # Test unsupported streaming cipher
        with pytest.raises(CryptoException):
            self.backend.create_cipher("chacha20-poly1305@openssh.com", key, iv)
    
    def test_compute_mac(self):
        """Test MAC computation."""
        key = os.urandom(32)
        data = b"Test data for MAC computation"
        
        # Test HMAC-SHA256
        mac_sha256 = self.backend.compute_mac("hmac-sha256", key, data)
        assert len(mac_sha256) == 32
        
        # Test HMAC-SHA512
        mac_sha512 = self.backend.compute_mac("hmac-sha512", key, data)
        assert len(mac_sha512) == 64
        
        # Test HMAC-SHA1
        mac_sha1 = self.backend.compute_mac("hmac-sha1", key, data)
        assert len(mac_sha1) == 20
        
        # Test consistency
        mac2 = self.backend.compute_mac("hmac-sha256", key, data)
        assert mac_sha256 == mac2
        
        # Test different key produces different MAC
        key2 = os.urandom(32)
        mac_different = self.backend.compute_mac("hmac-sha256", key2, data)
        assert mac_sha256 != mac_different
        
        # Test unsupported MAC algorithm
        with pytest.raises(CryptoException):
            self.backend.compute_mac("hmac-md4", key, data)
    
    def test_derive_key(self):
        """Test SSH key derivation."""
        shared_secret = os.urandom(32)
        exchange_hash = os.urandom(32)
        session_id = os.urandom(32)
        
        # Test different key types
        for key_type in [b'A', b'B', b'C', b'D', b'E', b'F']:
            derived_key = self.backend.derive_key(
                "sha256", shared_secret, exchange_hash, session_id, key_type, 32
            )
            assert len(derived_key) == 32
            assert isinstance(derived_key, bytes)
        
        # Test different key types produce different keys
        key_a = self.backend.derive_key(
            "sha256", shared_secret, exchange_hash, session_id, b'A', 32
        )
        key_b = self.backend.derive_key(
            "sha256", shared_secret, exchange_hash, session_id, b'B', 32
        )
        assert key_a != key_b
        
        # Test key extension for longer keys
        long_key = self.backend.derive_key(
            "sha256", shared_secret, exchange_hash, session_id, b'A', 64
        )
        assert len(long_key) == 64
        assert long_key[:32] == key_a  # First 32 bytes should match
        
        # Test unsupported hash algorithm
        with pytest.raises(CryptoException):
            self.backend.derive_key(
                "md4", shared_secret, exchange_hash, session_id, b'A', 32
            )


def test_default_backend():
    """Test default backend instance."""
    assert default_crypto_backend is not None
    assert isinstance(default_crypto_backend, CryptographyBackend)
    
    # Test basic functionality
    random_data = default_crypto_backend.generate_random(16)
    assert len(random_data) == 16