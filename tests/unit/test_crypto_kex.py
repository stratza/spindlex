"""
Tests for SSH key exchange algorithms.

Tests Curve25519, ECDH, and Diffie-Hellman key exchange implementations.
"""

import pytest
import os
from ssh_library.crypto.kex import (
    KeyExchange, KeyExchangeManager, Curve25519KeyExchange, 
    ECDHKeyExchange, DHGroup14KeyExchange
)
from ssh_library.exceptions import CryptoException


class TestCurve25519KeyExchange:
    """Test Curve25519 key exchange implementation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.kex = Curve25519KeyExchange()
    
    def test_generate_keypair(self):
        """Test Curve25519 key pair generation."""
        public_key = self.kex.generate_keypair()
        
        # Curve25519 public keys are 32 bytes
        assert len(public_key) == 32
        assert isinstance(public_key, bytes)
        assert self.kex.private_key is not None
        assert self.kex.public_key is not None
    
    def test_compute_shared_secret(self):
        """Test Curve25519 shared secret computation."""
        # Generate two key pairs
        kex1 = Curve25519KeyExchange()
        kex2 = Curve25519KeyExchange()
        
        public_key1 = kex1.generate_keypair()
        public_key2 = kex2.generate_keypair()
        
        # Compute shared secrets
        shared_secret1 = kex1.compute_shared_secret(public_key2)
        shared_secret2 = kex2.compute_shared_secret(public_key1)
        
        # Shared secrets should match
        assert shared_secret1 == shared_secret2
        assert len(shared_secret1) == 32
    
    def test_invalid_public_key(self):
        """Test handling of invalid public key."""
        self.kex.generate_keypair()
        
        # Test wrong length
        with pytest.raises(CryptoException):
            self.kex.compute_shared_secret(b"invalid_key")
        
        # Test no private key
        kex_no_key = Curve25519KeyExchange()
        with pytest.raises(CryptoException):
            kex_no_key.compute_shared_secret(os.urandom(32))


class TestECDHKeyExchange:
    """Test ECDH key exchange implementation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.kex = ECDHKeyExchange()
    
    def test_generate_keypair(self):
        """Test ECDH key pair generation."""
        public_key = self.kex.generate_keypair()
        
        # ECDH P-256 public keys are 65 bytes (uncompressed point)
        assert len(public_key) == 65
        assert public_key[0] == 0x04  # Uncompressed point marker
        assert isinstance(public_key, bytes)
        assert self.kex.private_key is not None
        assert self.kex.public_key is not None
    
    def test_compute_shared_secret(self):
        """Test ECDH shared secret computation."""
        # Generate two key pairs
        kex1 = ECDHKeyExchange()
        kex2 = ECDHKeyExchange()
        
        public_key1 = kex1.generate_keypair()
        public_key2 = kex2.generate_keypair()
        
        # Compute shared secrets
        shared_secret1 = kex1.compute_shared_secret(public_key2)
        shared_secret2 = kex2.compute_shared_secret(public_key1)
        
        # Shared secrets should match
        assert shared_secret1 == shared_secret2
        assert len(shared_secret1) == 32  # P-256 coordinate is 32 bytes
    
    def test_invalid_public_key(self):
        """Test handling of invalid public key."""
        self.kex.generate_keypair()
        
        # Test wrong length
        with pytest.raises(CryptoException):
            self.kex.compute_shared_secret(b"invalid_key")
        
        # Test wrong format (not uncompressed point)
        invalid_key = b"\x02" + os.urandom(64)
        with pytest.raises(CryptoException):
            self.kex.compute_shared_secret(invalid_key)
        
        # Test no private key
        kex_no_key = ECDHKeyExchange()
        with pytest.raises(CryptoException):
            kex_no_key.compute_shared_secret(os.urandom(65))


class TestDHGroup14KeyExchange:
    """Test Diffie-Hellman Group 14 key exchange implementation."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.kex = DHGroup14KeyExchange()
    
    def test_generate_keypair(self):
        """Test DH Group 14 key pair generation."""
        public_key = self.kex.generate_keypair()
        
        # DH Group 14 public keys are 256 bytes (2048 bits)
        assert len(public_key) == 256
        assert isinstance(public_key, bytes)
        assert self.kex.private_key is not None
        assert self.kex.public_key is not None
    
    def test_compute_shared_secret(self):
        """Test DH Group 14 shared secret computation."""
        # Generate two key pairs
        kex1 = DHGroup14KeyExchange()
        kex2 = DHGroup14KeyExchange()
        
        public_key1 = kex1.generate_keypair()
        public_key2 = kex2.generate_keypair()
        
        # Compute shared secrets
        shared_secret1 = kex1.compute_shared_secret(public_key2)
        shared_secret2 = kex2.compute_shared_secret(public_key1)
        
        # Shared secrets should match
        assert shared_secret1 == shared_secret2
        assert len(shared_secret1) <= 256  # Up to 256 bytes for Group 14
    
    def test_invalid_public_key(self):
        """Test handling of invalid public key."""
        self.kex.generate_keypair()
        
        # Test invalid key values (0, 1, p-1)
        invalid_keys = [
            b"\x00" * 256,  # 0
            b"\x00" * 255 + b"\x01",  # 1
        ]
        
        for invalid_key in invalid_keys:
            with pytest.raises(CryptoException):
                self.kex.compute_shared_secret(invalid_key)
        
        # Test no private key
        kex_no_key = DHGroup14KeyExchange()
        with pytest.raises(CryptoException):
            kex_no_key.compute_shared_secret(os.urandom(256))


class TestKeyExchangeManager:
    """Test key exchange manager functionality."""
    
    def setup_method(self):
        """Set up test fixtures."""
        self.manager = KeyExchangeManager()
    
    def test_create_kex(self):
        """Test key exchange instance creation."""
        # Test Curve25519
        kex_curve25519 = self.manager.create_kex("curve25519-sha256")
        assert isinstance(kex_curve25519, Curve25519KeyExchange)
        
        # Test ECDH
        kex_ecdh = self.manager.create_kex("ecdh-sha2-nistp256")
        assert isinstance(kex_ecdh, ECDHKeyExchange)
        
        # Test DH Group 14
        kex_dh = self.manager.create_kex("diffie-hellman-group14-sha256")
        assert isinstance(kex_dh, DHGroup14KeyExchange)
        
        # Test unsupported algorithm
        with pytest.raises(CryptoException):
            self.manager.create_kex("unsupported-kex")
    
    def test_get_hash_algorithm(self):
        """Test hash algorithm retrieval."""
        # All current KEX methods use SHA-256
        algorithms = [
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group14-sha256"
        ]
        
        for algorithm in algorithms:
            hash_algo = self.manager.get_hash_algorithm(algorithm)
            assert hash_algo == "sha256"
        
        # Test unsupported algorithm
        with pytest.raises(CryptoException):
            self.manager.get_hash_algorithm("unknown-kex")
    
    def test_negotiate_algorithm(self):
        """Test algorithm negotiation."""
        client_algorithms = [
            "diffie-hellman-group14-sha256",
            "ecdh-sha2-nistp256",
            "curve25519-sha256"
        ]
        server_algorithms = [
            "curve25519-sha256",
            "ecdh-sha2-nistp256"
        ]
        
        # Should select curve25519 (highest preference mutually supported)
        negotiated = self.manager.negotiate_algorithm(client_algorithms, server_algorithms)
        assert negotiated == "curve25519-sha256"
        
        # Test no common algorithms
        client_only = ["diffie-hellman-group14-sha256"]
        server_only = ["curve25519-sha256"]
        
        with pytest.raises(CryptoException):
            self.manager.negotiate_algorithm(client_only, server_only)
    
    def test_full_key_exchange_workflow(self):
        """Test complete key exchange workflow."""
        # Test each supported algorithm
        algorithms = [
            "curve25519-sha256",
            "ecdh-sha2-nistp256", 
            "diffie-hellman-group14-sha256"
        ]
        
        for algorithm in algorithms:
            # Create two KEX instances
            kex1 = self.manager.create_kex(algorithm)
            kex2 = self.manager.create_kex(algorithm)
            
            # Generate key pairs
            public_key1 = kex1.generate_keypair()
            public_key2 = kex2.generate_keypair()
            
            # Compute shared secrets
            shared_secret1 = kex1.compute_shared_secret(public_key2)
            shared_secret2 = kex2.compute_shared_secret(public_key1)
            
            # Verify shared secrets match
            assert shared_secret1 == shared_secret2
            assert len(shared_secret1) > 0
            
            # Verify hash algorithm
            hash_algo = self.manager.get_hash_algorithm(algorithm)
            assert hash_algo == "sha256"