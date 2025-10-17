"""
Tests for SSH public key handling.

Tests Ed25519, ECDSA, and RSA key implementations with loading,
signing, verification, and fingerprinting functionality.
"""

import base64
import os
import tempfile

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from ssh_library.crypto.pkey import (
    ECDSAKey,
    Ed25519Key,
    PKey,
    RSAKey,
    load_key_from_file,
    load_public_key_from_string,
)
from ssh_library.exceptions import CryptoException


class TestEd25519Key:
    """Test Ed25519 key implementation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.key = Ed25519Key()

        # Generate test key pair
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        # Get PEM format private key
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def test_algorithm_name(self):
        """Test algorithm name property."""
        assert self.key.algorithm_name == "ssh-ed25519"

    def test_load_private_key(self):
        """Test loading Ed25519 private key."""
        self.key.load_private_key(self.private_pem)
        assert self.key._key is not None
        assert isinstance(self.key._key, ed25519.Ed25519PrivateKey)

    def test_load_invalid_private_key(self):
        """Test loading invalid private key."""
        # Test invalid PEM data
        with pytest.raises(CryptoException):
            self.key.load_private_key(b"invalid pem data")

        # Test wrong key type (RSA key)
        rsa_key = rsa.generate_private_key(65537, 2048, default_backend())
        rsa_pem = rsa_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        with pytest.raises(CryptoException):
            self.key.load_private_key(rsa_pem)

    def test_get_public_key_bytes(self):
        """Test getting public key in SSH wire format."""
        self.key.load_private_key(self.private_pem)
        public_key_bytes = self.key.get_public_key_bytes()

        # Should start with algorithm name length and name
        assert public_key_bytes.startswith(b"\x00\x00\x00\x0bssh-ed25519")
        # Total length should be 4 + 11 + 4 + 32 = 51 bytes
        assert len(public_key_bytes) == 51

    def test_load_public_key(self):
        """Test loading public key from SSH wire format."""
        self.key.load_private_key(self.private_pem)
        public_key_bytes = self.key.get_public_key_bytes()

        # Create new key instance and load public key
        public_key_only = Ed25519Key()
        public_key_only.load_public_key(public_key_bytes)

        # Should be able to get the same public key bytes
        assert public_key_only.get_public_key_bytes() == public_key_bytes

    def test_sign_and_verify(self):
        """Test signing and verification."""
        self.key.load_private_key(self.private_pem)
        test_data = b"Hello, SSH signing!"

        # Sign data
        signature = self.key.sign(test_data)
        assert len(signature) > 0

        # Verify signature
        assert self.key.verify(signature, test_data)

        # Verify with wrong data should fail
        assert not self.key.verify(signature, b"wrong data")

    def test_fingerprint(self):
        """Test key fingerprinting."""
        self.key.load_private_key(self.private_pem)

        # Test SHA-256 fingerprint
        fp_sha256 = self.key.get_fingerprint("sha256")
        assert fp_sha256.startswith("SHA256:")
        assert len(fp_sha256) > 10

        # Test MD5 fingerprint
        fp_md5 = self.key.get_fingerprint("md5")
        assert fp_md5.startswith("MD5:")
        assert ":" in fp_md5[4:]  # Should have colon separators

        # Test unsupported algorithm
        with pytest.raises(CryptoException):
            self.key.get_fingerprint("sha1")

    def test_key_equality(self):
        """Test key equality comparison."""
        self.key.load_private_key(self.private_pem)

        # Load same key in another instance
        key2 = Ed25519Key()
        key2.load_private_key(self.private_pem)

        assert self.key == key2
        assert hash(self.key) == hash(key2)

        # Different key should not be equal
        different_key = Ed25519Key()
        different_private = ed25519.Ed25519PrivateKey.generate()
        different_pem = different_private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        different_key.load_private_key(different_pem)

        assert self.key != different_key


class TestECDSAKey:
    """Test ECDSA key implementation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.key = ECDSAKey()

        # Generate test key pair
        self.private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.public_key = self.private_key.public_key()

        # Get PEM format private key
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def test_algorithm_name(self):
        """Test algorithm name property."""
        assert self.key.algorithm_name == "ecdsa-sha2-nistp256"

    def test_load_private_key(self):
        """Test loading ECDSA private key."""
        self.key.load_private_key(self.private_pem)
        assert self.key._key is not None
        assert isinstance(self.key._key, ec.EllipticCurvePrivateKey)

    def test_get_public_key_bytes(self):
        """Test getting public key in SSH wire format."""
        self.key.load_private_key(self.private_pem)
        public_key_bytes = self.key.get_public_key_bytes()

        # Should start with algorithm name
        assert b"ecdsa-sha2-nistp256" in public_key_bytes
        assert b"nistp256" in public_key_bytes
        # Should contain uncompressed point (65 bytes)
        assert len(public_key_bytes) > 80  # Algorithm names + point data

    def test_sign_and_verify(self):
        """Test ECDSA signing and verification."""
        self.key.load_private_key(self.private_pem)
        test_data = b"Hello, ECDSA signing!"

        # Sign data
        signature = self.key.sign(test_data)
        assert len(signature) > 0

        # Verify signature
        assert self.key.verify(signature, test_data)

        # Verify with wrong data should fail
        assert not self.key.verify(signature, b"wrong data")


class TestRSAKey:
    """Test RSA key implementation."""

    def setup_method(self):
        """Set up test fixtures."""
        self.key = RSAKey()

        # Generate test key pair
        self.private_key = rsa.generate_private_key(65537, 2048, default_backend())
        self.public_key = self.private_key.public_key()

        # Get PEM format private key
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    def test_algorithm_name(self):
        """Test algorithm name property."""
        assert self.key.algorithm_name == "rsa-sha2-256"

    def test_load_private_key(self):
        """Test loading RSA private key."""
        self.key.load_private_key(self.private_pem)
        assert self.key._key is not None
        assert isinstance(self.key._key, rsa.RSAPrivateKey)

    def test_get_public_key_bytes(self):
        """Test getting public key in SSH wire format."""
        self.key.load_private_key(self.private_pem)
        public_key_bytes = self.key.get_public_key_bytes()

        # Should start with ssh-rsa algorithm name
        assert b"ssh-rsa" in public_key_bytes
        # Should contain exponent and modulus
        assert len(public_key_bytes) > 200  # RSA 2048 keys are large

    def test_sign_and_verify(self):
        """Test RSA signing and verification."""
        self.key.load_private_key(self.private_pem)
        test_data = b"Hello, RSA signing!"

        # Sign data
        signature = self.key.sign(test_data)
        assert len(signature) > 0

        # Verify signature
        assert self.key.verify(signature, test_data)

        # Verify with wrong data should fail
        assert not self.key.verify(signature, b"wrong data")


class TestKeyLoading:
    """Test key loading utilities."""

    def test_load_key_from_file(self):
        """Test loading key from file."""
        # Generate Ed25519 key
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        # Write to temporary file
        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(private_pem)
            temp_filename = f.name

        try:
            # Load key from file
            loaded_key = load_key_from_file(temp_filename)
            assert isinstance(loaded_key, Ed25519Key)
            assert loaded_key._key is not None
        finally:
            os.unlink(temp_filename)

    def test_load_public_key_from_string(self):
        """Test loading public key from OpenSSH string format."""
        # Generate Ed25519 key and get public key
        private_key = ed25519.Ed25519PrivateKey.generate()
        ed25519_key = Ed25519Key()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        ed25519_key.load_private_key(private_pem)

        # Get public key bytes and create OpenSSH format string
        public_key_bytes = ed25519_key.get_public_key_bytes()
        public_key_b64 = base64.b64encode(public_key_bytes).decode()
        openssh_string = f"ssh-ed25519 {public_key_b64} test@example.com"

        # Load from string
        loaded_key = load_public_key_from_string(openssh_string)
        assert isinstance(loaded_key, Ed25519Key)
        assert loaded_key.get_public_key_bytes() == public_key_bytes

    def test_load_invalid_public_key_string(self):
        """Test loading invalid public key string."""
        # Test invalid format
        with pytest.raises(CryptoException):
            load_public_key_from_string("invalid format")

        # Test unsupported algorithm
        with pytest.raises(CryptoException):
            load_public_key_from_string(
                "unsupported-algo AAAAB3NzaC1yc2E test@example.com"
            )

    def test_no_key_loaded_operations(self):
        """Test operations when no key is loaded."""
        key = Ed25519Key()

        # Should raise exception for operations requiring loaded key
        with pytest.raises(CryptoException):
            key.get_public_key_bytes()

        with pytest.raises(CryptoException):
            key.sign(b"test data")

        with pytest.raises(CryptoException):
            key.get_fingerprint()


def test_key_type_detection():
    """Test automatic key type detection in loading functions."""
    # Test that load_key_from_file can detect different key types
    key_types = [
        (ed25519.Ed25519PrivateKey.generate(), Ed25519Key),
        (ec.generate_private_key(ec.SECP256R1(), default_backend()), ECDSAKey),
        (rsa.generate_private_key(65537, 2048, default_backend()), RSAKey),
    ]

    for private_key, expected_class in key_types:
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with tempfile.NamedTemporaryFile(mode="wb", delete=False) as f:
            f.write(private_pem)
            temp_filename = f.name

        try:
            loaded_key = load_key_from_file(temp_filename)
            assert isinstance(loaded_key, expected_class)
        finally:
            os.unlink(temp_filename)
