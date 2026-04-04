"""
SSH Key Exchange Algorithms

Implements SSH key exchange algorithms including Curve25519, ECDH, and
Diffie-Hellman with algorithm negotiation logic.
"""

import struct
from typing import Any, Dict, Optional, Tuple

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, ec, x25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from ..exceptions import CryptoException
from .backend import CryptoBackend, default_crypto_backend


class KeyExchange:
    """
    Base class for SSH key exchange algorithms.

    Provides common interface for different key exchange implementations
    with support for key generation, exchange, and shared secret computation.
    """

    def __init__(self, crypto_backend: Optional[CryptoBackend] = None) -> None:
        """
        Initialize key exchange.

        Args:
            crypto_backend: Cryptographic backend to use
        """
        self.crypto_backend = crypto_backend or default_crypto_backend
        self.private_key: Any = None
        self.public_key: Any = None

    def generate_keypair(self) -> bytes:
        """
        Generate key pair and return public key.

        Returns:
            Public key bytes for transmission

        Raises:
            CryptoException: If key generation fails
        """
        raise NotImplementedError("Subclasses must implement generate_keypair")

    def compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        """
        Compute shared secret from peer's public key.

        Args:
            peer_public_key: Peer's public key bytes

        Returns:
            Shared secret bytes

        Raises:
            CryptoException: If shared secret computation fails
        """
        raise NotImplementedError("Subclasses must implement compute_shared_secret")


class Curve25519KeyExchange(KeyExchange):
    """
    Curve25519 key exchange implementation.

    Implements curve25519-sha256 key exchange algorithm using X25519
    elliptic curve Diffie-Hellman.
    """

    def generate_keypair(self) -> bytes:
        """
        Generate Curve25519 key pair.

        Returns:
            32-byte public key for transmission

        Raises:
            CryptoException: If key generation fails
        """
        try:
            self.private_key = x25519.X25519PrivateKey.generate()
            self.public_key = self.private_key.public_key()

            # Return raw 32-byte public key
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
        except Exception as e:
            raise CryptoException(f"Curve25519 key generation failed: {e}")

    def compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        """
        Compute shared secret using peer's Curve25519 public key.

        Args:
            peer_public_key: 32-byte peer public key

        Returns:
            32-byte shared secret

        Raises:
            CryptoException: If shared secret computation fails
        """
        try:
            if len(peer_public_key) != 32:
                raise CryptoException("Invalid Curve25519 public key length")

            if self.private_key is None:
                raise CryptoException("Private key not generated")

            # Load peer's public key
            peer_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key)

            # Perform key exchange
            shared_secret = self.private_key.exchange(peer_key)
            return shared_secret
        except Exception as e:
            raise CryptoException(f"Curve25519 shared secret computation failed: {e}")


class ECDHKeyExchange(KeyExchange):
    """
    ECDH key exchange implementation.

    Implements ecdh-sha2-nistp256 key exchange algorithm using NIST P-256
    elliptic curve.
    """

    def __init__(self, crypto_backend: Optional[CryptoBackend] = None) -> None:
        """Initialize ECDH key exchange with P-256 curve."""
        super().__init__(crypto_backend)
        self.curve = ec.SECP256R1()

    def generate_keypair(self) -> bytes:
        """
        Generate ECDH key pair on NIST P-256 curve.

        Returns:
            Uncompressed point public key (65 bytes: 0x04 + 32-byte x + 32-byte y)

        Raises:
            CryptoException: If key generation fails
        """
        try:
            self.private_key = ec.generate_private_key(self.curve, default_backend())
            self.public_key = self.private_key.public_key()

            # Return uncompressed point format
            return self.public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
        except Exception as e:
            raise CryptoException(f"ECDH key generation failed: {e}")

    def compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        """
        Compute shared secret using peer's ECDH public key.

        Args:
            peer_public_key: Peer's uncompressed point public key

        Returns:
            Shared secret (x-coordinate of shared point)

        Raises:
            CryptoException: If shared secret computation fails
        """
        try:
            if len(peer_public_key) != 65 or peer_public_key[0] != 0x04:
                raise CryptoException("Invalid ECDH public key format")

            if self.private_key is None:
                raise CryptoException("Private key not generated")

            # Load peer's public key
            peer_key = ec.EllipticCurvePublicKey.from_encoded_point(
                self.curve, peer_public_key
            )

            # Perform ECDH
            shared_secret = self.private_key.exchange(ec.ECDH(), peer_key)
            return shared_secret
        except Exception as e:
            raise CryptoException(f"ECDH shared secret computation failed: {e}")


class DHGroup14KeyExchange(KeyExchange):
    """
    Diffie-Hellman Group 14 key exchange implementation.

    Implements diffie-hellman-group14-sha256 using RFC 3526 2048-bit MODP group.
    """

    # RFC 3526 Group 14 parameters (2048-bit MODP)
    GROUP14_P = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16,
    )
    GROUP14_G = 2

    def __init__(self, crypto_backend: Optional[CryptoBackend] = None) -> None:
        """Initialize DH Group 14 key exchange."""
        super().__init__(crypto_backend)

        # Create DH parameters
        self.parameters = dh.DHParameterNumbers(
            p=self.GROUP14_P, g=self.GROUP14_G
        ).parameters(default_backend())

    def generate_keypair(self) -> bytes:
        """
        Generate DH key pair.

        Returns:
            Public key as big-endian integer bytes

        Raises:
            CryptoException: If key generation fails
        """
        try:
            self.private_key = self.parameters.generate_private_key()
            self.public_key = self.private_key.public_key()

            # Get public key as integer and convert to bytes
            public_numbers = self.public_key.public_numbers()
            public_int = public_numbers.y

            # Convert to big-endian bytes with proper padding
            byte_length = (self.GROUP14_P.bit_length() + 7) // 8
            return public_int.to_bytes(byte_length, "big")
        except Exception as e:
            raise CryptoException(f"DH Group 14 key generation failed: {e}")

    def compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        """
        Compute shared secret using peer's DH public key.

        Args:
            peer_public_key: Peer's public key as big-endian bytes

        Returns:
            Shared secret as big-endian bytes

        Raises:
            CryptoException: If shared secret computation fails
        """
        try:
            if self.private_key is None:
                raise CryptoException("Private key not generated")

            # Convert peer public key bytes to integer
            peer_public_int = int.from_bytes(peer_public_key, "big")

            # Validate peer public key
            if peer_public_int <= 1 or peer_public_int >= self.GROUP14_P - 1:
                raise CryptoException("Invalid DH public key value")

            # Create peer public key object
            peer_public_numbers = dh.DHPublicNumbers(
                y=peer_public_int, parameter_numbers=self.parameters.parameter_numbers()
            )
            peer_key = peer_public_numbers.public_key(default_backend())

            # Perform DH exchange
            shared_secret = self.private_key.exchange(peer_key)
            return shared_secret
        except Exception as e:
            raise CryptoException(f"DH Group 14 shared secret computation failed: {e}")


class KeyExchangeManager:
    """
    Key exchange algorithm manager.

    Manages different key exchange algorithms and provides algorithm
    negotiation and instantiation functionality.
    """

    # Supported key exchange algorithms
    ALGORITHMS = {
        "curve25519-sha256": Curve25519KeyExchange,
        "ecdh-sha2-nistp256": ECDHKeyExchange,
        "diffie-hellman-group14-sha256": DHGroup14KeyExchange,
    }

    # Hash algorithms for each KEX method
    KEX_HASH_ALGORITHMS = {
        "curve25519-sha256": "sha256",
        "ecdh-sha2-nistp256": "sha256",
        "diffie-hellman-group14-sha256": "sha256",
    }

    def __init__(self, crypto_backend: Optional[CryptoBackend] = None) -> None:
        """
        Initialize key exchange manager.

        Args:
            crypto_backend: Cryptographic backend to use
        """
        self.crypto_backend = crypto_backend or default_crypto_backend

    def create_kex(self, algorithm: str) -> KeyExchange:
        """
        Create key exchange instance for specified algorithm.

        Args:
            algorithm: Key exchange algorithm name

        Returns:
            KeyExchange instance

        Raises:
            CryptoException: If algorithm is unsupported
        """
        if algorithm not in self.ALGORITHMS:
            raise CryptoException(f"Unsupported key exchange algorithm: {algorithm}")

        kex_class = self.ALGORITHMS[algorithm]
        return kex_class(self.crypto_backend)

    def get_hash_algorithm(self, kex_algorithm: str) -> str:
        """
        Get hash algorithm for key exchange method.

        Args:
            kex_algorithm: Key exchange algorithm name

        Returns:
            Hash algorithm name

        Raises:
            CryptoException: If algorithm is unsupported
        """
        if kex_algorithm not in self.KEX_HASH_ALGORITHMS:
            raise CryptoException(f"Unknown key exchange algorithm: {kex_algorithm}")

        return self.KEX_HASH_ALGORITHMS[kex_algorithm]

    def negotiate_algorithm(
        self, client_algorithms: list, server_algorithms: list
    ) -> str:
        """
        Negotiate key exchange algorithm between client and server.

        Args:
            client_algorithms: Client's supported KEX algorithms
            server_algorithms: Server's supported KEX algorithms

        Returns:
            Negotiated algorithm name

        Raises:
            CryptoException: If no compatible algorithm found
        """
        # Find first mutually supported algorithm in preference order
        for algorithm in [
            "curve25519-sha256",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group14-sha256",
        ]:
            if algorithm in client_algorithms and algorithm in server_algorithms:
                return algorithm

        raise CryptoException("No compatible key exchange algorithm found")
