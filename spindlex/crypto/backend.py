"""
Cryptographic Backend Abstraction

Provides pluggable cryptographic backend interface with
cryptography library implementation.
"""

import os
import struct
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.poly1305 import Poly1305

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

    def decrypt_length(
        self, algorithm: str, key: bytes, iv: bytes, data: bytes
    ) -> bytes:
        """
        Decrypt only the length field for ciphers that encrypt it.
        """
        ...

    def create_cipher(self, algorithm: str, key: bytes, iv: bytes) -> Any:
        """Create cipher instance for streaming operations."""
        ...

    def compute_mac(self, algorithm: str, key: bytes, data: bytes) -> bytes:
        """Compute MAC using specified algorithm."""
        ...

    def derive_key(
        self,
        algorithm: str,
        shared_secret: bytes,
        exchange_hash: bytes,
        session_id: bytes,
        key_type: bytes,
        key_length: int,
    ) -> bytes:
        """Derive encryption/MAC keys from shared secret."""
        ...

    def chacha20_poly1305_encrypt(
        self, key_64: bytes, seq_num: int, length_bytes: bytes, body_bytes: bytes
    ) -> bytes:
        """Encrypt an SSH packet using chacha20-poly1305@openssh.com."""
        ...

    def chacha20_poly1305_decrypt_length(
        self, key_64: bytes, seq_num: int, enc_length: bytes
    ) -> bytes:
        """Decrypt the 4-byte length field using chacha20-poly1305@openssh.com."""
        ...

    def chacha20_poly1305_decrypt_body(
        self,
        key_64: bytes,
        seq_num: int,
        enc_length: bytes,
        enc_body: bytes,
        tag: bytes,
    ) -> bytes:
        """Verify Poly1305 tag and decrypt the packet body."""
        ...


class CryptographyBackend:
    """
    Cryptography library backend implementation.

    Implements CryptoBackend interface using the Python cryptography library
    for modern, secure cryptographic operations.
    """

    # Hash algorithm mapping — SHA-1 intentionally excluded (weak, not negotiated)
    HASH_ALGORITHMS = {
        "sha256": hashes.SHA256,
        "sha384": hashes.SHA384,
        "sha512": hashes.SHA512,
    }

    # MAC algorithm mapping
    MAC_ALGORITHMS = {
        "hmac-sha2-256": hashes.SHA256,
        "hmac-sha2-512": hashes.SHA512,
        "hmac-sha256": hashes.SHA256,  # Alias
        "hmac-sha512": hashes.SHA512,  # Alias
    }

    def __init__(self) -> None:
        """Initialize cryptography backend."""
        pass

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
            raise CryptoException(f"Failed to generate random bytes: {e}") from e

    def hash_data(self, algorithm: str, data: bytes) -> bytes:
        """
        Hash data using specified algorithm.

        Args:
            algorithm: Hash algorithm name (sha256, sha384, sha512)
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
            digest = hashes.Hash(hash_class())  # type: ignore[abstract]
            digest.update(data_bytes)
            return digest.finalize()
        except CryptoException:
            raise
        except Exception as e:
            raise CryptoException(f"Hash operation failed: {e}") from e

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

            if algorithm in ["aes128-ctr", "aes192-ctr", "aes256-ctr"]:
                cipher_algo = algorithms.AES(key_bytes)
                mode = modes.CTR(iv_bytes)
                cipher = Cipher(cipher_algo, mode)
                encryptor = cipher.encryptor()
                return bytes(encryptor.update(data_bytes) + encryptor.finalize())
            else:
                raise CryptoException(f"Unsupported cipher algorithm: {algorithm}")
        except Exception as e:
            raise CryptoException(f"Encryption failed: {e}") from e

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

            if algorithm in ["aes128-ctr", "aes192-ctr", "aes256-ctr"]:
                cipher_algo = algorithms.AES(key_bytes)
                mode = modes.CTR(iv_bytes)
                cipher = Cipher(cipher_algo, mode)
                decryptor = cipher.decryptor()
                return bytes(decryptor.update(data_bytes) + decryptor.finalize())
            else:
                raise CryptoException(f"Unsupported cipher algorithm: {algorithm}")
        except Exception as e:
            raise CryptoException(f"Decryption failed: {e}") from e

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
                return Cipher(cipher_algo, mode)
            else:
                raise CryptoException(
                    f"Streaming cipher not supported for: {algorithm}"
                )
        except Exception as e:
            raise CryptoException(f"Cipher creation failed: {e}") from e

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
            h = hmac.HMAC(key_bytes, hash_class())  # type: ignore
            h.update(data_bytes)
            return bytes(h.finalize())
        except Exception as e:
            raise CryptoException(f"MAC computation failed: {e}") from e

    def derive_key(
        self,
        algorithm: str,
        shared_secret: bytes,
        exchange_hash: bytes,
        session_id: bytes,
        key_type: bytes,
        key_length: int,
    ) -> bytes:
        """
        Derive encryption/MAC keys from shared secret using SSH key derivation.

        Args:
            algorithm: Hash algorithm for key derivation
            shared_secret: Shared secret K - MUST be mpint-encoded per RFC 4253 §7.2,
                i.e. a 4-byte big-endian length prefix followed by the minimal
                two's-complement big-endian representation of K (with a leading
                0x00 byte if the MSB is set). Pass write_mpint(K) from protocol.utils.
            exchange_hash: Hash of key exchange
            session_id: Session identifier
            key_type: Key type identifier (A, B, C, D, E, F)
            key_length: Required key length

        Returns:
            Derived key

        Raises:
            CryptoException: If key derivation fails or shared_secret is not mpint-encoded
        """
        try:
            if algorithm not in self.HASH_ALGORITHMS:
                raise CryptoException(f"Unsupported hash algorithm: {algorithm}")

            hash_class = self.HASH_ALGORITHMS[algorithm]

            # Ensure all inputs are bytes
            shared_secret_bytes = bytes(shared_secret)

            # Validate mpint envelope: 4-byte length prefix + payload (RFC 4253 §7.2)
            if len(shared_secret_bytes) < 4:
                raise CryptoException(
                    "shared_secret must be mpint-encoded (RFC 4253 §7.2): too short"
                )
            declared = struct.unpack(">I", shared_secret_bytes[:4])[0]
            if len(shared_secret_bytes) != 4 + declared:
                raise CryptoException(
                    "shared_secret must be mpint-encoded (RFC 4253 §7.2): "
                    f"declared length {declared} does not match actual payload length "
                    f"{len(shared_secret_bytes) - 4}"
                )
            exchange_hash_bytes = bytes(exchange_hash)
            key_type_bytes = bytes(key_type)
            session_id_bytes = bytes(session_id)

            # SSH key derivation: K || H || key_type || session_id
            initial_data = (
                shared_secret_bytes
                + exchange_hash_bytes
                + key_type_bytes
                + session_id_bytes
            )

            # Hash the initial data
            digest = hashes.Hash(hash_class())  # type: ignore[abstract]
            digest.update(initial_data)
            key_material = digest.finalize()

            # Extend key material if needed
            while len(key_material) < key_length:
                digest = hashes.Hash(hash_class())  # type: ignore[abstract]
                digest.update(shared_secret_bytes + exchange_hash_bytes + key_material)
                key_material += digest.finalize()

            return key_material[:key_length]
        except Exception as e:
            raise CryptoException(f"Key derivation failed: {e}") from e

    def decrypt_length(
        self, algorithm: str, key: bytes, iv: bytes, data: bytes
    ) -> bytes:
        """
        Decrypt only the length field for ciphers that encrypt it.

        For AES-CTR (the only cipher currently supported), the full packet
        including the length field is decrypted together, so this method is
        not used. It is retained as a hook for future CBC-mode support where
        the 4-byte length must be decrypted before knowing how much payload
        to read from the socket.

        Returns:
            ``data`` unchanged (passthrough for CTR-mode callers).
        """
        return bytes(data)

    def chacha20_poly1305_encrypt(
        self, key_64: bytes, seq_num: int, length_bytes: bytes, body_bytes: bytes
    ) -> bytes:
        seq_be = struct.pack(">Q", seq_num)
        nonce_c0 = b"\x00" * 8 + seq_be
        nonce_c1 = b"\x01\x00\x00\x00" + b"\x00" * 4 + seq_be
        key_body = key_64[:32]
        key_header = key_64[32:]
        enc_length = (
            Cipher(algorithms.ChaCha20(key_header, nonce_c0), mode=None)
            .encryptor()
            .update(length_bytes)
        )
        poly_key = (
            Cipher(algorithms.ChaCha20(key_body, nonce_c0), mode=None)
            .encryptor()
            .update(b"\x00" * 32)
        )
        enc_body = (
            Cipher(algorithms.ChaCha20(key_body, nonce_c1), mode=None)
            .encryptor()
            .update(body_bytes)
        )
        ciphertext = enc_length + enc_body
        tag = Poly1305.generate_tag(poly_key, ciphertext)
        return ciphertext + tag

    def chacha20_poly1305_decrypt_length(
        self, key_64: bytes, seq_num: int, enc_length: bytes
    ) -> bytes:
        seq_be = struct.pack(">Q", seq_num)
        nonce_c0 = b"\x00" * 4 + b"\x00" * 4 + seq_be
        key_header = key_64[32:]
        return (
            Cipher(algorithms.ChaCha20(key_header, nonce_c0), mode=None)
            .encryptor()
            .update(enc_length)
        )

    def chacha20_poly1305_decrypt_body(
        self,
        key_64: bytes,
        seq_num: int,
        enc_length: bytes,
        enc_body: bytes,
        tag: bytes,
    ) -> bytes:
        seq_be = struct.pack(">Q", seq_num)
        nonce_c0 = b"\x00" * 4 + b"\x00" * 4 + seq_be
        nonce_c1 = b"\x01\x00\x00\x00" + b"\x00" * 4 + seq_be
        key_body = key_64[:32]
        poly_key = (
            Cipher(algorithms.ChaCha20(key_body, nonce_c0), mode=None)
            .encryptor()
            .update(b"\x00" * 32)
        )
        try:
            Poly1305.verify_tag(poly_key, enc_length + enc_body, tag)
        except InvalidSignature as e:
            raise CryptoException("Poly1305 authentication failed") from e
        return (
            Cipher(algorithms.ChaCha20(key_body, nonce_c1), mode=None)
            .encryptor()
            .update(enc_body)
        )


# Default backend instance
default_crypto_backend = CryptographyBackend()


def get_crypto_backend() -> CryptoBackend:
    """
    Get the default cryptographic backend.

    Returns:
        Default CryptoBackend instance
    """
    return default_crypto_backend
