"""
Cryptographic Backend Abstraction

Provides pluggable cryptographic backend interface with
cryptography library implementation.
"""

import os
from typing import Any, Protocol

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, poly1305
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..exceptions import CryptoException


class ChaCha20Poly1305OpenSSH:
    """
    OpenSSH-specific ChaCha20-Poly1305 implementation.
    Reference: PROTOCOL.chacha20poly1305 in OpenSSH source.
    """

    def __init__(self, key: bytes) -> None:
        if len(key) != 64:
            raise CryptoException("ChaCha20-Poly1305 key must be 64 bytes")
        self.k_main = key[:32]
        self.k_len = key[32:]

    def _get_poly_key(self, nonce: bytes) -> bytes:
        # Poly1305 key is ChaCha20(k_main, nonce) at block 0
        # nonce in cryptography library is 16 bytes: 8 bytes counter (LE) + 8 bytes nonce
        nonce16 = b"\x00" * 8 + nonce
        cipher = Cipher(algorithms.ChaCha20(self.k_main, nonce16), mode=None)
        encryptor = cipher.encryptor()
        return encryptor.update(b"\x00" * 32)

    def encrypt(self, nonce: bytes, data: bytes) -> bytes:
        """
        Encrypt data.
        data is the full packet: length (4) + payload + padding
        """
        if len(data) < 4:
            raise CryptoException("Data too short for encryption")

        # 1. Encrypt length (first 4 bytes) with k_len
        # Length encryption uses block 0
        len_nonce16 = b"\x00" * 8 + nonce
        len_cipher = Cipher(algorithms.ChaCha20(self.k_len, len_nonce16), mode=None)
        len_encryptor = len_cipher.encryptor()
        enc_len = len_encryptor.update(data[:4])

        # 2. Encrypt payload with k_main, starting at block 1
        main_nonce16 = b"\x01\x00\x00\x00\x00\x00\x00\x00" + nonce
        main_cipher = Cipher(algorithms.ChaCha20(self.k_main, main_nonce16), mode=None)
        main_encryptor = main_cipher.encryptor()
        enc_payload = main_encryptor.update(data[4:])

        # 3. Compute Poly1305 MAC over Enc(len) + Enc(payload)
        poly_key = self._get_poly_key(nonce)
        p = poly1305.Poly1305(poly_key)
        p.update(enc_len + enc_payload)
        mac = p.finalize()

        return enc_len + enc_payload + mac

    def decrypt(self, nonce: bytes, data: bytes) -> bytes:
        """
        Decrypt data.
        data is Enc(len) + Enc(payload) + MAC
        """
        if len(data) < 4 + 16:
            raise CryptoException("Data too short for decryption")

        enc_len = data[:4]
        mac = data[-16:]
        enc_payload = data[4:-16]

        # 1. Verify MAC
        poly_key = self._get_poly_key(nonce)
        p = poly1305.Poly1305(poly_key)
        p.update(enc_len + enc_payload)
        try:
            p.verify(mac)
        except Exception:
            raise CryptoException("MAC verification failed")

        # 2. Decrypt length
        len_nonce16 = b"\x00" * 8 + nonce
        len_cipher = Cipher(algorithms.ChaCha20(self.k_len, len_nonce16), mode=None)
        len_decryptor = len_cipher.decryptor()
        dec_len = len_decryptor.update(enc_len)

        # 3. Decrypt payload
        main_nonce16 = b"\x01\x00\x00\x00\x00\x00\x00\x00" + nonce
        main_cipher = Cipher(algorithms.ChaCha20(self.k_main, main_nonce16), mode=None)
        main_decryptor = main_cipher.decryptor()
        dec_payload = main_decryptor.update(enc_payload)

        return dec_len + dec_payload

    def decrypt_length(self, nonce: bytes, enc_len: bytes) -> bytes:
        """Decrypt only the length field."""
        len_nonce16 = b"\x00" * 8 + nonce
        len_cipher = Cipher(algorithms.ChaCha20(self.k_len, len_nonce16), mode=None)
        len_decryptor = len_cipher.decryptor()
        return len_decryptor.update(enc_len)


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
        """Decrypt only the length field for AEAD ciphers that encrypt it."""
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


class CryptographyBackend:
    """
    Cryptography library backend implementation.

    Implements CryptoBackend interface using the Python cryptography library
    for modern, secure cryptographic operations.
    """

    # Hash algorithm mapping
    HASH_ALGORITHMS = {
        "sha256": hashes.SHA256,
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
            raise CryptoException(f"Failed to generate random bytes: {e}") from e

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

            cipher: Any
            if algorithm == "chacha20-poly1305@openssh.com":
                cipher = ChaCha20Poly1305OpenSSH(key_bytes)
                return bytes(cipher.encrypt(iv_bytes, data_bytes))
            elif algorithm in ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]:
                # SSH AES-GCM (RFC 5647):
                # data is full packet: length (4) + payload + padding
                # length is AAD, payload+padding is encrypted
                cipher = AESGCM(key_bytes)
                aad = data_bytes[:4]
                payload = data_bytes[4:]
                return aad + bytes(cipher.encrypt(iv_bytes, payload, aad))
            elif algorithm == "aes256-ctr":
                cipher_algo = algorithms.AES(key_bytes)
                mode = modes.CTR(iv_bytes)
                cipher = Cipher(cipher_algo, mode, backend=self.backend)
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

            cipher: Any
            if algorithm == "chacha20-poly1305@openssh.com":
                cipher = ChaCha20Poly1305OpenSSH(key_bytes)
                return bytes(cipher.decrypt(iv_bytes, data_bytes))
            elif algorithm in ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]:
                # SSH AES-GCM (RFC 5647):
                # data is Length (4) + Enc(payload) + Tag (16)
                cipher = AESGCM(key_bytes)
                aad = data_bytes[:4]
                ciphertext = data_bytes[4:]
                return aad + bytes(cipher.decrypt(iv_bytes, ciphertext, aad))
            elif algorithm == "aes256-ctr":
                cipher_algo = algorithms.AES(key_bytes)
                mode = modes.CTR(iv_bytes)
                cipher = Cipher(cipher_algo, mode, backend=self.backend)
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
                return Cipher(cipher_algo, mode, backend=self.backend)
            elif algorithm == "chacha20-poly1305@openssh.com":
                return ChaCha20Poly1305OpenSSH(key_bytes)
            elif algorithm in ["aes256-gcm@openssh.com", "aes128-gcm@openssh.com"]:
                return AESGCM(key_bytes)
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
            h = hmac.HMAC(key_bytes, hash_class(), backend=self.backend)  # type: ignore
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
            initial_data = (
                shared_secret_bytes
                + exchange_hash_bytes
                + key_type_bytes
                + session_id_bytes
            )

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
            raise CryptoException(f"Key derivation failed: {e}") from e

    def decrypt_length(
        self, algorithm: str, key: bytes, iv: bytes, data: bytes
    ) -> bytes:
        """
        Decrypt only the length field for AEAD ciphers that encrypt it.

        Args:
            algorithm: Cipher algorithm name
            key: Decryption key
            iv: Initialization vector or nonce
            data: Encrypted length field (4 bytes)

        Returns:
            Decrypted length field

        Raises:
            CryptoException: If decryption fails
        """
        try:
            key_bytes = bytes(key)
            iv_bytes = bytes(iv)
            data_bytes = bytes(data)

            if algorithm == "chacha20-poly1305@openssh.com":
                cipher = ChaCha20Poly1305OpenSSH(key_bytes)
                return bytes(cipher.decrypt_length(iv_bytes, data_bytes))
            else:
                # Ciphers that don't encrypt the length just return it as is
                return data_bytes
        except Exception as e:
            raise CryptoException(f"Length decryption failed: {e}") from e


# Default backend instance
default_crypto_backend = CryptographyBackend()


def get_crypto_backend() -> CryptoBackend:
    """
    Get the default cryptographic backend.

    Returns:
        Default CryptoBackend instance
    """
    return default_crypto_backend
