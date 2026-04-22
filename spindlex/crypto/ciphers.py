"""
SSH Cipher Suite Implementation

Implements SSH cipher suites with modern cryptographic algorithms
and secure defaults according to current best practices.
"""

from typing import Any, Optional

from ..exceptions import CryptoException
from .backend import CryptoBackend, default_crypto_backend


class CipherSuite:
    """
    SSH cipher suite implementation.

    Manages cipher algorithms, key exchange methods, and MAC algorithms
    with preference for modern, secure cryptographic primitives.
    """

    # Supported key exchange algorithms (in preference order)
    KEX_ALGORITHMS = [
        "curve25519-sha256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha256",
        "kex-strict-c-v01@openssh.com",
        "ext-info-c",
    ]

    # Supported host key algorithms (in preference order)
    HOST_KEY_ALGORITHMS = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-256",
    ]

    # Supported encryption algorithms (in preference order)
    ENCRYPTION_ALGORITHMS = [
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "aes128-gcm@openssh.com",
        "aes256-gcm@openssh.com",
        "chacha20-poly1305@openssh.com",
    ]

    # Supported MAC algorithms (in preference order)
    MAC_ALGORITHMS = [
        "hmac-sha2-256",
        "hmac-sha2-512",
    ]

    # Cipher key and IV lengths
    CIPHER_INFO = {
        "chacha20-poly1305@openssh.com": {"key_len": 64, "iv_len": 0, "aead": True},
        "aes256-gcm@openssh.com": {"key_len": 32, "iv_len": 4, "aead": True},
        "aes128-gcm@openssh.com": {"key_len": 16, "iv_len": 4, "aead": True},
        "aes256-ctr": {"key_len": 32, "iv_len": 16, "aead": False},
        "aes192-ctr": {"key_len": 24, "iv_len": 16, "aead": False},
        "aes128-ctr": {"key_len": 16, "iv_len": 16, "aead": False},
    }

    # MAC key lengths
    MAC_INFO = {
        "hmac-sha2-256": {"key_len": 32, "digest_len": 32},
        "hmac-sha2-512": {"key_len": 64, "digest_len": 64},
    }

    def __init__(self, crypto_backend: Optional[CryptoBackend] = None) -> None:
        """
        Initialize cipher suite with secure defaults.

        Args:
            crypto_backend: Cryptographic backend to use (defaults to CryptographyBackend)
        """
        self.crypto_backend = crypto_backend or default_crypto_backend
        self.negotiated_algorithms: dict[str, str] = {}

    def negotiate_algorithms(
        self,
        client_algorithms: dict[str, list[str]],
        server_algorithms: dict[str, list[str]],
    ) -> dict[str, str]:
        """
        Negotiate algorithms between client and server.

        Args:
            client_algorithms: Client's supported algorithms
            server_algorithms: Server's supported algorithms

        Returns:
            Dictionary of negotiated algorithms

        Raises:
            CryptoException: If no compatible algorithms found
        """
        negotiated = {}

        # Algorithm categories to negotiate
        categories = {
            "kex": ("kex_algorithms", self.KEX_ALGORITHMS),
            "server_host_key": ("server_host_key_algorithms", self.HOST_KEY_ALGORITHMS),
            "encryption_client_to_server": (
                "encryption_algorithms_client_to_server",
                self.ENCRYPTION_ALGORITHMS,
            ),
            "encryption_server_to_client": (
                "encryption_algorithms_server_to_client",
                self.ENCRYPTION_ALGORITHMS,
            ),
            "mac_client_to_server": (
                "mac_algorithms_client_to_server",
                self.MAC_ALGORITHMS,
            ),
            "mac_server_to_client": (
                "mac_algorithms_server_to_client",
                self.MAC_ALGORITHMS,
            ),
        }

        # Strict-KEX / extension markers must never be selected as the actual
        # KEX algorithm even if both peers advertise them. They are signaling
        # tokens, not key-exchange algorithms.
        kex_markers = {
            "ext-info-c",
            "ext-info-s",
            "kex-strict-c-v01@openssh.com",
            "kex-strict-s-v01@openssh.com",
        }

        for category, (key, preferred_list) in categories.items():
            client_list = client_algorithms.get(key, [])
            server_list = server_algorithms.get(key, [])

            # Find first mutually supported algorithm. RFC 4253 §7.1 says the
            # client's preference order wins; iterate the client list first
            # and check that the algorithm is also in our preferred set so we
            # never end up agreeing to something we cannot actually implement.
            preferred_set = set(preferred_list)
            server_set = set(server_list)
            if category == "kex":
                preferred_set -= kex_markers
                server_set -= kex_markers

            selected = None
            for algorithm in client_list:
                if algorithm in kex_markers and category == "kex":
                    continue
                if algorithm in preferred_set and algorithm in server_set:
                    selected = algorithm
                    break

            if selected is None:
                raise CryptoException(f"No compatible {category} algorithm found")

            negotiated[category] = selected

        # Handle AEAD ciphers (no separate MAC needed)
        enc_c2s = negotiated["encryption_client_to_server"]
        enc_s2c = negotiated["encryption_server_to_client"]

        if self.is_aead_cipher(enc_c2s):
            negotiated["mac_client_to_server"] = "none"
        if self.is_aead_cipher(enc_s2c):
            negotiated["mac_server_to_client"] = "none"

        self.negotiated_algorithms = negotiated
        return negotiated

    def get_cipher_info(self, algorithm: str) -> dict[str, Any]:
        """
        Get cipher information for specified algorithm.

        Args:
            algorithm: Cipher algorithm name

        Returns:
            Dictionary with key_len, iv_len, and aead properties

        Raises:
            CryptoException: If algorithm is unsupported
        """
        if algorithm not in self.CIPHER_INFO:
            raise CryptoException(f"Unsupported cipher algorithm: {algorithm}")
        return self.CIPHER_INFO[algorithm]

    def get_mac_info(self, algorithm: str) -> dict[str, int]:
        """
        Get MAC information for specified algorithm.

        Args:
            algorithm: MAC algorithm name

        Returns:
            Dictionary with key_len and digest_len properties

        Raises:
            CryptoException: If algorithm is unsupported
        """
        if algorithm not in self.MAC_INFO:
            raise CryptoException(f"Unsupported MAC algorithm: {algorithm}")
        return self.MAC_INFO[algorithm]

    def is_aead_cipher(self, algorithm: str) -> bool:
        """
        Check if cipher algorithm is AEAD (Authenticated Encryption with Associated Data).

        Args:
            algorithm: Cipher algorithm name

        Returns:
            True if algorithm is AEAD, False otherwise
        """
        info = self.get_cipher_info(algorithm)
        return bool(info.get("aead", False))
