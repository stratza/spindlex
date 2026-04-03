"""
SSH Cipher Suite Implementation

Implements SSH cipher suites with modern cryptographic algorithms
and secure defaults according to current best practices.
"""

from typing import Dict, List, Any, Optional
from .backend import CryptoBackend, default_crypto_backend
from ..exceptions import CryptoException


class CipherSuite:
    """
    SSH cipher suite implementation.
    
    Manages cipher algorithms, key exchange methods, and MAC algorithms
    with preference for modern, secure cryptographic primitives.
    """
    
    # Supported key exchange algorithms (in preference order)
    KEX_ALGORITHMS = [
        "curve25519-sha256",
        "ecdh-sha2-nistp256", 
        "diffie-hellman-group14-sha256",
    ]
    
    # Supported host key algorithms (in preference order)
    HOST_KEY_ALGORITHMS = [
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "rsa-sha2-256",
        "ssh-rsa",
    ]
    
    # Supported encryption algorithms (in preference order)
    ENCRYPTION_ALGORITHMS = [
        "aes256-ctr",
        "aes192-ctr",
        "aes128-ctr",
        "chacha20-poly1305@openssh.com",
        "aes256-gcm@openssh.com",
        "aes128-gcm@openssh.com", 
    ]
    
    # Supported MAC algorithms (in preference order)
    MAC_ALGORITHMS = [
        "hmac-sha2-256",
        "hmac-sha2-512",
        "hmac-sha1",
    ]
    
    # Cipher key and IV lengths
    CIPHER_INFO = {
        "chacha20-poly1305@openssh.com": {"key_len": 64, "iv_len": 12, "aead": True},
        "aes256-gcm@openssh.com": {"key_len": 32, "iv_len": 12, "aead": True},
        "aes128-gcm@openssh.com": {"key_len": 16, "iv_len": 12, "aead": True},
        "aes256-ctr": {"key_len": 32, "iv_len": 16, "aead": False},
        "aes192-ctr": {"key_len": 24, "iv_len": 16, "aead": False},
        "aes128-ctr": {"key_len": 16, "iv_len": 16, "aead": False},
    }
    
    # MAC key lengths
    MAC_INFO = {
        "hmac-sha2-256": {"key_len": 32, "digest_len": 32},
        "hmac-sha2-512": {"key_len": 64, "digest_len": 64},
        "hmac-sha1": {"key_len": 20, "digest_len": 20},
    }
    
    def __init__(self, crypto_backend: Optional[CryptoBackend] = None) -> None:
        """
        Initialize cipher suite with secure defaults.
        
        Args:
            crypto_backend: Cryptographic backend to use (defaults to CryptographyBackend)
        """
        self.crypto_backend = crypto_backend or default_crypto_backend
        self.negotiated_algorithms: Dict[str, str] = {}
    
    def negotiate_algorithms(
        self, 
        client_algorithms: Dict[str, List[str]], 
        server_algorithms: Dict[str, List[str]]
    ) -> Dict[str, str]:
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
            'kex': ('kex_algorithms', self.KEX_ALGORITHMS),
            'server_host_key': ('server_host_key_algorithms', self.HOST_KEY_ALGORITHMS),
            'encryption_client_to_server': ('encryption_algorithms_client_to_server', self.ENCRYPTION_ALGORITHMS),
            'encryption_server_to_client': ('encryption_algorithms_server_to_client', self.ENCRYPTION_ALGORITHMS),
            'mac_client_to_server': ('mac_algorithms_client_to_server', self.MAC_ALGORITHMS),
            'mac_server_to_client': ('mac_algorithms_server_to_client', self.MAC_ALGORITHMS),
        }
        
        for category, (key, preferred_list) in categories.items():
            client_list = client_algorithms.get(key, [])
            server_list = server_algorithms.get(key, [])
            
            # Find first mutually supported algorithm
            selected = None
            for algorithm in preferred_list:
                if algorithm in client_list and algorithm in server_list:
                    selected = algorithm
                    break
            
            if selected is None:
                raise CryptoException(f"No compatible {category} algorithm found")
            
            negotiated[category] = selected
        
        # Handle AEAD ciphers (no separate MAC needed)
        enc_c2s = negotiated['encryption_client_to_server']
        enc_s2c = negotiated['encryption_server_to_client']
        
        if self.is_aead_cipher(enc_c2s):
            negotiated['mac_client_to_server'] = 'none'
        if self.is_aead_cipher(enc_s2c):
            negotiated['mac_server_to_client'] = 'none'
        
        self.negotiated_algorithms = negotiated
        return negotiated
    
    def get_cipher_info(self, algorithm: str) -> Dict[str, Any]:
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
    
    def get_mac_info(self, algorithm: str) -> Dict[str, int]:
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
        return info.get("aead", False)