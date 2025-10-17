"""
SSH Key Exchange Implementation

Implements SSH key exchange algorithms including Curve25519, ECDH,
and Diffie-Hellman for secure session key establishment.
"""

import os
import hashlib
from typing import Optional, Tuple, Any, Dict, List
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from ..exceptions import CryptoException, ProtocolException
from ..protocol.constants import *
from ..protocol.messages import *
from ..protocol.utils import *
from ..crypto.backend import default_crypto_backend


class KeyExchange:
    """
    SSH key exchange implementation.
    
    Handles key exchange algorithms and session key derivation
    according to SSH protocol specifications.
    """
    
    # Diffie-Hellman Group 14 parameters (RFC 3526)
    DH_GROUP14_P = int(
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
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    DH_GROUP14_G = 2
    
    def __init__(self, transport: Any) -> None:
        """
        Initialize key exchange with transport.
        
        Args:
            transport: SSH transport instance
        """
        self._transport = transport
        self._algorithm: Optional[str] = None
        self._shared_secret: Optional[bytes] = None
        self._exchange_hash: Optional[bytes] = None
        self._session_id: Optional[bytes] = None
        
        # Key exchange state
        self._client_kexinit: Optional[bytes] = None
        self._server_kexinit: Optional[bytes] = None
        self._dh_private_key: Optional[Any] = None
        self._dh_public_key: Optional[bytes] = None
        self._server_public_key: Optional[bytes] = None
        
        # Negotiated algorithms
        self._kex_algorithm: Optional[str] = None
        self._server_host_key_algorithm: Optional[str] = None
        self._encryption_algorithm_c2s: Optional[str] = None
        self._encryption_algorithm_s2c: Optional[str] = None
        self._mac_algorithm_c2s: Optional[str] = None
        self._mac_algorithm_s2c: Optional[str] = None
        self._compression_algorithm_c2s: Optional[str] = None
        self._compression_algorithm_s2c: Optional[str] = None
    
    def start_kex(self) -> None:
        """
        Start key exchange process.
        
        Raises:
            CryptoException: If key exchange fails
        """
        try:
            # Send KEXINIT message
            self._send_kexinit()
            
            # Receive server KEXINIT
            self._receive_kexinit()
            
            # Negotiate algorithms
            self._negotiate_algorithms()
            
            # Perform key exchange based on negotiated algorithm
            if self._kex_algorithm == "curve25519-sha256":
                self._perform_curve25519_sha256()
            elif self._kex_algorithm == "diffie-hellman-group14-sha1":
                self._perform_dh_group14_sha1()
            elif self._kex_algorithm == KEX_DH_GROUP14_SHA256:
                self._perform_dh_group14_sha256()
            else:
                # Default to Curve25519 for maximum compatibility
                self._kex_algorithm = "curve25519-sha256"
                self._perform_curve25519_sha256()
            
            # Generate session keys
            self._generate_session_keys()
            
            # Send NEWKEYS message
            self._send_newkeys()
            
            # Receive NEWKEYS message
            self._receive_newkeys()
            
        except Exception as e:
            if isinstance(e, (CryptoException, ProtocolException)):
                raise
            raise CryptoException(f"Key exchange failed: {e}")
    
    def _send_kexinit(self) -> None:
        """Send KEXINIT message with supported algorithms."""
        cookie = default_crypto_backend.generate_random(KEX_COOKIE_SIZE)
        
        # Define supported algorithms with SSH extensions (compatible with OpenSSH 9.x)
        kex_algorithms = [
            "curve25519-sha256",
            "curve25519-sha256@libssh.org", 
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            KEX_DH_GROUP14_SHA256,
            "ext-info-c",
            "kex-strict-c-v00@openssh.com"
        ]
        server_host_key_algorithms = [
            "rsa-sha2-512",
            "rsa-sha2-256", 
            "ecdsa-sha2-nistp256",
            "ssh-ed25519"
        ]
        encryption_algorithms = [
            "chacha20-poly1305@openssh.com",
            "aes128-ctr",
            "aes192-ctr", 
            "aes256-ctr",
            "aes128-gcm@openssh.com",
            "aes256-gcm@openssh.com"
        ]
        mac_algorithms = [
            "umac-64-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha1-etm@openssh.com",
            "umac-64@openssh.com",
            "umac-128@openssh.com",
            "hmac-sha2-256",
            "hmac-sha2-512",
            "hmac-sha1"
        ]
        compression_algorithms = [COMPRESS_NONE, "zlib@openssh.com"]
        

        
        kexinit_msg = KexInitMessage(
            cookie=cookie,
            kex_algorithms=kex_algorithms,
            server_host_key_algorithms=server_host_key_algorithms,
            encryption_algorithms_client_to_server=encryption_algorithms,
            encryption_algorithms_server_to_client=encryption_algorithms,
            mac_algorithms_client_to_server=mac_algorithms,
            mac_algorithms_server_to_client=mac_algorithms,
            compression_algorithms_client_to_server=compression_algorithms,
            compression_algorithms_server_to_client=compression_algorithms,
            first_kex_packet_follows=False
        )
        
        # Store our KEXINIT for hash calculation
        self._client_kexinit = kexinit_msg.pack()
        
        # Send the message
        self._transport._send_message(kexinit_msg)
    
    def _receive_kexinit(self) -> None:
        """Receive and process server KEXINIT message."""
        msg = self._transport._recv_message()
        
        if not isinstance(msg, KexInitMessage):
            raise ProtocolException(f"Expected KEXINIT, got {type(msg).__name__}")
        
        # Store server KEXINIT for hash calculation
        self._server_kexinit = msg.pack()
        
        # Store server's algorithm lists
        self._server_kex_algorithms = msg.kex_algorithms
        self._server_host_key_algorithms = msg.server_host_key_algorithms
        self._server_encryption_c2s = msg.encryption_algorithms_client_to_server
        self._server_encryption_s2c = msg.encryption_algorithms_server_to_client
        self._server_mac_c2s = msg.mac_algorithms_client_to_server
        self._server_mac_s2c = msg.mac_algorithms_server_to_client
        self._server_compression_c2s = msg.compression_algorithms_client_to_server
        self._server_compression_s2c = msg.compression_algorithms_server_to_client
    
    def _negotiate_algorithms(self) -> None:
        """Negotiate algorithms based on client and server preferences."""
        # Negotiate KEX algorithm
        client_kex = ["diffie-hellman-group14-sha1", KEX_DH_GROUP14_SHA256]
        self._kex_algorithm = self._choose_algorithm(client_kex, self._server_kex_algorithms)

        
        # Negotiate host key algorithm
        client_hostkey = [HOSTKEY_RSA_SHA2_256, HOSTKEY_ED25519]
        self._server_host_key_algorithm = self._choose_algorithm(client_hostkey, self._server_host_key_algorithms)
        
        # Negotiate encryption algorithms
        client_enc = [CIPHER_AES256_CTR, CIPHER_AES128_GCM]
        self._encryption_algorithm_c2s = self._choose_algorithm(client_enc, self._server_encryption_c2s)
        self._encryption_algorithm_s2c = self._choose_algorithm(client_enc, self._server_encryption_s2c)
        
        # Negotiate MAC algorithms
        client_mac = [MAC_HMAC_SHA2_256, MAC_HMAC_SHA2_512]
        self._mac_algorithm_c2s = self._choose_algorithm(client_mac, self._server_mac_c2s)
        self._mac_algorithm_s2c = self._choose_algorithm(client_mac, self._server_mac_s2c)
        
        # Negotiate compression algorithms
        client_comp = [COMPRESS_NONE]
        self._compression_algorithm_c2s = self._choose_algorithm(client_comp, self._server_compression_c2s)
        self._compression_algorithm_s2c = self._choose_algorithm(client_comp, self._server_compression_s2c)
    
    def _choose_algorithm(self, client_list: List[str], server_list: List[str]) -> str:
        """Choose first matching algorithm from client and server lists, excluding extensions."""
        # Filter out SSH extensions from both lists
        extensions = ["ext-info-c", "ext-info-s", "kex-strict-c-v00@openssh.com", "kex-strict-s-v00@openssh.com"]
        
        client_algs = [alg for alg in client_list if alg not in extensions]
        server_algs = [alg for alg in server_list if alg not in extensions]
        
        for client_alg in client_algs:
            if client_alg in server_algs:
                return client_alg
        
        raise CryptoException(f"No matching algorithms: client={client_algs}, server={server_algs}")
    
    def _perform_dh_group14_sha256(self) -> None:
        """Perform Diffie-Hellman Group 14 SHA256 key exchange."""
        try:
            # Generate DH parameters
            parameters = dh.DHParameterNumbers(self.DH_GROUP14_P, self.DH_GROUP14_G).parameters(default_backend())
            
            # Generate private key
            self._dh_private_key = parameters.generate_private_key()
            
            # Get public key
            dh_public_key = self._dh_private_key.public_key()
            public_numbers = dh_public_key.public_numbers()
            
            # Store public key value
            self._dh_public_key = public_numbers.y
            self._dh_public_key_mpint = write_mpint(public_numbers.y)
            
            # Send KEXDH_INIT message
            kexdh_init = Message(MSG_KEXDH_INIT)
            kexdh_init.add_mpint(self._dh_public_key)
            self._transport._send_message(kexdh_init)
            
            # Receive KEXDH_REPLY message
            reply_msg = self._transport._recv_message()
            
            if reply_msg.msg_type != MSG_KEXDH_REPLY:
                raise ProtocolException(f"Expected KEXDH_REPLY, got {reply_msg.msg_type}")
            
            # Parse KEXDH_REPLY
            offset = 0
            server_host_key_blob, offset = read_string(reply_msg._data, offset)
            server_dh_public, offset = read_string(reply_msg._data, offset)
            signature_blob, offset = read_string(reply_msg._data, offset)
            
            # Extract server's DH public key
            server_public_int, _ = read_mpint(server_dh_public, 0)
            
            # Compute shared secret
            server_public_numbers = dh.DHPublicNumbers(server_public_int, parameters.parameter_numbers())
            server_public_key = server_public_numbers.public_key(default_backend())
            
            shared_secret_int = self._dh_private_key.exchange(server_public_key)
            self._shared_secret = write_mpint(int.from_bytes(shared_secret_int, 'big'))
            
            # Compute exchange hash
            self._compute_exchange_hash(server_host_key_blob, server_dh_public, signature_blob)
            
            # Set session ID (first exchange hash)
            if self._session_id is None:
                self._session_id = self._exchange_hash
                
        except Exception as e:
            raise
    
    def _perform_curve25519_sha256(self) -> None:
        """Perform Curve25519 SHA256 key exchange (modern, preferred)."""
        try:
            from cryptography.hazmat.primitives.asymmetric import x25519
            from cryptography.hazmat.primitives import serialization
            
            # Generate Curve25519 key pair
            self._curve25519_private_key = x25519.X25519PrivateKey.generate()
            public_key = self._curve25519_private_key.public_key()
            
            # Get public key bytes (32 bytes for Curve25519)
            self._curve25519_public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Send KEX_ECDH_INIT message (message type 30)
            kex_ecdh_init = Message(30)  # MSG_KEX_ECDH_INIT
            kex_ecdh_init.add_string(self._curve25519_public_key_bytes)
            self._transport._send_message(kex_ecdh_init)
            
            # Receive KEX_ECDH_REPLY message
            reply_msg = self._transport._recv_message()
            
            if reply_msg.msg_type != 31:  # MSG_KEX_ECDH_REPLY
                raise ProtocolException(f"Expected KEX_ECDH_REPLY, got {reply_msg.msg_type}")
            
            # Parse KEX_ECDH_REPLY
            offset = 0
            server_host_key_blob, offset = read_string(reply_msg._data, offset)
            server_public_key_blob, offset = read_string(reply_msg._data, offset)
            signature_blob, offset = read_string(reply_msg._data, offset)
            
            # Perform key exchange
            server_public_key = x25519.X25519PublicKey.from_public_bytes(server_public_key_blob)
            shared_secret_bytes = self._curve25519_private_key.exchange(server_public_key)
            self._shared_secret = write_mpint(int.from_bytes(shared_secret_bytes, 'big'))
            
            # Compute exchange hash using SHA256
            self._compute_curve25519_exchange_hash(server_host_key_blob, server_public_key_blob, signature_blob)
            
            # Set session ID (first exchange hash)
            if self._session_id is None:
                self._session_id = self._exchange_hash
                
        except Exception as e:
            raise
    
    def _compute_curve25519_exchange_hash(self, server_host_key: bytes, server_public_key: bytes, signature: bytes) -> None:
        """Compute the exchange hash H for Curve25519."""
        hash_data = bytearray()
        
        # Client version string
        client_version = self._transport._client_version or "SSH-2.0-SpindleX_1.0"
        hash_data.extend(write_string(client_version))
        
        # Server version string  
        server_version = self._transport._server_version or "SSH-2.0-Unknown"
        hash_data.extend(write_string(server_version))
        
        # Client KEXINIT
        hash_data.extend(write_string(self._client_kexinit))
        
        # Server KEXINIT
        hash_data.extend(write_string(self._server_kexinit))
        
        # Server host key
        hash_data.extend(write_string(server_host_key))
        
        # Client public key
        hash_data.extend(write_string(self._curve25519_public_key_bytes))
        
        # Server public key
        hash_data.extend(write_string(server_public_key))
        
        # Shared secret
        hash_data.extend(self._shared_secret)
        
        # Compute SHA256 hash
        self._exchange_hash = default_crypto_backend.hash_data('sha256', bytes(hash_data))
    
    def _perform_dh_group14_sha1(self) -> None:
        """Perform Diffie-Hellman Group 14 SHA1 key exchange (more compatible)."""
        try:
            # Generate DH parameters
            parameters = dh.DHParameterNumbers(self.DH_GROUP14_P, self.DH_GROUP14_G).parameters(default_backend())
            
            # Generate private key
            self._dh_private_key = parameters.generate_private_key()
            
            # Get public key
            dh_public_key = self._dh_private_key.public_key()
            public_numbers = dh_public_key.public_numbers()
            
            # Store public key value
            self._dh_public_key = public_numbers.y
            self._dh_public_key_mpint = write_mpint(public_numbers.y)
            
            # Send KEXDH_INIT message
            kexdh_init = Message(MSG_KEXDH_INIT)
            kexdh_init.add_mpint(self._dh_public_key)
            self._transport._send_message(kexdh_init)
            
            # Receive KEXDH_REPLY message
            reply_msg = self._transport._recv_message()
            
            if reply_msg.msg_type != MSG_KEXDH_REPLY:
                raise ProtocolException(f"Expected KEXDH_REPLY, got {reply_msg.msg_type}")
            
            # Parse KEXDH_REPLY
            offset = 0
            server_host_key_blob, offset = read_string(reply_msg._data, offset)
            server_dh_public, offset = read_string(reply_msg._data, offset)
            signature_blob, offset = read_string(reply_msg._data, offset)
            
            # Extract server's DH public key
            server_public_int, _ = read_mpint(server_dh_public, 0)
            
            # Compute shared secret
            server_public_numbers = dh.DHPublicNumbers(server_public_int, parameters.parameter_numbers())
            server_public_key = server_public_numbers.public_key(default_backend())
            
            shared_secret_int = self._dh_private_key.exchange(server_public_key)
            self._shared_secret = write_mpint(int.from_bytes(shared_secret_int, 'big'))
            
            # Compute exchange hash using SHA1
            self._compute_exchange_hash_sha1(server_host_key_blob, server_dh_public, signature_blob)
            
            # Set session ID (first exchange hash)
            if self._session_id is None:
                self._session_id = self._exchange_hash
                
        except Exception as e:
            raise
    
    def _compute_exchange_hash(self, server_host_key: bytes, server_dh_public: bytes, signature: bytes) -> None:
        """Compute the exchange hash H."""
        hash_data = bytearray()
        
        # Client version string
        client_version = self._transport._client_version or "SSH-2.0-SpindleX_1.0"
        hash_data.extend(write_string(client_version))
        
        # Server version string  
        server_version = self._transport._server_version or "SSH-2.0-Unknown"
        hash_data.extend(write_string(server_version))
        
        # Client KEXINIT
        hash_data.extend(write_string(self._client_kexinit))
        
        # Server KEXINIT
        hash_data.extend(write_string(self._server_kexinit))
        
        # Server host key
        hash_data.extend(write_string(server_host_key))
        
        # Client DH public key
        hash_data.extend(self._dh_public_key_mpint)
        
        # Server DH public key
        hash_data.extend(server_dh_public)
        
        # Shared secret
        hash_data.extend(self._shared_secret)
        
        # Compute SHA256 hash
        self._exchange_hash = default_crypto_backend.hash_data('sha256', bytes(hash_data))
    
    def _compute_exchange_hash_sha1(self, server_host_key: bytes, server_dh_public: bytes, signature: bytes) -> None:
        """Compute the exchange hash H using SHA1."""
        hash_data = bytearray()
        
        # Client version string
        client_version = self._transport._client_version or "SSH-2.0-SpindleX_1.0"
        hash_data.extend(write_string(client_version))
        
        # Server version string  
        server_version = self._transport._server_version or "SSH-2.0-Unknown"
        hash_data.extend(write_string(server_version))
        
        # Client KEXINIT
        hash_data.extend(write_string(self._client_kexinit))
        
        # Server KEXINIT
        hash_data.extend(write_string(self._server_kexinit))
        
        # Server host key
        hash_data.extend(write_string(server_host_key))
        
        # Client DH public key
        hash_data.extend(self._dh_public_key_mpint)
        
        # Server DH public key
        hash_data.extend(server_dh_public)
        
        # Shared secret
        hash_data.extend(self._shared_secret)
        
        # Compute SHA1 hash
        self._exchange_hash = default_crypto_backend.hash_data('sha1', bytes(hash_data))
    
    def _generate_session_keys(self) -> None:
        """Generate session keys from shared secret and exchange hash."""
        if not self._shared_secret or not self._exchange_hash or not self._session_id:
            raise CryptoException("Missing key exchange data for key generation")
        
        # Key lengths (simplified - using AES256 = 32 bytes, HMAC-SHA256 = 32 bytes)
        key_length = 32
        iv_length = 16
        
        # Choose hash algorithm based on KEX algorithm
        hash_alg = 'sha1' if self._kex_algorithm == "diffie-hellman-group14-sha1" else 'sha256'
        
        # Generate keys using SSH key derivation
        # A: IV client to server
        self._iv_c2s = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash, 
            self._session_id, b'A', iv_length
        )
        
        # B: IV server to client
        self._iv_s2c = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash,
            self._session_id, b'B', iv_length
        )
        
        # C: Encryption key client to server
        self._encryption_key_c2s = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash,
            self._session_id, b'C', key_length
        )
        
        # D: Encryption key server to client
        self._encryption_key_s2c = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash,
            self._session_id, b'D', key_length
        )
        
        # E: MAC key client to server
        self._mac_key_c2s = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash,
            self._session_id, b'E', key_length
        )
        
        # F: MAC key server to client
        self._mac_key_s2c = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash,
            self._session_id, b'F', key_length
        )
        
        # Update transport with keys
        self._transport._encryption_key_c2s = self._encryption_key_c2s
        self._transport._encryption_key_s2c = self._encryption_key_s2c
        self._transport._mac_key_c2s = self._mac_key_c2s
        self._transport._mac_key_s2c = self._mac_key_s2c
        self._transport._cipher_c2s = self._encryption_algorithm_c2s
        self._transport._cipher_s2c = self._encryption_algorithm_s2c
        self._transport._mac_c2s = self._mac_algorithm_c2s
        self._transport._mac_s2c = self._mac_algorithm_s2c
        self._transport._session_id = self._session_id
    
    def _send_newkeys(self) -> None:
        """Send NEWKEYS message to activate new keys."""
        newkeys_msg = Message(MSG_NEWKEYS)
        self._transport._send_message(newkeys_msg)
    
    def _receive_newkeys(self) -> None:
        """Receive NEWKEYS message from server."""
        msg = self._transport._recv_message()
        if msg.msg_type != MSG_NEWKEYS:
            raise ProtocolException(f"Expected NEWKEYS, got {msg.msg_type}")
    
    def generate_keys(self) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Generate session keys from shared secret.
        
        Returns:
            Tuple of (encryption_key_c2s, encryption_key_s2c, mac_key_c2s, mac_key_s2c)
            
        Raises:
            CryptoException: If key generation fails
        """
        if not all([self._encryption_key_c2s, self._encryption_key_s2c, 
                   self._mac_key_c2s, self._mac_key_s2c]):
            raise CryptoException("Keys not generated - run key exchange first")
        
        return (self._encryption_key_c2s, self._encryption_key_s2c, 
                self._mac_key_c2s, self._mac_key_s2c)