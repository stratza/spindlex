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
from ..crypto.ciphers import CipherSuite


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
        
        # Cipher suite for negotiation and info
        self._cipher_suite = CipherSuite(default_crypto_backend)
        
        # Key exchange state
        self._client_kexinit: Optional[bytes] = None
        self._server_kexinit: Optional[bytes] = None
        self._dh_private_key: Optional[Any] = None
        self._dh_public_key: Optional[bytes] = None
        self._dh_public_key_mpint: Optional[bytes] = None
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
        
        Note: KEXINIT exchange should already be completed by transport layer.
        
        Raises:
            CryptoException: If key exchange fails
        """
        try:
            # Get peer KEXINIT from transport (should already be exchanged)
            if not hasattr(self._transport, "_peer_kexinit") or self._transport._peer_kexinit is None:
                # If not exchanged yet, do it now
                self._send_kexinit()
                self._receive_kexinit()
            else:
                # Already exchanged, store the blobs
                self._server_kexinit = self._transport._peer_kexinit.pack()
                # Use our KEXINIT already sent by transport if available
                if hasattr(self._transport, "_client_kexinit_blob") and self._transport._client_kexinit_blob:
                    self._client_kexinit = self._transport._client_kexinit_blob
                elif self._client_kexinit is None:
                    self._send_kexinit()
            
            # Negotiate algorithms
            self._negotiate_algorithms()
            
            # Perform key exchange based on negotiated algorithm
            if self._kex_algorithm == KEX_DH_GROUP1_SHA1:
                self._perform_dh_group1_sha1()
            elif self._kex_algorithm in [KEX_CURVE25519_SHA256, "curve25519-sha256@libssh.org"]:
                self._perform_curve25519_sha256()
            elif self._kex_algorithm == KEX_ECDH_SHA2_NISTP256:
                self._perform_ecdh_sha2_nistp256()
            elif self._kex_algorithm == KEX_DH_GROUP14_SHA256:
                self._perform_dh_group14_sha256()
            else:
                # Default to DH Group 14 SHA256 for compatibility
                self._kex_algorithm = KEX_DH_GROUP14_SHA256
                self._perform_dh_group14_sha256()
            
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
        
        # Use algorithms from CipherSuite
        kexinit_msg = KexInitMessage(
            cookie=cookie,
            kex_algorithms=self._cipher_suite.KEX_ALGORITHMS,
            server_host_key_algorithms=self._cipher_suite.HOST_KEY_ALGORITHMS,
            encryption_algorithms_client_to_server=self._cipher_suite.ENCRYPTION_ALGORITHMS,
            encryption_algorithms_server_to_client=self._cipher_suite.ENCRYPTION_ALGORITHMS,
            mac_algorithms_client_to_server=self._cipher_suite.MAC_ALGORITHMS,
            mac_algorithms_server_to_client=self._cipher_suite.MAC_ALGORITHMS,
            compression_algorithms_client_to_server=[COMPRESS_NONE],
            compression_algorithms_server_to_client=[COMPRESS_NONE],
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
        
        # Store server peer info in transport if needed
        self._transport._peer_kexinit = msg
        
        # Store server KEXINIT blob for hash calculation
        self._server_kexinit = msg.pack()
    
    def _negotiate_algorithms(self) -> None:
        """Negotiate algorithms based on client and server preferences."""
        if not self._transport._peer_kexinit:
            raise CryptoException("No peer KEXINIT for negotiation")
            
        # Build client algorithms dict
        client_algs = {
            'kex_algorithms': self._cipher_suite.KEX_ALGORITHMS,
            'server_host_key_algorithms': self._cipher_suite.HOST_KEY_ALGORITHMS,
            'encryption_algorithms_client_to_server': self._cipher_suite.ENCRYPTION_ALGORITHMS,
            'encryption_algorithms_server_to_client': self._cipher_suite.ENCRYPTION_ALGORITHMS,
            'mac_algorithms_client_to_server': self._cipher_suite.MAC_ALGORITHMS,
            'mac_algorithms_server_to_client': self._cipher_suite.MAC_ALGORITHMS,
        }
        
        # Build server algorithms dict
        peer = self._transport._peer_kexinit
        server_algs = {
            'kex_algorithms': peer.kex_algorithms,
            'server_host_key_algorithms': peer.server_host_key_algorithms,
            'encryption_algorithms_client_to_server': peer.encryption_algorithms_client_to_server,
            'encryption_algorithms_server_to_client': peer.encryption_algorithms_server_to_client,
            'mac_algorithms_client_to_server': peer.mac_algorithms_client_to_server,
            'mac_algorithms_server_to_client': peer.mac_algorithms_server_to_client,
        }
        
        # Use CipherSuite to negotiate
        negotiated = self._cipher_suite.negotiate_algorithms(client_algs, server_algs)
        
        self._kex_algorithm = negotiated['kex']
        self._server_host_key_algorithm = negotiated['server_host_key']
        self._encryption_algorithm_c2s = negotiated['encryption_client_to_server']
        self._encryption_algorithm_s2c = negotiated['encryption_server_to_client']
        self._mac_algorithm_c2s = negotiated['mac_client_to_server']
        self._mac_algorithm_s2c = negotiated['mac_server_to_client']
        
        # Default compression to none
        self._compression_algorithm_c2s = COMPRESS_NONE
        self._compression_algorithm_s2c = COMPRESS_NONE
    
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
            
            # Ensure the public key is positive (SSH requirement)
            if self._dh_public_key <= 0:
                raise CryptoException("Invalid DH public key: must be positive")
            
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
            server_dh_public_blob, offset = read_string(reply_msg._data, offset)
            signature_blob, offset = read_string(reply_msg._data, offset)
            
            # Store server host key for verification
            self._transport._server_host_key_blob = server_host_key_blob
            
            # Extract server's DH public key
            server_public_int, _ = read_mpint(server_dh_public_blob, 0)
            
            # Validate server's public key
            if server_public_int <= 1 or server_public_int >= self.DH_GROUP14_P - 1:
                raise CryptoException("Invalid server DH public key")
            
            # Compute shared secret
            server_public_numbers = dh.DHPublicNumbers(server_public_int, parameters.parameter_numbers())
            server_public_key = server_public_numbers.public_key(default_backend())
            
            shared_secret_int = self._dh_private_key.exchange(server_public_key)
            self._shared_secret = write_mpint(int.from_bytes(shared_secret_int, 'big'))
            
            # Compute exchange hash
            self._compute_exchange_hash(server_host_key_blob, server_dh_public_blob, signature_blob)
            
            # Set session ID (first exchange hash)
            if self._session_id is None:
                self._session_id = self._exchange_hash
                
        except Exception as e:
            raise

    def _perform_ecdh_sha2_nistp256(self) -> None:
        """Perform ECDH NIST P-256 SHA256 key exchange."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            
            # Generate ECDH key pair
            self._ecdh_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
            public_key = self._ecdh_private_key.public_key()
            
            # Get public key in uncompressed format (SSH requirement)
            self._ecdh_public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint
            )
            
            # Send KEX_ECDH_INIT message (message type 30)
            kex_ecdh_init = Message(30)  # MSG_KEX_ECDH_INIT
            kex_ecdh_init.add_string(self._ecdh_public_key_bytes)
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
            
            # Store server host key for verification
            self._transport._server_host_key_blob = server_host_key_blob
            
            # Perform key exchange
            server_public_key = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), server_public_key_blob
            )
            shared_secret_bytes = self._ecdh_private_key.exchange(ec.ECDH(), server_public_key)
            self._shared_secret = write_mpint(int.from_bytes(shared_secret_bytes, 'big'))
            
            # Compute exchange hash using SHA256
            self._compute_ecdh_exchange_hash(server_host_key_blob, server_public_key_blob, signature_blob)
            
            # Set session ID (first exchange hash)
            if self._session_id is None:
                self._session_id = self._exchange_hash
                
        except Exception as e:
            raise

    def _compute_ecdh_exchange_hash(self, server_host_key: bytes, server_public_key: bytes, signature: bytes) -> None:
        """Compute the exchange hash H for ECDH."""
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
        hash_data.extend(write_string(self._ecdh_public_key_bytes))
        
        # Server public key
        hash_data.extend(write_string(server_public_key))
        
        # Shared secret
        hash_data.extend(self._shared_secret)
        
        # Compute SHA256 hash
        self._exchange_hash = default_crypto_backend.hash_data('sha256', bytes(hash_data))

    def _perform_dh_group1_sha1(self) -> None:
        """Perform Diffie-Hellman Group 1 SHA1 key exchange."""
        try:
            # Generate DH parameters for Group 1 (1024-bit)
            # Using the existing DH_GROUP14_P and DH_GROUP14_G constants which seem to be for Group 1.
            parameters = dh.DHParameterNumbers(self.DH_GROUP14_P, self.DH_GROUP14_G).parameters(default_backend())
            
            # Generate private key
            self._dh_private_key = parameters.generate_private_key()
            
            # Get public key
            dh_public_key = self._dh_private_key.public_key()
            public_numbers = dh_public_key.public_numbers()
            
            # Store public key value
            self._dh_public_key = public_numbers.y
            self._dh_public_key_mpint = write_mpint(public_numbers.y) # Store mpint for hash calculation
            
            # Ensure the public key is positive (SSH requirement)
            if self._dh_public_key <= 0:
                raise CryptoException("Invalid DH public key: must be positive")
            
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
            
            # Store server host key for verification
            self._transport._server_host_key_blob = server_host_key_blob
            
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
            
            # Store server host key for verification
            self._transport._server_host_key_blob = server_host_key_blob
            
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
            
            # Store server host key for verification
            self._transport._server_host_key_blob = server_host_key_blob
            
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
        
        # Get key lengths from negotiated ciphers
        c2s_cipher_info = self._cipher_suite.get_cipher_info(self._encryption_algorithm_c2s)
        s2c_cipher_info = self._cipher_suite.get_cipher_info(self._encryption_algorithm_s2c)
        
        key_len_c2s = c2s_cipher_info['key_len']
        iv_len_c2s = c2s_cipher_info['iv_len']
        key_len_s2c = s2c_cipher_info['key_len']
        iv_len_s2c = s2c_cipher_info['iv_len']
        
        # Get MAC key lengths
        mac_key_len_c2s = 0
        if self._mac_algorithm_c2s != 'none':
            mac_key_len_c2s = self._cipher_suite.get_mac_info(self._mac_algorithm_c2s)['key_len']
            
        mac_key_len_s2c = 0
        if self._mac_algorithm_s2c != 'none':
            mac_key_len_s2c = self._cipher_suite.get_mac_info(self._mac_algorithm_s2c)['key_len']
        
        # Choose hash algorithm based on KEX algorithm
        hash_alg = 'sha256'
        if 'sha512' in self._kex_algorithm:
            hash_alg = 'sha512'
        elif 'sha1' in self._kex_algorithm:
            hash_alg = 'sha1'
        
        # Generate keys using SSH key derivation
        # A: IV client to server
        self._iv_c2s = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash, 
            self._session_id, b'A', iv_len_c2s
        )
        
        # B: IV server to client
        self._iv_s2c = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash,
            self._session_id, b'B', iv_len_s2c
        )
        
        # C: Encryption key client to server
        self._encryption_key_c2s = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash,
            self._session_id, b'C', key_len_c2s
        )
        
        # D: Encryption key server to client
        self._encryption_key_s2c = default_crypto_backend.derive_key(
            hash_alg, self._shared_secret, self._exchange_hash,
            self._session_id, b'D', key_len_s2c
        )
        
        # E: MAC key client to server
        self._mac_key_c2s = b""
        if mac_key_len_c2s > 0:
            self._mac_key_c2s = default_crypto_backend.derive_key(
                hash_alg, self._shared_secret, self._exchange_hash,
                self._session_id, b'E', mac_key_len_c2s
            )
        
        # F: MAC key server to client
        self._mac_key_s2c = b""
        if mac_key_len_s2c > 0:
            self._mac_key_s2c = default_crypto_backend.derive_key(
                hash_alg, self._shared_secret, self._exchange_hash,
                self._session_id, b'F', mac_key_len_s2c
            )
        
        # Update transport with keys and parameters
        self._transport._encryption_key_c2s = self._encryption_key_c2s
        self._transport._encryption_key_s2c = self._encryption_key_s2c
        self._transport._mac_key_c2s = self._mac_key_c2s
        self._transport._mac_key_s2c = self._mac_key_s2c
        self._transport._iv_c2s = self._iv_c2s
        self._transport._iv_s2c = self._iv_s2c
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