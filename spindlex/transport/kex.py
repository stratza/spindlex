"""
SSH Key Exchange Implementation

Implements SSH key exchange algorithms including Curve25519, ECDH,
and Diffie-Hellman for secure session key establishment.
"""

from typing import Any, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh

from ..crypto.backend import default_crypto_backend
from ..crypto.ciphers import CipherSuite
from ..exceptions import CryptoException, ProtocolException
from ..protocol.constants import (
    COMPRESS_NONE,
    KEX_COOKIE_SIZE,
    KEX_CURVE25519_SHA256,
    KEX_DH_GROUP14_SHA256,
    KEX_ECDH_SHA2_NISTP256,
    MSG_KEX_ECDH_INIT,
    MSG_KEX_ECDH_REPLY,
    MSG_KEXDH_INIT,
    MSG_KEXDH_REPLY,
    MSG_KEXINIT,
    MSG_NEWKEYS,
)
from ..protocol.messages import KexInitMessage, Message
from ..protocol.utils import (
    read_mpint,
    read_string,
    write_mpint,
    write_string,
)


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
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
        16,
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
        self._dh_public_key: Optional[int] = None
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
            if not self._transport._peer_kexinit:
                self._send_kexinit()
                self._receive_kexinit()

            peer_kexinit_blob = self._transport._peer_kexinit.pack()
            our_kexinit_blob = self._transport._client_kexinit_blob

            if self._transport._server_mode:
                self._client_kexinit = peer_kexinit_blob
                self._server_kexinit = our_kexinit_blob
            else:
                self._client_kexinit = our_kexinit_blob
                self._server_kexinit = peer_kexinit_blob

            # Negotiate algorithms
            self._negotiate_algorithms()

            # Perform key exchange based on negotiated algorithm
            if self._transport._server_mode:
                self._perform_server_kex()
            else:
                self._perform_client_kex()

            # Generate session keys
            self._generate_session_keys()

            # Send NEWKEYS message
            self._send_newkeys()

            # Receive NEWKEYS message
            self._receive_newkeys()

        except Exception as e:
            if isinstance(e, (CryptoException, ProtocolException)):
                raise
            raise CryptoException(f"Key exchange failed: {e}") from e

    def _perform_client_kex(self) -> None:
        """Perform client-side key exchange."""
        if self._kex_algorithm in [
            KEX_CURVE25519_SHA256,
            "curve25519-sha256@libssh.org",
        ]:
            self._perform_curve25519_sha256()
        elif self._kex_algorithm == KEX_ECDH_SHA2_NISTP256:
            self._perform_ecdh_sha2_nistp256()
        elif self._kex_algorithm == KEX_DH_GROUP14_SHA256:
            self._perform_dh_group14_sha256()
        else:
            self._kex_algorithm = KEX_DH_GROUP14_SHA256
            self._perform_dh_group14_sha256()

    def _perform_server_kex(self) -> None:
        """Perform server-side key exchange."""
        if self._kex_algorithm in [
            KEX_CURVE25519_SHA256,
            "curve25519-sha256@libssh.org",
        ]:
            self._perform_curve25519_sha256_server()
        elif self._kex_algorithm == KEX_ECDH_SHA2_NISTP256:
            self._perform_ecdh_sha2_nistp256_server()
        elif self._kex_algorithm == KEX_DH_GROUP14_SHA256:
            self._perform_dh_group14_sha256_server()
        else:
            self._kex_algorithm = KEX_DH_GROUP14_SHA256
            self._perform_dh_group14_sha256_server()

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
            first_kex_packet_follows=False,
        )

        # Store our KEXINIT for hash calculation
        self._client_kexinit = kexinit_msg.pack()

        # Send the message
        self._transport._send_message(kexinit_msg)

    def _receive_kexinit(self) -> None:
        """Receive and process server KEXINIT message."""
        msg = self._transport._expect_message(MSG_KEXINIT)

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
            "kex_algorithms": self._cipher_suite.KEX_ALGORITHMS,
            "server_host_key_algorithms": self._cipher_suite.HOST_KEY_ALGORITHMS,
            "encryption_algorithms_client_to_server": self._cipher_suite.ENCRYPTION_ALGORITHMS,
            "encryption_algorithms_server_to_client": self._cipher_suite.ENCRYPTION_ALGORITHMS,
            "mac_algorithms_client_to_server": self._cipher_suite.MAC_ALGORITHMS,
            "mac_algorithms_server_to_client": self._cipher_suite.MAC_ALGORITHMS,
        }

        # Build server algorithms dict
        peer = self._transport._peer_kexinit
        server_algs = {
            "kex_algorithms": peer.kex_algorithms,
            "server_host_key_algorithms": peer.server_host_key_algorithms,
            "encryption_algorithms_client_to_server": peer.encryption_algorithms_client_to_server,
            "encryption_algorithms_server_to_client": peer.encryption_algorithms_server_to_client,
            "mac_algorithms_client_to_server": peer.mac_algorithms_client_to_server,
            "mac_algorithms_server_to_client": peer.mac_algorithms_server_to_client,
        }

        # Use CipherSuite to negotiate
        negotiated = self._cipher_suite.negotiate_algorithms(client_algs, server_algs)
        self._transport._logger.debug(f"Negotiated algorithms: {negotiated}")

        self._kex_algorithm = negotiated["kex"]
        self._server_host_key_algorithm = negotiated["server_host_key"]
        self._encryption_algorithm_c2s = negotiated["encryption_client_to_server"]
        self._encryption_algorithm_s2c = negotiated["encryption_server_to_client"]
        self._mac_algorithm_c2s = negotiated["mac_client_to_server"]
        self._mac_algorithm_s2c = negotiated["mac_server_to_client"]

        # Default compression to none
        self._compression_algorithm_c2s = COMPRESS_NONE
        self._compression_algorithm_s2c = COMPRESS_NONE

    def _choose_algorithm(self, client_list: list[str], server_list: list[str]) -> str:
        """Choose first matching algorithm from client and server lists, excluding extensions."""
        # Filter out SSH extensions and Terrapin/strict-KEX markers. Names must
        # match what Transport advertises; the v00 spelling does not exist in
        # any deployed implementation and previously let the v01 marker leak
        # into the negotiation pool, silently disabling the strict-KEX defense.
        extensions = {
            "ext-info-c",
            "ext-info-s",
            "kex-strict-c-v01@openssh.com",
            "kex-strict-s-v01@openssh.com",
        }

        client_algs = [alg for alg in client_list if alg not in extensions]
        server_algs = [alg for alg in server_list if alg not in extensions]

        for client_alg in client_algs:
            if client_alg in server_algs:
                return client_alg

        raise CryptoException(
            f"No matching algorithms: client={client_algs}, server={server_algs}"
        )

    def _perform_dh_group14_sha256(self) -> None:
        """Perform Diffie-Hellman Group 14 SHA256 key exchange."""
        try:
            # Generate DH parameters
            parameters = dh.DHParameterNumbers(
                self.DH_GROUP14_P, self.DH_GROUP14_G
            ).parameters(default_backend())

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
            assert self._dh_public_key is not None
            kexdh_init.add_mpint(self._dh_public_key)
            self._transport._send_message(kexdh_init)

            # Receive KEXDH_REPLY
            reply_msg = self._transport._expect_message(MSG_KEXDH_REPLY)

            # Parse KEXDH_REPLY
            offset = 0
            server_host_key_blob, offset = read_string(reply_msg._data, offset)

            # Extract server's DH public key (f)
            # We need the blob for hash computation and the int for DH
            server_dh_public_blob, offset = read_string(reply_msg._data, offset)
            server_public_int = int.from_bytes(
                server_dh_public_blob, "big", signed=True
            )

            signature_blob, offset = read_string(reply_msg._data, offset)

            # Store host key blob for transport
            self._transport._server_host_key_blob = server_host_key_blob

            # Validate server's public key
            if server_public_int <= 1 or server_public_int >= self.DH_GROUP14_P - 1:
                raise CryptoException("Invalid server DH public key")

            # Compute shared secret
            server_public_numbers = dh.DHPublicNumbers(
                server_public_int, parameters.parameter_numbers()
            )
            server_public_key = server_public_numbers.public_key(default_backend())

            shared_secret_int = self._dh_private_key.exchange(server_public_key)
            self._shared_secret = write_mpint(int.from_bytes(shared_secret_int, "big"))

            # Compute exchange hash
            self._compute_exchange_hash(
                server_host_key_blob, server_dh_public_blob, signature_blob
            )

            # Set session ID (first exchange hash)
            if self._session_id is None:
                self._session_id = self._exchange_hash

            # Verify server signature
            self._verify_server_signature(server_host_key_blob, signature_blob)

        except Exception:
            raise

    def _verify_server_signature(
        self, server_host_key_blob: bytes, signature_blob: bytes
    ) -> None:
        """Verify server host key signature."""
        from ..crypto.pkey import PKey

        try:
            server_key = PKey.from_string(server_host_key_blob)
            assert self._exchange_hash is not None
            if not server_key.verify(signature_blob, self._exchange_hash):
                raise CryptoException("Server host key signature verification failed")
        except Exception as e:
            if isinstance(e, CryptoException):
                raise
            raise CryptoException(f"Failed to verify server signature: {e}") from e

    def _perform_ecdh_sha2_nistp256(self) -> None:
        """Perform ECDH NIST P-256 SHA256 key exchange."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec

            # Generate ECDH key pair
            self._ecdh_private_key = ec.generate_private_key(
                ec.SECP256R1(), default_backend()
            )
            public_key = self._ecdh_private_key.public_key()

            # Get public key in uncompressed format (SSH requirement)
            self._ecdh_public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )

            # Send KEX_ECDH_INIT message
            kex_ecdh_init = Message(MSG_KEX_ECDH_INIT)
            kex_ecdh_init.add_string(self._ecdh_public_key_bytes)
            self._transport._send_message(kex_ecdh_init)

            # Receive KEX_ECDH_REPLY message
            reply_msg = self._transport._expect_message(MSG_KEX_ECDH_REPLY)

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
            shared_secret_bytes = self._ecdh_private_key.exchange(
                ec.ECDH(), server_public_key
            )
            self._shared_secret = write_mpint(
                int.from_bytes(shared_secret_bytes, "big")
            )

            # Compute exchange hash using SHA256
            self._compute_ecdh_exchange_hash(
                server_host_key_blob, server_public_key_blob, signature_blob
            )

            # Set session ID (first exchange hash)
            if self._session_id is None:
                self._session_id = self._exchange_hash

            # Verify server signature
            self._verify_server_signature(server_host_key_blob, signature_blob)

        except Exception:
            raise

    def _compute_ecdh_exchange_hash(
        self,
        server_host_key: bytes,
        server_public_key: bytes,
        signature: bytes,
        client_ecdh_public_key: Optional[bytes] = None,
    ) -> None:
        """Compute the exchange hash H for ECDH.

        client_ecdh_public_key overrides self._ecdh_public_key_bytes, allowing
        the server-side path to pass in the client's key without mutating state.
        """
        hash_data = bytearray()

        # Client version string
        client_version = self._transport._client_version or "SSH-2.0-SpindleX_1.0"
        hash_data.extend(write_string(client_version))

        # Server version string
        server_version = self._transport._server_version or "SSH-2.0-Unknown"
        hash_data.extend(write_string(server_version))

        # Client KEXINIT
        if self._client_kexinit is None:
            raise CryptoException("Missing client KEXINIT for ECDH exchange hash")
        hash_data.extend(write_string(self._client_kexinit))

        # Server KEXINIT
        if self._server_kexinit is None:
            raise CryptoException("Missing server KEXINIT for ECDH exchange hash")
        hash_data.extend(write_string(self._server_kexinit))

        # Server host key
        hash_data.extend(write_string(server_host_key))

        # Client public key
        client_pub = (
            client_ecdh_public_key
            if client_ecdh_public_key is not None
            else self._ecdh_public_key_bytes
        )
        if client_pub is None:
            raise CryptoException("Missing ECDH client public key for exchange hash")
        hash_data.extend(write_string(client_pub))

        # Server public key
        hash_data.extend(write_string(server_public_key))

        # Shared secret
        if self._shared_secret is None:
            raise CryptoException("Missing shared secret for ECDH exchange hash")
        hash_data.extend(self._shared_secret)

        # Compute SHA256 hash
        self._exchange_hash = default_crypto_backend.hash_data(
            "sha256", bytes(hash_data)
        )

    def _perform_curve25519_sha256_server(self) -> None:
        """Perform Curve25519 SHA256 key exchange on the server side."""
        try:
            from cryptography.hazmat.primitives.asymmetric import x25519

            # 1. Receive KEX_ECDH_INIT
            init_msg = self._transport._expect_message(MSG_KEX_ECDH_INIT)
            client_public_key_blob, _ = read_string(init_msg._data, 0)

            # 2. Generate server Curve25519 key pair
            self._curve25519_private_key = x25519.X25519PrivateKey.generate()
            server_public_key = self._curve25519_private_key.public_key()
            server_public_key_bytes = server_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # 3. Compute shared secret
            client_public_key = x25519.X25519PublicKey.from_public_bytes(
                client_public_key_blob
            )
            shared_secret_bytes = self._curve25519_private_key.exchange(
                client_public_key
            )
            self._shared_secret = write_mpint(
                int.from_bytes(shared_secret_bytes, "big")
            )

            # 4. Get server host key blob
            server_host_key = self._transport._server_key
            server_host_key_blob = server_host_key.get_public_key_bytes()

            # 5. Compute exchange hash H
            self._compute_curve25519_exchange_hash(
                server_host_key_blob, client_public_key_blob, server_public_key_bytes
            )

            # 6. Sign exchange hash
            signature_blob = self._sign_exchange_hash(self._exchange_hash)  # type: ignore[arg-type]

            # 7. Send KEX_ECDH_REPLY
            reply_msg = Message(MSG_KEX_ECDH_REPLY)
            reply_msg.add_string(server_host_key_blob)
            reply_msg.add_string(server_public_key_bytes)
            reply_msg.add_string(signature_blob)
            self._transport._send_message(reply_msg)

            # Set session ID
            if self._session_id is None:
                self._session_id = self._exchange_hash

        except Exception as e:
            raise CryptoException(f"Curve25519 server KEX failed: {e}") from e

    def _perform_dh_group14_sha256_server(self) -> None:
        """Perform server-side Diffie-Hellman Group 14 SHA256 key exchange."""
        try:
            # 1. Receive MSG_KEXDH_INIT (30)
            init_msg = self._transport._expect_message(MSG_KEXDH_INIT)
            client_public_key_int, _ = read_mpint(init_msg._data, 0)

            # 2. Generate DH parameters and private key
            parameters = dh.DHParameterNumbers(
                self.DH_GROUP14_P, self.DH_GROUP14_G
            ).parameters(default_backend())
            self._dh_private_key = parameters.generate_private_key()

            # 3. Get server public key (f)
            server_public_key = self._dh_private_key.public_key()
            server_public_numbers = server_public_key.public_numbers()
            self._dh_public_key = server_public_numbers.y
            self._dh_public_key_mpint = write_mpint(server_public_numbers.y)

            # 4. Compute shared secret (K)
            client_public_numbers = dh.DHPublicNumbers(
                client_public_key_int, parameters.parameter_numbers()
            )
            client_public_key_obj = client_public_numbers.public_key(default_backend())
            shared_secret_int = self._dh_private_key.exchange(client_public_key_obj)
            self._shared_secret = write_mpint(int.from_bytes(shared_secret_int, "big"))

            # 5. Get server host key blob (K_S)
            server_host_key = self._transport._server_key
            server_host_key_blob = server_host_key.get_public_key_bytes()

            # 6. Compute exchange hash H — pass client key explicitly to avoid mutating state
            self._compute_exchange_hash(
                server_host_key_blob,
                write_mpint(server_public_numbers.y)[4:],  # strip 4-byte length prefix
                b"",  # signature not used during hash computation itself
                client_dh_public_mpint=write_mpint(client_public_key_int),
            )

            # 7. Sign exchange hash
            signature_blob = self._sign_exchange_hash(self._exchange_hash)  # type: ignore[arg-type]

            # 8. Send MSG_KEXDH_REPLY (31)
            reply_msg = Message(MSG_KEXDH_REPLY)
            reply_msg.add_string(server_host_key_blob)
            reply_msg.add_string(write_mpint(server_public_numbers.y))
            reply_msg.add_string(signature_blob)
            self._transport._send_message(reply_msg)

            # Set session ID
            if self._session_id is None:
                self._session_id = self._exchange_hash

        except Exception as e:
            raise CryptoException(f"DH Group 14 server KEX failed: {e}") from e

    def _perform_ecdh_sha2_nistp256_server(self) -> None:
        """Perform server-side ECDH NIST P-256 SHA256 key exchange."""
        try:
            from cryptography.hazmat.primitives.asymmetric import ec

            # 1. Receive KEX_ECDH_INIT with client's P-256 public key
            init_msg = self._transport._expect_message(MSG_KEX_ECDH_INIT)
            client_public_key_blob, _ = read_string(init_msg._data, 0)

            # 2. Generate server P-256 key pair
            self._ecdh_private_key = ec.generate_private_key(
                ec.SECP256R1(), default_backend()
            )
            server_public_key = self._ecdh_private_key.public_key()
            self._ecdh_public_key_bytes = server_public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )

            # 3. Compute shared secret
            client_public_key_obj = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), client_public_key_blob
            )
            shared_secret_bytes = self._ecdh_private_key.exchange(
                ec.ECDH(), client_public_key_obj
            )
            self._shared_secret = write_mpint(
                int.from_bytes(shared_secret_bytes, "big")
            )

            # 4. Get server host key blob
            server_host_key = self._transport._server_key
            server_host_key_blob = server_host_key.get_public_key_bytes()

            # 5. Compute exchange hash — pass client key explicitly to avoid mutating state
            self._compute_ecdh_exchange_hash(
                server_host_key_blob,
                self._ecdh_public_key_bytes,  # server's public key
                b"",
                client_ecdh_public_key=client_public_key_blob,
            )

            # 6. Sign exchange hash
            signature_blob = self._sign_exchange_hash(self._exchange_hash)  # type: ignore[arg-type]

            # 7. Send KEX_ECDH_REPLY
            reply_msg = Message(MSG_KEX_ECDH_REPLY)
            reply_msg.add_string(server_host_key_blob)
            reply_msg.add_string(self._ecdh_public_key_bytes)
            reply_msg.add_string(signature_blob)
            self._transport._send_message(reply_msg)

            # 8. Set session ID
            if self._session_id is None:
                self._session_id = self._exchange_hash

        except Exception as e:
            raise CryptoException(f"ECDH P-256 server KEX failed: {e}") from e

    def _sign_exchange_hash(self, exchange_hash: bytes) -> bytes:
        """Sign exchange hash using server private key."""
        server_key = self._transport._server_key
        if server_key is None:
            raise CryptoException("Server key not set — cannot sign exchange hash")
        signature = server_key.sign(exchange_hash)
        if signature is None:
            raise CryptoException("Failed to sign exchange hash")
        return signature  # type: ignore[no-any-return]

    def _perform_curve25519_sha256(self) -> None:
        """Perform client-side Curve25519 SHA256 key exchange."""
        try:
            from cryptography.hazmat.primitives.asymmetric import x25519

            # Generate Curve25519 key pair
            self._curve25519_private_key = x25519.X25519PrivateKey.generate()
            public_key = self._curve25519_private_key.public_key()
            client_public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # Send KEX_ECDH_INIT
            kex_ecdh_init = Message(MSG_KEX_ECDH_INIT)
            kex_ecdh_init.add_string(client_public_key_bytes)
            self._transport._send_message(kex_ecdh_init)

            # Receive KEX_ECDH_REPLY
            reply_msg = self._transport._expect_message(MSG_KEX_ECDH_REPLY)
            offset = 0
            server_host_key_blob, offset = read_string(reply_msg._data, offset)
            server_public_key_blob, offset = read_string(reply_msg._data, offset)
            signature_blob, offset = read_string(reply_msg._data, offset)

            # Store host key blob for transport
            self._transport._server_host_key_blob = server_host_key_blob

            # Perform DH
            server_public_key = x25519.X25519PublicKey.from_public_bytes(
                server_public_key_blob
            )
            shared_secret_bytes = self._curve25519_private_key.exchange(
                server_public_key
            )
            self._shared_secret = write_mpint(
                int.from_bytes(shared_secret_bytes, "big")
            )

            # Compute hash (Client order: host_key, client_pub, server_pub)
            self._compute_curve25519_exchange_hash(
                server_host_key_blob, client_public_key_bytes, server_public_key_blob
            )

            if self._session_id is None:
                self._session_id = self._exchange_hash

            self._verify_server_signature(server_host_key_blob, signature_blob)
        except Exception as e:
            raise CryptoException(f"Curve25519 client KEX failed: {e}") from e

    def _compute_curve25519_exchange_hash(
        self, server_host_key: bytes, client_public_key: bytes, server_public_key: bytes
    ) -> None:
        """Compute the exchange hash H for Curve25519."""
        hash_data = bytearray()
        hash_data.extend(
            write_string(self._transport._client_version or "SSH-2.0-SpindleX_1.0")
        )
        hash_data.extend(
            write_string(self._transport._server_version or "SSH-2.0-Unknown")
        )
        hash_data.extend(write_string(self._client_kexinit))  # type: ignore[arg-type]
        hash_data.extend(write_string(self._server_kexinit))  # type: ignore[arg-type]
        hash_data.extend(write_string(server_host_key))
        hash_data.extend(write_string(client_public_key))
        hash_data.extend(write_string(server_public_key))
        hash_data.extend(self._shared_secret)  # type: ignore[arg-type]

        self._exchange_hash = default_crypto_backend.hash_data(
            "sha256", bytes(hash_data)
        )

    def _compute_exchange_hash(
        self,
        server_host_key: bytes,
        server_dh_public: bytes,
        signature: bytes,
        client_dh_public_mpint: Optional[bytes] = None,
    ) -> None:
        """Compute the exchange hash H for DH key exchange.

        client_dh_public_mpint overrides self._dh_public_key_mpint, allowing
        the server-side path to pass in the client's key without mutating state.
        """
        hash_data = bytearray()

        # Client version string
        client_version = self._transport._client_version or "SSH-2.0-SpindleX_1.0"
        hash_data.extend(write_string(client_version))

        # Server version string
        server_version = self._transport._server_version or "SSH-2.0-Unknown"
        hash_data.extend(write_string(server_version))

        # Client KEXINIT
        if self._client_kexinit is None:
            raise CryptoException("Missing client KEXINIT")
        hash_data.extend(write_string(self._client_kexinit))

        # Server KEXINIT
        if self._server_kexinit is None:
            raise CryptoException("Missing server KEXINIT")
        hash_data.extend(write_string(self._server_kexinit))

        # Server host key
        hash_data.extend(write_string(server_host_key))

        # Client DH public key (e)
        client_mpint = (
            client_dh_public_mpint
            if client_dh_public_mpint is not None
            else self._dh_public_key_mpint
        )
        if client_mpint is None:
            raise CryptoException("Missing DH client public key")
        hash_data.extend(client_mpint)

        # Server DH public key (f) - must be encoded as mpint/string
        hash_data.extend(write_string(server_dh_public))

        # Shared secret
        if self._shared_secret is None:
            raise CryptoException("Missing shared secret")
        hash_data.extend(self._shared_secret)

        # Compute SHA256 hash
        self._exchange_hash = default_crypto_backend.hash_data(
            "sha256", bytes(hash_data)
        )

    def _generate_session_keys(self) -> None:
        """Generate session keys from shared secret and exchange hash."""
        # First-time handshake: session_id is equal to first exchange_hash
        effective_session_id = self._session_id or self._exchange_hash

        if (
            not self._shared_secret
            or not self._exchange_hash
            or not effective_session_id
            or self._encryption_algorithm_c2s is None
            or self._encryption_algorithm_s2c is None
        ):
            raise CryptoException("Missing key exchange data for key generation")

        # Get key lengths from negotiated ciphers
        c2s_cipher_info = self._cipher_suite.get_cipher_info(
            self._encryption_algorithm_c2s
        )
        s2c_cipher_info = self._cipher_suite.get_cipher_info(
            self._encryption_algorithm_s2c
        )

        key_len_c2s = c2s_cipher_info["key_len"]
        iv_len_c2s = c2s_cipher_info["iv_len"]
        key_len_s2c = s2c_cipher_info["key_len"]
        iv_len_s2c = s2c_cipher_info["iv_len"]

        # Get MAC key lengths
        mac_key_len_c2s = 0
        if self._mac_algorithm_c2s != "none" and self._mac_algorithm_c2s is not None:
            mac_key_len_c2s = self._cipher_suite.get_mac_info(self._mac_algorithm_c2s)[
                "key_len"
            ]

        mac_key_len_s2c = 0
        if self._mac_algorithm_s2c != "none" and self._mac_algorithm_s2c is not None:
            mac_key_len_s2c = self._cipher_suite.get_mac_info(self._mac_algorithm_s2c)[
                "key_len"
            ]

        # Choose hash algorithm based on KEX algorithm
        hash_alg = "sha256"
        if self._kex_algorithm and "sha512" in self._kex_algorithm:
            hash_alg = "sha512"

        # Generate keys using SSH key derivation
        # A: IV client to server
        self._iv_c2s = default_crypto_backend.derive_key(
            hash_alg,
            self._shared_secret,
            self._exchange_hash,
            effective_session_id,
            b"A",
            iv_len_c2s,
        )

        # B: IV server to client
        self._iv_s2c = default_crypto_backend.derive_key(
            hash_alg,
            self._shared_secret,
            self._exchange_hash,
            effective_session_id,
            b"B",
            iv_len_s2c,
        )

        # C: Encryption key client to server
        self._encryption_key_c2s = default_crypto_backend.derive_key(
            hash_alg,
            self._shared_secret,
            self._exchange_hash,
            effective_session_id,
            b"C",
            key_len_c2s,
        )

        # D: Encryption key server to client
        self._encryption_key_s2c = default_crypto_backend.derive_key(
            hash_alg,
            self._shared_secret,
            self._exchange_hash,
            effective_session_id,
            b"D",
            key_len_s2c,
        )

        # E: MAC key client to server
        self._mac_key_c2s = b""
        if mac_key_len_c2s > 0:
            self._mac_key_c2s = default_crypto_backend.derive_key(
                hash_alg,
                self._shared_secret,
                self._exchange_hash,
                effective_session_id,
                b"E",
                mac_key_len_c2s,
            )

        # F: MAC key server to client
        self._mac_key_s2c = b""
        if mac_key_len_s2c > 0:
            self._mac_key_s2c = default_crypto_backend.derive_key(
                hash_alg,
                self._shared_secret,
                self._exchange_hash,
                effective_session_id,
                b"F",
                mac_key_len_s2c,
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
        self._transport._expect_message(MSG_NEWKEYS)

    def generate_keys(self) -> tuple[bytes, bytes, bytes, bytes]:
        """
        Generate session keys from shared secret.

        Returns:
            Tuple of (encryption_key_c2s, encryption_key_s2c, mac_key_c2s, mac_key_s2c)

        Raises:
            CryptoException: If key generation fails
        """
        if not all(
            [
                self._encryption_key_c2s,
                self._encryption_key_s2c,
                self._mac_key_c2s,
                self._mac_key_s2c,
            ]
        ):
            raise CryptoException("Keys not generated - run key exchange first")

        return (
            self._encryption_key_c2s,
            self._encryption_key_s2c,
            self._mac_key_c2s,
            self._mac_key_s2c,
        )
