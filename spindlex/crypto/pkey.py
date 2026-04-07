"""
SSH Public Key Implementation

Implements SSH public key handling including Ed25519, ECDSA, and RSA keys
with support for key loading, fingerprinting, and signature operations.
"""

import base64
import hashlib
import struct
from typing import Any, Optional, Tuple, Union

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from ..exceptions import BadHostKeyException, CryptoException
from ..protocol.utils import write_mpint
from .backend import CryptoBackend, default_crypto_backend


class PKey:
    """
    Base class for SSH public keys.

    Provides common interface for different public key types with support
    for loading, saving, signing, verification, and fingerprinting.
    """

    def __init__(self, crypto_backend: Optional[CryptoBackend] = None) -> None:
        """
        Initialize public key.

        Args:
            crypto_backend: Cryptographic backend to use
        """
        self.crypto_backend = crypto_backend or default_crypto_backend
        self._key: Any = None

    @property
    def algorithm_name(self) -> str:
        """Get SSH algorithm name for this key type."""
        raise NotImplementedError("Subclasses must implement algorithm_name")

    def load_private_key(
        self, key_data: bytes, password: Optional[bytes] = None
    ) -> None:
        """
        Load private key from bytes.

        Args:
            key_data: Private key data (PEM or OpenSSH format)
            password: Optional password for encrypted keys

        Raises:
            CryptoException: If key loading fails
        """
        raise NotImplementedError("Subclasses must implement load_private_key")

    def load_public_key(self, key_data: bytes) -> None:
        """
        Load public key from bytes.

        Args:
            key_data: Public key data (SSH wire format)

        Raises:
            CryptoException: If key loading fails
        """
        raise NotImplementedError("Subclasses must implement load_public_key")

    def get_public_key_bytes(self) -> bytes:
        """
        Get public key in SSH wire format.

        Returns:
            Public key bytes in SSH wire format

        Raises:
            CryptoException: If no key loaded
        """
        raise NotImplementedError("Subclasses must implement get_public_key_bytes")

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with private key.

        Args:
            data: Data to sign

        Returns:
            Signature bytes in SSH format

        Raises:
            CryptoException: If signing fails or no private key
        """
        raise NotImplementedError("Subclasses must implement sign")

    def verify(self, signature: bytes, data: bytes) -> bool:
        """
        Verify signature with public key.

        Args:
            signature: Signature bytes in SSH format
            data: Original data that was signed

        Returns:
            True if signature is valid, False otherwise
        """
        raise NotImplementedError("Subclasses must implement verify")

    def get_fingerprint(self, hash_algorithm: str = "sha256") -> str:
        """
        Get key fingerprint.

        Args:
            hash_algorithm: Hash algorithm to use (md5, sha256)

        Returns:
            Formatted fingerprint string

        Raises:
            CryptoException: If fingerprint generation fails
        """
        try:
            key_bytes = self.get_public_key_bytes()

            if hash_algorithm == "md5":
                digest = hashlib.md5(key_bytes).digest()
                return "MD5:" + ":".join(f"{b:02x}" for b in digest)
            elif hash_algorithm == "sha256":
                digest = hashlib.sha256(key_bytes).digest()
                return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
            else:
                raise CryptoException(f"Unsupported hash algorithm: {hash_algorithm}")
        except Exception as e:
            raise CryptoException(f"Fingerprint generation failed: {e}")

    def __eq__(self, other: object) -> bool:
        """Compare keys for equality."""
        if not isinstance(other, PKey):
            return False
        try:
            return self.get_public_key_bytes() == other.get_public_key_bytes()
        except:
            return False

    @classmethod
    def generate(cls, *args: Any, **kwargs: Any) -> "PKey":
        """
        Generate a new key pair.

        Returns:
            New PKey instance with generated key pair
        """
        raise NotImplementedError("Subclasses must implement generate")

    def save_to_file(self, filename: str, password: Optional[str] = None) -> None:
        """
        Save private key to file in PEM format.

        Args:
            filename: Path to save key file
            password: Optional password for encryption

        Raises:
            CryptoException: If saving fails
        """
        raise NotImplementedError("Subclasses must implement save_to_file")

    def get_openssh_string(self) -> str:
        """
        Get public key in OpenSSH format.

        Returns:
            Public key string in OpenSSH format (e.g., "ssh-rsa AAAAB3N...")
        """
        key_bytes = self.get_public_key_bytes()
        # Parse out the algorithm name from the bytes (first string)
        algo_len = struct.unpack(">I", key_bytes[:4])[0]
        algo_name = key_bytes[4 : 4 + algo_len].decode()
        
        key_base64 = base64.b64encode(key_bytes).decode()
        return f"{algo_name} {key_base64}"

    @classmethod
    def from_private_key_file(cls, filename: str, password: Optional[str] = None) -> "PKey":
        """
        Load private key from file.

        Args:
            filename: Path to key file
            password: Optional password for encrypted keys

        Returns:
            Loaded PKey instance
        """
        return load_key_from_file(filename, password)

    def get_public_key(self) -> "PKey":
        """
        Get a PKey instance containing only the public key.

        Returns:
            PKey instance with only public key loaded
        """
        new_key = self.__class__(self.crypto_backend)
        new_key.load_public_key(self.get_public_key_bytes())
        return new_key


class Ed25519Key(PKey):
    """
    Ed25519 SSH key implementation.

    Implements ssh-ed25519 key type using Ed25519 signature algorithm.
    """

    @property
    def algorithm_name(self) -> str:
        """Get SSH algorithm name."""
        return "ssh-ed25519"

    def load_private_key(
        self, key_data: bytes, password: Optional[bytes] = None
    ) -> None:
        """
        Load Ed25519 private key.

        Args:
            key_data: Private key data (PEM or OpenSSH format)
            password: Optional password for encrypted keys

        Raises:
            CryptoException: If key loading fails
        """
        try:
            self._key = serialization.load_pem_private_key(
                key_data, password=password, backend=default_backend()
            )
            if not isinstance(self._key, ed25519.Ed25519PrivateKey):
                raise CryptoException("Key is not Ed25519 private key")
        except Exception as e:
            raise CryptoException(f"Failed to load Ed25519 private key: {e}")

    def load_public_key(self, key_data: bytes) -> None:
        """
        Load Ed25519 public key from SSH wire format.

        Args:
            key_data: Public key data in SSH wire format

        Raises:
            CryptoException: If key loading fails
        """
        try:
            # Parse SSH wire format: string algorithm_name, string public_key
            offset = 0

            # Read algorithm name
            algo_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4
            algorithm = key_data[offset : offset + algo_len].decode()
            offset += algo_len

            if algorithm not in ["ssh-ed25519", "ed25519"]:
                raise CryptoException(f"Expected ssh-ed25519, got {algorithm}")

            # Read public key bytes
            key_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4
            public_key_bytes = key_data[offset : offset + key_len]

            if len(public_key_bytes) != 32:
                raise CryptoException("Invalid Ed25519 public key length")

            self._key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        except Exception as e:
            raise CryptoException(f"Failed to load Ed25519 public key: {e}")

    def get_public_key_bytes(self) -> bytes:
        """
        Get Ed25519 public key in SSH wire format.

        Returns:
            Public key bytes in SSH wire format

        Raises:
            CryptoException: If no key loaded
        """
        try:
            if self._key is None:
                raise CryptoException("No key loaded")

            # Get public key
            if isinstance(self._key, ed25519.Ed25519PrivateKey):
                public_key = self._key.public_key()
            else:
                public_key = self._key

            # Get raw public key bytes
            public_key_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )

            # Format as SSH wire format
            algorithm = b"ssh-ed25519"
            result = struct.pack(">I", len(algorithm)) + algorithm
            result += struct.pack(">I", len(public_key_bytes)) + public_key_bytes
            return result
        except Exception as e:
            raise CryptoException(f"Failed to get Ed25519 public key bytes: {e}")

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with Ed25519 private key.

        Args:
            data: Data to sign

        Returns:
            Signature bytes in SSH format

        Raises:
            CryptoException: If signing fails or no private key
        """
        try:
            if not isinstance(self._key, ed25519.Ed25519PrivateKey):
                raise CryptoException("No Ed25519 private key loaded")

            # Sign data
            signature = self._key.sign(data)

            # Format as SSH signature
            algorithm = b"ssh-ed25519"
            result = struct.pack(">I", len(algorithm)) + algorithm
            result += struct.pack(">I", len(signature)) + signature
            return result
        except Exception as e:
            raise CryptoException(f"Ed25519 signing failed: {e}")

    @classmethod
    def generate(cls, *args: Any, **kwargs: Any) -> "Ed25519Key":
        """Generate a new Ed25519 key pair."""
        key = cls()
        key._key = ed25519.Ed25519PrivateKey.generate()
        return key

    def save_to_file(self, filename: str, password: Optional[str] = None) -> None:
        """Save Ed25519 private key to file."""
        try:
            if not isinstance(self._key, ed25519.Ed25519PrivateKey):
                raise CryptoException("No Ed25519 private key loaded")

            encryption_algorithm = (
                serialization.BestAvailableEncryption(password.encode())
                if password
                else serialization.NoEncryption()
            )

            pem = self._key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=encryption_algorithm,
            )

            with open(filename, "wb") as f:
                f.write(pem)
        except Exception as e:
            raise CryptoException(f"Failed to save Ed25519 key: {e}")

    def verify(self, signature: bytes, data: bytes) -> bool:
        """
        Verify Ed25519 signature.

        Args:
            signature: Signature bytes in SSH format
            data: Original data that was signed

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if self._key is None:
                return False

            # Get public key
            if isinstance(self._key, ed25519.Ed25519PrivateKey):
                public_key = self._key.public_key()
            else:
                public_key = self._key

            # Parse SSH signature format
            offset = 0
            algo_len = struct.unpack(">I", signature[offset : offset + 4])[0]
            offset += 4
            algorithm = signature[offset : offset + algo_len].decode()
            offset += algo_len

            if algorithm != "ssh-ed25519":
                return False

            sig_len = struct.unpack(">I", signature[offset : offset + 4])[0]
            offset += 4
            sig_bytes = signature[offset : offset + sig_len]

            # Verify signature
            public_key.verify(sig_bytes, data)
            return True
        except:
            return False


class ECDSAKey(PKey):
    """
    ECDSA SSH key implementation.

    Implements ecdsa-sha2-nistp256 key type using NIST P-256 curve.
    """

    def __init__(self, crypto_backend: Optional[CryptoBackend] = None) -> None:
        """Initialize ECDSA key with P-256 curve."""
        super().__init__(crypto_backend)
        self.curve = ec.SECP256R1()
        self.curve_name = "nistp256"

    @property
    def algorithm_name(self) -> str:
        """Get SSH algorithm name."""
        return "ecdsa-sha2-nistp256"

    def load_private_key(
        self, key_data: bytes, password: Optional[bytes] = None
    ) -> None:
        """
        Load ECDSA private key.

        Args:
            key_data: Private key data (PEM format)
            password: Optional password for encrypted keys

        Raises:
            CryptoException: If key loading fails
        """
        try:
            self._key = serialization.load_pem_private_key(
                key_data, password=password, backend=default_backend()
            )
            if not isinstance(self._key, ec.EllipticCurvePrivateKey):
                raise CryptoException("Key is not ECDSA private key")

            # Verify curve type
            if not isinstance(self._key.curve, ec.SECP256R1):
                raise CryptoException("Key is not P-256 ECDSA key")
        except Exception as e:
            raise CryptoException(f"Failed to load ECDSA private key: {e}")

    def load_public_key(self, key_data: bytes) -> None:
        """
        Load ECDSA public key from SSH wire format.

        Args:
            key_data: Public key data in SSH wire format

        Raises:
            CryptoException: If key loading fails
        """
        try:
            # Parse SSH wire format
            offset = 0

            # Read algorithm name
            algo_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4
            algorithm = key_data[offset : offset + algo_len].decode()
            offset += algo_len

            if algorithm not in ["ecdsa-sha2-nistp256", "ecdsa"]:
                raise CryptoException(f"Expected ecdsa-sha2-nistp256, got {algorithm}")

            # Read curve name
            curve_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4
            curve_name = key_data[offset : offset + curve_len].decode()
            offset += curve_len

            if curve_name != "nistp256":
                raise CryptoException(f"Expected nistp256 curve, got {curve_name}")

            # Read public key point
            point_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4
            point_bytes = key_data[offset : offset + point_len]

            # Load public key from uncompressed point
            self._key = ec.EllipticCurvePublicKey.from_encoded_point(
                self.curve, point_bytes
            )
        except Exception as e:
            raise CryptoException(f"Failed to load ECDSA public key: {e}")

    def get_public_key_bytes(self) -> bytes:
        """
        Get ECDSA public key in SSH wire format.

        Returns:
            Public key bytes in SSH wire format

        Raises:
            CryptoException: If no key loaded
        """
        try:
            if self._key is None:
                raise CryptoException("No key loaded")

            # Get public key
            if isinstance(self._key, ec.EllipticCurvePrivateKey):
                public_key = self._key.public_key()
            else:
                public_key = self._key

            # Get uncompressed point
            point_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )

            # Format as SSH wire format
            algorithm = b"ecdsa-sha2-nistp256"
            curve_name = b"nistp256"

            result = struct.pack(">I", len(algorithm)) + algorithm
            result += struct.pack(">I", len(curve_name)) + curve_name
            result += struct.pack(">I", len(point_bytes)) + point_bytes
            return result
        except Exception as e:
            raise CryptoException(f"Failed to get ECDSA public key bytes: {e}")

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with ECDSA private key.

        Args:
            data: Data to sign

        Returns:
            Signature bytes in SSH format

        Raises:
            CryptoException: If signing fails or no private key
        """
        try:
            if not isinstance(self._key, ec.EllipticCurvePrivateKey):
                raise CryptoException("No ECDSA private key loaded")

            # Sign data with SHA-256
            signature = self._key.sign(data, ec.ECDSA(hashes.SHA256()))

            # Convert DER signature to SSH format (r, s values)
            r, s = decode_dss_signature(signature)

            # Create SSH signature blob with proper mpint encoding
            sig_blob = write_mpint(r) + write_mpint(s)

            # Format as SSH signature
            algorithm = b"ecdsa-sha2-nistp256"
            result = struct.pack(">I", len(algorithm)) + algorithm
            result += struct.pack(">I", len(sig_blob)) + sig_blob
            return result
        except Exception as e:
            raise CryptoException(f"ECDSA signing failed: {e}")

    @classmethod
    def generate(cls, *args: Any, **kwargs: Any) -> "ECDSAKey":
        """Generate a new ECDSA key pair (P-256)."""
        key = cls()
        key._key = ec.generate_private_key(key.curve, backend=default_backend())
        return key

    def save_to_file(self, filename: str, password: Optional[str] = None) -> None:
        """Save ECDSA private key to file."""
        try:
            if not isinstance(self._key, ec.EllipticCurvePrivateKey):
                raise CryptoException("No ECDSA private key loaded")

            encryption_algorithm = (
                serialization.BestAvailableEncryption(password.encode())
                if password
                else serialization.NoEncryption()
            )

            pem = self._key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=encryption_algorithm,
            )

            with open(filename, "wb") as f:
                f.write(pem)
        except Exception as e:
            raise CryptoException(f"Failed to save ECDSA key: {e}")

    def verify(self, signature: bytes, data: bytes) -> bool:
        """
        Verify ECDSA signature.

        Args:
            signature: Signature bytes in SSH format
            data: Original data that was signed

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if self._key is None:
                return False

            # Get public key
            if isinstance(self._key, ec.EllipticCurvePrivateKey):
                public_key = self._key.public_key()
            else:
                public_key = self._key

            # Parse SSH signature format
            offset = 0
            algo_len = struct.unpack(">I", signature[offset : offset + 4])[0]
            offset += 4
            algorithm = signature[offset : offset + algo_len].decode()
            offset += algo_len

            if algorithm != "ecdsa-sha2-nistp256":
                return False

            sig_len = struct.unpack(">I", signature[offset : offset + 4])[0]
            offset += 4
            sig_blob = signature[offset : offset + sig_len]

            # Parse r and s values
            blob_offset = 0
            r_len = struct.unpack(">I", sig_blob[blob_offset : blob_offset + 4])[0]
            blob_offset += 4
            r_bytes = sig_blob[blob_offset : blob_offset + r_len]
            blob_offset += r_len

            s_len = struct.unpack(">I", sig_blob[blob_offset : blob_offset + 4])[0]
            blob_offset += 4
            s_bytes = sig_blob[blob_offset : blob_offset + s_len]

            # Convert to integers and create DER signature
            r = int.from_bytes(r_bytes, "big")
            s = int.from_bytes(s_bytes, "big")
            der_signature = encode_dss_signature(r, s)

            # Verify signature
            public_key.verify(der_signature, data, ec.ECDSA(hashes.SHA256()))
            return True
        except:
            return False


class RSAKey(PKey):
    """
    RSA SSH key implementation.

    Implements rsa-sha2-256 key type using RSA with SHA-256.
    """

    @property
    def algorithm_name(self) -> str:
        """Get SSH algorithm name."""
        return "rsa-sha2-256"

    def load_private_key(
        self, key_data: bytes, password: Optional[bytes] = None
    ) -> None:
        """
        Load RSA private key.

        Args:
            key_data: Private key data (PEM format)
            password: Optional password for encrypted keys

        Raises:
            CryptoException: If key loading fails
        """
        try:
            self._key = serialization.load_pem_private_key(
                key_data, password=password, backend=default_backend()
            )
            if not isinstance(self._key, rsa.RSAPrivateKey):
                raise CryptoException("Key is not RSA private key")
        except Exception as e:
            raise CryptoException(f"Failed to load RSA private key: {e}")

    def load_public_key(self, key_data: bytes) -> None:
        """
        Load RSA public key from SSH wire format.

        Args:
            key_data: Public key data in SSH wire format

        Raises:
            CryptoException: If key loading fails
        """
        try:
            # Parse SSH wire format
            offset = 0

            # Read algorithm name
            algo_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4
            algorithm = key_data[offset : offset + algo_len].decode()
            offset += algo_len

            if algorithm not in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512", "rsa"]:
                raise CryptoException(f"Expected RSA algorithm, got {algorithm}")

            # Read public exponent
            e_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4
            e_bytes = key_data[offset : offset + e_len]
            offset += e_len
            e = int.from_bytes(e_bytes, "big")

            # Read modulus
            n_len = struct.unpack(">I", key_data[offset : offset + 4])[0]
            offset += 4
            n_bytes = key_data[offset : offset + n_len]
            n = int.from_bytes(n_bytes, "big")

            # Create RSA public key
            public_numbers = rsa.RSAPublicNumbers(e, n)
            self._key = public_numbers.public_key(backend=default_backend())
        except Exception as e:
            raise CryptoException(f"Failed to load RSA public key: {e}")

    def get_public_key_bytes(self) -> bytes:
        """
        Get RSA public key in SSH wire format.

        Returns:
            Public key bytes in SSH wire format

        Raises:
            CryptoException: If no key loaded
        """
        try:
            if self._key is None:
                raise CryptoException("No key loaded")

            # Get public key
            if isinstance(self._key, rsa.RSAPrivateKey):
                public_key = self._key.public_key()
            else:
                public_key = self._key

            # Get public numbers
            numbers = public_key.public_numbers()

            # Format as SSH wire format
            algorithm = b"ssh-rsa"
            result = struct.pack(">I", len(algorithm)) + algorithm
            result += write_mpint(numbers.e)
            result += write_mpint(numbers.n)
            return result
        except Exception as e:
            raise CryptoException(f"Failed to get RSA public key bytes: {e}")

    def sign(self, data: bytes) -> bytes:
        """
        Sign data with RSA private key using SHA-256.

        Args:
            data: Data to sign

        Returns:
            Signature bytes in SSH format

        Raises:
            CryptoException: If signing fails or no private key
        """
        try:
            if not isinstance(self._key, rsa.RSAPrivateKey):
                raise CryptoException("No RSA private key loaded")

            # Sign data with PKCS1v15 padding and SHA-256
            signature = self._key.sign(data, padding.PKCS1v15(), hashes.SHA256())

            # Format as SSH signature
            algorithm = b"rsa-sha2-256"
            result = struct.pack(">I", len(algorithm)) + algorithm
            result += struct.pack(">I", len(signature)) + signature
            return result
        except Exception as e:
            raise CryptoException(f"RSA signing failed: {e}")

    @classmethod
    def generate(cls, bits: int = 2048, *args: Any, **kwargs: Any) -> "RSAKey":
        """Generate a new RSA key pair."""
        key = cls()
        key._key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=bits,
            backend=default_backend()
        )
        return key

    def save_to_file(self, filename: str, password: Optional[str] = None) -> None:
        """Save RSA private key to file."""
        try:
            if not isinstance(self._key, rsa.RSAPrivateKey):
                raise CryptoException("No RSA private key loaded")

            encryption_algorithm = (
                serialization.BestAvailableEncryption(password.encode())
                if password
                else serialization.NoEncryption()
            )

            pem = self._key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=encryption_algorithm,
            )

            with open(filename, "wb") as f:
                f.write(pem)
        except Exception as e:
            raise CryptoException(f"Failed to save RSA key: {e}")

    def verify(self, signature: bytes, data: bytes) -> bool:
        """
        Verify RSA signature.

        Args:
            signature: Signature bytes in SSH format
            data: Original data that was signed

        Returns:
            True if signature is valid, False otherwise
        """
        try:
            if self._key is None:
                return False

            # Get public key
            if isinstance(self._key, rsa.RSAPrivateKey):
                public_key = self._key.public_key()
            else:
                public_key = self._key

            # Parse SSH signature format
            offset = 0
            algo_len = struct.unpack(">I", signature[offset : offset + 4])[0]
            offset += 4
            algorithm = signature[offset : offset + algo_len].decode()
            offset += algo_len

            if algorithm not in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]:
                return False

            sig_len = struct.unpack(">I", signature[offset : offset + 4])[0]
            offset += 4
            sig_bytes = signature[offset : offset + sig_len]

            # Choose hash algorithm based on signature type
            if algorithm == "rsa-sha2-512":
                hash_algo = hashes.SHA512()
            elif algorithm == "rsa-sha2-256":
                hash_algo = hashes.SHA256()
            else:
                # Default to SHA-1 for ssh-rsa
                hash_algo = hashes.SHA1()

            # Verify signature
            public_key.verify(sig_bytes, data, padding.PKCS1v15(), hash_algo)
            return True
        except:
            return False


def load_key_from_file(filename: str, password: Optional[str] = None) -> PKey:
    """
    Load SSH key from file.

    Args:
        filename: Path to key file
        password: Optional password for encrypted keys

    Returns:
        Loaded PKey instance

    Raises:
        CryptoException: If key loading fails
    """
    try:
        with open(filename, "rb") as f:
            key_data = f.read()

        password_bytes = password.encode() if password else None

        # Try different key types
        for key_class in [Ed25519Key, ECDSAKey, RSAKey]:
            try:
                key = key_class()
                key.load_private_key(key_data, password_bytes)
                return key
            except:
                continue

        raise CryptoException("Unable to load key - unsupported format or type")
    except Exception as e:
        raise CryptoException(f"Failed to load key from file: {e}")


def load_public_key_from_string(key_string: str) -> PKey:
    """
    Load SSH public key from string (OpenSSH format).

    Args:
        key_string: Public key string in OpenSSH format

    Returns:
        Loaded PKey instance

    Raises:
        CryptoException: If key loading fails
    """
    try:
        # Parse OpenSSH public key format: "algorithm base64_key comment"
        parts = key_string.strip().split()
        if len(parts) < 2:
            raise CryptoException("Invalid public key format")

        algorithm = parts[0]
        key_data = base64.b64decode(parts[1])

        # Determine key type and load
        if algorithm == "ssh-ed25519":
            key = Ed25519Key()
        elif algorithm == "ecdsa-sha2-nistp256":
            key = ECDSAKey()
        elif algorithm in ["ssh-rsa", "rsa-sha2-256", "rsa-sha2-512"]:
            key = RSAKey()
        else:
            raise CryptoException(f"Unsupported key algorithm: {algorithm}")

        key.load_public_key(key_data)
        return key
    except Exception as e:
        raise CryptoException(f"Failed to load public key from string: {e}")
