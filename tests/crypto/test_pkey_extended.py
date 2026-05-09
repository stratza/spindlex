"""
Extended coverage tests for spindlex/crypto/pkey.py.
Targets the remaining ~68 missed lines identified by coverage.
"""

import struct

import pytest

from spindlex.crypto.pkey import (
    ECDSAKey,
    Ed25519Key,
    PKey,
    RSAKey,
    load_key_from_file,
    load_public_key_from_string,
)
from spindlex.exceptions import CryptoException

# ---------------------------------------------------------------------------
# PKey.__eq__ exception path (lines 170-171)
# ---------------------------------------------------------------------------


class TestPKeyEqualityException:
    def test_eq_raises_returns_false(self):
        """When get_public_key_bytes raises, __eq__ returns False."""
        k1 = Ed25519Key.generate()
        k2 = Ed25519Key()  # no key loaded — get_public_key_bytes will raise
        # k1 == k2 → k2.get_public_key_bytes() raises → returns False
        assert k1 != k2


# ---------------------------------------------------------------------------
# PKey.from_string non-CryptoException path (line 212)
# ---------------------------------------------------------------------------


class TestPKeyFromStringNonCrypto:
    def test_from_string_non_crypto_exception_wrapped(self):
        """A non-CryptoException is wrapped in CryptoException."""
        # Pass garbage bytes that can't be parsed
        with pytest.raises(CryptoException):
            PKey.from_string(b"\x00\x00\x00\x04test_garbage")


# ---------------------------------------------------------------------------
# Ed25519Key.load_public_key wrong length (line 370)
# ---------------------------------------------------------------------------


class TestEd25519LoadPublicKeyWrongLength:
    def test_load_public_key_wrong_length_raises(self):
        """Ed25519 public key bytes that are not 32 bytes long should fail."""
        # Build a valid-looking header but with 31-byte key body
        algo = b"ssh-ed25519"
        pub_bytes = b"\x00" * 31  # wrong length
        blob = (
            struct.pack(">I", len(algo))
            + algo
            + struct.pack(">I", len(pub_bytes))
            + pub_bytes
        )
        key = Ed25519Key()
        with pytest.raises(CryptoException):
            key.load_public_key(blob)


# ---------------------------------------------------------------------------
# Ed25519Key.verify wrong algorithm (line 500)
# ---------------------------------------------------------------------------


class TestEd25519VerifyWrongAlgorithm:
    def test_verify_wrong_algorithm_returns_false(self):
        """If the signature blob says 'ecdsa-...', verify returns False."""
        key = Ed25519Key.generate()
        # Build a signature blob with the wrong algorithm
        wrong_algo = b"ecdsa-sha2-nistp256"
        sig_bytes = b"\x00" * 64
        sig_blob = (
            struct.pack(">I", len(wrong_algo))
            + wrong_algo
            + struct.pack(">I", len(sig_bytes))
            + sig_bytes
        )
        assert not key.verify(sig_blob, b"data")


# ---------------------------------------------------------------------------
# ECDSAKey.load_private_key paths (lines 546, 554, 558-560)
# ---------------------------------------------------------------------------


class TestECDSALoadPrivateKey:
    def test_load_openssh_format(self, tmp_path):
        """Cover the 'BEGIN OPENSSH PRIVATE KEY' branch (line 546)."""
        key = ECDSAKey.generate()
        # Save as OpenSSH PEM which has 'BEGIN OPENSSH PRIVATE KEY' header
        from cryptography.hazmat.primitives import serialization

        pem = key._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key2 = ECDSAKey()
        key2.load_private_key(pem)
        assert key2._key is not None

    def test_load_wrong_key_type_raises(self):
        """Non-EC key data raises CryptoException (line 554)."""
        # RSA key is not an EllipticCurvePrivateKey
        rsa_key = RSAKey.generate(bits=2048)
        from cryptography.hazmat.primitives import serialization

        pem = rsa_key._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key = ECDSAKey()
        with pytest.raises(CryptoException):
            key.load_private_key(pem)


# ---------------------------------------------------------------------------
# ECDSAKey.load_public_key wrong algorithm / curve (lines 583, 592, 603-604)
# ---------------------------------------------------------------------------


class TestECDSALoadPublicKey:
    def test_load_wrong_algorithm_raises(self):
        """Unrecognized algorithm string raises CryptoException (line 583)."""
        algo = b"ssh-ed25519"
        blob = struct.pack(">I", len(algo)) + algo + b"\x00" * 20
        key = ECDSAKey()
        with pytest.raises(CryptoException):
            key.load_public_key(blob)

    def test_load_wrong_curve_name_raises(self):
        """nistp521 curve name instead of nistp256 raises CryptoException (line 592)."""
        algo = b"ecdsa-sha2-nistp256"
        curve = b"nistp521"
        point = b"\x04" + b"\x00" * 64  # fake uncompressed point
        blob = (
            struct.pack(">I", len(algo))
            + algo
            + struct.pack(">I", len(curve))
            + curve
            + struct.pack(">I", len(point))
            + point
        )
        key = ECDSAKey()
        with pytest.raises(CryptoException):
            key.load_public_key(blob)


# ---------------------------------------------------------------------------
# ECDSAKey.get_public_key_bytes no key (line 618)
# ---------------------------------------------------------------------------


class TestECDSAGetPublicKeyBytesNoKey:
    def test_no_key_raises(self):
        key = ECDSAKey()
        with pytest.raises(CryptoException, match="No key loaded"):
            key.get_public_key_bytes()


# ---------------------------------------------------------------------------
# ECDSAKey.sign no private key (line 658)
# ---------------------------------------------------------------------------


class TestECDSASignNoKey:
    def test_sign_with_public_key_only_raises(self):
        """Sign with public key only raises CryptoException (line 658)."""
        priv = ECDSAKey.generate()
        pub = priv.get_public_key()
        with pytest.raises(CryptoException, match="No ECDSA private key"):
            pub.sign(b"data")


# ---------------------------------------------------------------------------
# ECDSAKey.save_to_file no private key (line 690)
# ---------------------------------------------------------------------------


class TestECDSASaveNoKey:
    def test_save_public_key_only_raises(self, tmp_path):
        priv = ECDSAKey.generate()
        pub = priv.get_public_key()
        with pytest.raises(CryptoException):
            pub.save_to_file(str(tmp_path / "key.pem"))


# ---------------------------------------------------------------------------
# ECDSAKey.verify wrong algorithm (line 738)
# ---------------------------------------------------------------------------


class TestECDSAVerifyWrongAlgorithm:
    def test_verify_wrong_algorithm_returns_false(self):
        key = ECDSAKey.generate()
        wrong_algo = b"ssh-ed25519"
        sig_bytes = b"\x00" * 64
        sig_blob = (
            struct.pack(">I", len(wrong_algo))
            + wrong_algo
            + struct.pack(">I", len(sig_bytes))
            + sig_bytes
        )
        assert not key.verify(sig_blob, b"data")


# ---------------------------------------------------------------------------
# RSAKey.load_private_key errors (lines 794-801)
# ---------------------------------------------------------------------------


class TestRSALoadPrivateKey:
    def test_load_non_rsa_key_raises(self):
        """Loading an Ed25519 key into RSAKey raises CryptoException (line 798-799)."""
        ed_key = Ed25519Key.generate()
        from cryptography.hazmat.primitives import serialization

        pem = ed_key._key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key = RSAKey()
        with pytest.raises(CryptoException):
            key.load_private_key(pem)


# ---------------------------------------------------------------------------
# RSAKey.load_public_key wrong algorithm (line 824)
# ---------------------------------------------------------------------------


class TestRSALoadPublicKeyWrongAlgorithm:
    def test_wrong_algorithm_raises(self):
        algo = b"ssh-ed25519"
        blob = struct.pack(">I", len(algo)) + algo + b"\x00" * 20
        key = RSAKey()
        with pytest.raises(CryptoException, match="Expected RSA algorithm"):
            key.load_public_key(blob)


# ---------------------------------------------------------------------------
# RSAKey.get_public_key_bytes no key (line 861)
# ---------------------------------------------------------------------------


class TestRSAGetPublicKeyBytesNoKey:
    def test_no_key_raises(self):
        key = RSAKey()
        with pytest.raises(CryptoException, match="No key loaded"):
            key.get_public_key_bytes()


# ---------------------------------------------------------------------------
# RSAKey.sign paths (lines 897, 903)
# ---------------------------------------------------------------------------


class TestRSASign:
    def test_sign_no_private_key_raises(self):
        """Sign with public-key-only raises CryptoException (line 897)."""
        priv = RSAKey.generate(bits=2048)
        pub = priv.get_public_key()
        with pytest.raises(CryptoException, match="No RSA private key"):
            pub.sign(b"data")

    def test_sign_sha512(self):
        """Cover the SHA-512 branch (line 903)."""
        key = RSAKey.generate(bits=2048)
        key._algorithm_name = "rsa-sha2-512"
        sig = key.sign(b"test data")
        assert sig is not None
        assert b"rsa-sha2-512" in sig


# ---------------------------------------------------------------------------
# RSAKey.save_to_file no private key (line 948)
# ---------------------------------------------------------------------------


class TestRSASaveNoKey:
    def test_save_public_key_only_raises(self, tmp_path):
        priv = RSAKey.generate(bits=2048)
        pub = priv.get_public_key()
        with pytest.raises(CryptoException):
            pub.save_to_file(str(tmp_path / "key.pem"))


# ---------------------------------------------------------------------------
# RSAKey.verify paths (lines 986, 1002, 1017)
# ---------------------------------------------------------------------------


class TestRSAVerify:
    def test_verify_no_key_returns_false(self):
        """Line 986: _key is None → returns False."""
        key = RSAKey()
        # Build a fake signature
        algo = b"rsa-sha2-256"
        sig_bytes = b"\x00" * 64
        sig = (
            struct.pack(">I", len(algo))
            + algo
            + struct.pack(">I", len(sig_bytes))
            + sig_bytes
        )
        assert not key.verify(sig, b"data")

    def test_verify_sha512(self):
        """Cover the rsa-sha2-512 verify branch (line 1002)."""
        key = RSAKey.generate(bits=2048)
        key._algorithm_name = "rsa-sha2-512"
        sig = key.sign(b"test data")
        assert key.verify(sig, b"test data")

    def test_verify_unknown_algorithm_returns_false(self):
        """Line 1017: unknown algorithm string → returns False."""
        key = RSAKey.generate(bits=2048)
        algo = b"unknown-algo"
        sig_bytes = b"\x00" * 64
        sig = (
            struct.pack(">I", len(algo))
            + algo
            + struct.pack(">I", len(sig_bytes))
            + sig_bytes
        )
        assert not key.verify(sig, b"data")


# ---------------------------------------------------------------------------
# load_key_from_file all formats fail (lines 1057-1064)
# ---------------------------------------------------------------------------


class TestLoadKeyFromFile:
    def test_unsupported_format_raises(self, tmp_path):
        """When no key type matches, CryptoException is raised (lines 1057-1063)."""
        bad_key_file = tmp_path / "bad_key.pem"
        bad_key_file.write_bytes(
            b"-----BEGIN GARBAGE-----\nZmFrZQ==\n-----END GARBAGE-----\n"
        )
        with pytest.raises(CryptoException, match="Unable to load key"):
            load_key_from_file(str(bad_key_file))

    def test_file_not_found_raises(self, tmp_path):
        """OS error when opening file is wrapped in CryptoException (line 1064)."""
        with pytest.raises(CryptoException):
            load_key_from_file(str(tmp_path / "nonexistent_key.pem"))


# ---------------------------------------------------------------------------
# load_public_key_from_string (lines 1080-1103)
# ---------------------------------------------------------------------------


class TestLoadPublicKeyFromString:
    def test_ed25519_from_string(self):
        key = Ed25519Key.generate()
        openssh_str = key.get_openssh_string()
        loaded = load_public_key_from_string(openssh_str)
        assert isinstance(loaded, Ed25519Key)

    def test_ecdsa_from_string(self):
        key = ECDSAKey.generate()
        openssh_str = key.get_openssh_string()
        loaded = load_public_key_from_string(openssh_str)
        assert isinstance(loaded, ECDSAKey)

    def test_rsa_from_string(self):
        key = RSAKey.generate(bits=2048)
        openssh_str = key.get_openssh_string()
        loaded = load_public_key_from_string(openssh_str)
        assert isinstance(loaded, RSAKey)

    def test_ssh_rsa_from_string(self):
        """Cover the 'ssh-rsa' branch in load_public_key_from_string."""
        key = RSAKey.generate(bits=2048)
        # Build a manually crafted ssh-rsa formatted key
        import base64

        # The openssh string already uses rsa-sha2-256 prefix
        # Build an ssh-rsa prefixed string
        algo_override = b"ssh-rsa"
        # Get the e and n from the actual key
        public_key = (
            key._key.public_key() if hasattr(key._key, "public_key") else key._key
        )
        nums = public_key.public_numbers()
        from spindlex.protocol.utils import write_mpint

        raw = struct.pack(">I", len(algo_override)) + algo_override
        raw += write_mpint(nums.e)
        raw += write_mpint(nums.n)
        key_b64 = base64.b64encode(raw).decode()
        loaded = load_public_key_from_string(f"ssh-rsa {key_b64}")
        assert isinstance(loaded, RSAKey)

    def test_invalid_format_raises(self):
        """Only one part → CryptoException (line 1084)."""
        with pytest.raises(CryptoException):
            load_public_key_from_string("just-one-part")

    def test_unsupported_algorithm_raises(self):
        """Unsupported algo → CryptoException (line 1098)."""
        import base64

        with pytest.raises(CryptoException):
            load_public_key_from_string(
                f"dss-key {base64.b64encode(b'fakedata').decode()}"
            )
