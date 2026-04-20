"""
Additional coverage tests for crypto/pkey.py.
Covers: load_private_key, save_to_file, from_string dispatch, get_fingerprint,
get_openssh_string, get_public_key, PKey.generate factory, equality,
sign/verify round-trips for all key types.
"""
import io
import os
import struct
import tempfile

import pytest

from spindlex.crypto.pkey import ECDSAKey, Ed25519Key, PKey, RSAKey
from spindlex.exceptions import CryptoException


# ---------------------------------------------------------------------------
# PKey factory / from_string
# ---------------------------------------------------------------------------

class TestPKeyFactory:
    def test_generate_ed25519(self):
        key = PKey.generate("ed25519")
        assert isinstance(key, Ed25519Key)

    def test_generate_rsa(self):
        key = PKey.generate("rsa", bits=2048)
        assert isinstance(key, RSAKey)

    def test_generate_ecdsa(self):
        key = PKey.generate("ecdsa")
        assert isinstance(key, ECDSAKey)

    def test_generate_unsupported_raises(self):
        with pytest.raises(CryptoException, match="Unsupported key type"):
            PKey.generate("dsa")

    def test_from_string_ed25519(self):
        priv = Ed25519Key.generate()
        pub_bytes = priv.get_public_key_bytes()
        loaded = PKey.from_string(pub_bytes)
        assert isinstance(loaded, Ed25519Key)

    def test_from_string_ecdsa(self):
        priv = ECDSAKey.generate()
        pub_bytes = priv.get_public_key_bytes()
        loaded = PKey.from_string(pub_bytes)
        assert isinstance(loaded, ECDSAKey)

    def test_from_string_rsa(self):
        priv = RSAKey.generate(bits=2048)
        pub_bytes = priv.get_public_key_bytes()
        loaded = PKey.from_string(pub_bytes)
        assert isinstance(loaded, RSAKey)

    def test_from_string_unsupported_raises(self):
        # Build a fake blob with unsupported algorithm
        algo = b"unsupported-algo"
        blob = struct.pack(">I", len(algo)) + algo
        with pytest.raises(CryptoException):
            PKey.from_string(blob)


class TestPKeyEquality:
    def test_same_key_equal(self):
        key = Ed25519Key.generate()
        pub = key.get_public_key()
        assert key == pub

    def test_different_keys_not_equal(self):
        k1 = Ed25519Key.generate()
        k2 = Ed25519Key.generate()
        assert k1 != k2

    def test_different_type_not_equal(self):
        k = Ed25519Key.generate()
        assert k != "not a key"

    def test_equality_different_types(self):
        ed = Ed25519Key.generate()
        rsa = RSAKey.generate(bits=2048)
        assert ed != rsa


class TestPKeyFingerprint:
    def test_sha256_fingerprint(self):
        key = Ed25519Key.generate()
        fp = key.get_fingerprint("sha256")
        assert fp.startswith("SHA256:")

    def test_md5_fingerprint(self):
        key = Ed25519Key.generate()
        fp = key.get_fingerprint("md5")
        assert fp.startswith("MD5:")

    def test_unsupported_hash_raises(self):
        key = Ed25519Key.generate()
        with pytest.raises(CryptoException, match="Unsupported hash algorithm"):
            key.get_fingerprint("sha1")


class TestPKeyOpenSSHString:
    def test_ed25519_openssh_string(self):
        key = Ed25519Key.generate()
        s = key.get_openssh_string()
        assert s.startswith("ssh-ed25519 ")

    def test_ecdsa_openssh_string(self):
        key = ECDSAKey.generate()
        s = key.get_openssh_string()
        assert "ecdsa" in s.lower()

    def test_rsa_openssh_string(self):
        key = RSAKey.generate(bits=2048)
        s = key.get_openssh_string()
        assert "rsa" in s.lower()


class TestPKeyGetPublicKey:
    def test_get_public_key_ed25519(self):
        priv = Ed25519Key.generate()
        pub = priv.get_public_key()
        assert pub is not priv
        assert priv == pub  # same public key bytes


# ---------------------------------------------------------------------------
# Ed25519Key
# ---------------------------------------------------------------------------

class TestEd25519Key:
    def test_sign_verify_roundtrip(self):
        key = Ed25519Key.generate()
        data = b"test data to sign"
        sig = key.sign(data)
        assert key.verify(sig, data)

    def test_verify_wrong_data_returns_false(self):
        key = Ed25519Key.generate()
        sig = key.sign(b"original data")
        assert not key.verify(sig, b"tampered data")

    def test_sign_without_private_key_raises(self):
        priv = Ed25519Key.generate()
        pub = priv.get_public_key()
        with pytest.raises(CryptoException, match="No Ed25519 private key"):
            pub.sign(b"data")

    def test_verify_no_key_returns_false(self):
        key = Ed25519Key()
        result = key.verify(b"\x00" * 80, b"data")
        assert not result

    def test_load_private_key_pem(self, tmp_path):
        key = Ed25519Key.generate()
        filename = str(tmp_path / "id_ed25519")
        key.save_to_file(filename)
        pem_data = open(filename, "rb").read()

        key2 = Ed25519Key()
        key2.load_private_key(pem_data)
        assert key2._key is not None

    def test_save_and_reload(self, tmp_path):
        key = Ed25519Key.generate()
        filename = str(tmp_path / "id_ed25519_save")
        key.save_to_file(filename)

        key2 = PKey.from_private_key_file(filename)
        assert isinstance(key2, Ed25519Key)
        assert key == key2

    def test_save_without_private_key_raises(self, tmp_path):
        priv = Ed25519Key.generate()
        pub = priv.get_public_key()
        with pytest.raises(CryptoException):
            pub.save_to_file(str(tmp_path / "pub_only"))

    def test_algorithm_name(self):
        key = Ed25519Key.generate()
        assert key.algorithm_name == "ssh-ed25519"
        assert key.get_ssh_type() == "ssh-ed25519"
        assert key.get_name() == "ssh-ed25519"

    def test_get_public_key_bytes_no_key_raises(self):
        key = Ed25519Key()
        with pytest.raises(CryptoException, match="No key loaded"):
            key.get_public_key_bytes()

    def test_load_public_key_wrong_algo_raises(self):
        algo = b"ecdsa-sha2-nistp256"
        blob = struct.pack(">I", len(algo)) + algo + b"\x00" * 10
        key = Ed25519Key()
        with pytest.raises(CryptoException):
            key.load_public_key(blob)


# ---------------------------------------------------------------------------
# ECDSAKey
# ---------------------------------------------------------------------------

class TestECDSAKey:
    def test_sign_verify_roundtrip(self):
        key = ECDSAKey.generate()
        data = b"ecdsa test data"
        sig = key.sign(data)
        assert key.verify(sig, data)

    def test_verify_wrong_data_returns_false(self):
        key = ECDSAKey.generate()
        sig = key.sign(b"original")
        assert not key.verify(sig, b"tampered")

    def test_algorithm_name(self):
        key = ECDSAKey.generate()
        assert "ecdsa" in key.algorithm_name.lower()

    def test_get_public_key_bytes_format(self):
        key = ECDSAKey.generate()
        pub_bytes = key.get_public_key_bytes()
        # First 4 bytes are length of algorithm name
        algo_len = struct.unpack(">I", pub_bytes[:4])[0]
        algo = pub_bytes[4:4+algo_len].decode()
        assert "ecdsa" in algo

    def test_save_and_reload(self, tmp_path):
        key = ECDSAKey.generate()
        filename = str(tmp_path / "id_ecdsa")
        key.save_to_file(filename)
        key2 = PKey.from_private_key_file(filename)
        assert isinstance(key2, ECDSAKey)
        assert key == key2

    def test_load_private_key_from_pem(self, tmp_path):
        key = ECDSAKey.generate()
        filename = str(tmp_path / "id_ecdsa_pem")
        key.save_to_file(filename)
        pem_data = open(filename, "rb").read()

        key2 = ECDSAKey()
        key2.load_private_key(pem_data)
        assert key2._key is not None

    def test_verify_no_key_returns_false(self):
        key = ECDSAKey()
        assert not key.verify(b"\x00" * 80, b"data")


# ---------------------------------------------------------------------------
# RSAKey
# ---------------------------------------------------------------------------

class TestRSAKey:
    def test_sign_verify_roundtrip(self):
        key = RSAKey.generate(bits=2048)
        data = b"rsa test data"
        sig = key.sign(data)
        assert key.verify(sig, data)

    def test_verify_wrong_data_returns_false(self):
        key = RSAKey.generate(bits=2048)
        sig = key.sign(b"original")
        assert not key.verify(sig, b"tampered")

    def test_algorithm_name(self):
        key = RSAKey.generate(bits=2048)
        assert "rsa" in key.algorithm_name.lower()

    def test_get_public_key_bytes_format(self):
        key = RSAKey.generate(bits=2048)
        pub_bytes = key.get_public_key_bytes()
        algo_len = struct.unpack(">I", pub_bytes[:4])[0]
        algo = pub_bytes[4:4+algo_len].decode()
        assert "rsa" in algo

    def test_save_creates_file(self, tmp_path):
        key = RSAKey.generate(bits=2048)
        filename = str(tmp_path / "id_rsa_save")
        key.save_to_file(filename)
        from pathlib import Path
        assert Path(filename).exists()
        assert b"OPENSSH PRIVATE KEY" in Path(filename).read_bytes()

    def test_verify_no_key_returns_false(self):
        key = RSAKey()
        assert not key.verify(b"\x00" * 80, b"data")

    def test_rsa_3072_bits(self):
        key = RSAKey.generate(bits=3072)
        data = b"rsa 3072 test"
        sig = key.sign(data)
        assert key.verify(sig, data)
