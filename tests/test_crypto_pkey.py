
import pytest
import os
from spindlex.crypto.pkey import RSAKey, ECDSAKey, Ed25519Key, PKey
from spindlex.exceptions import CryptoException
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519
from cryptography.hazmat.backends import default_backend

@pytest.fixture
def rsa_key():
    key = RSAKey()
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    key._key = private_key
    return key

@pytest.fixture
def ecdsa_key():
    key = ECDSAKey()
    private_key = ec.generate_private_key(
        ec.SECP256R1(),
        backend=default_backend()
    )
    key._key = private_key
    return key

@pytest.fixture
def ed25519_key():
    key = Ed25519Key()
    private_key = ed25519.Ed25519PrivateKey.generate()
    key._key = private_key
    return key

def test_rsa_key_properties(rsa_key):
    assert rsa_key.algorithm_name == "rsa-sha2-256"
    blob = rsa_key.get_public_key_bytes()
    assert blob.startswith(b"\x00\x00\x00\x07ssh-rsa")

def test_rsa_sign_verify(rsa_key):
    data = b"hello world"
    signature = rsa_key.sign(data)
    assert rsa_key.verify(signature, data)
    assert not rsa_key.verify(signature, b"wrong data")

def test_ecdsa_key_properties(ecdsa_key):
    assert ecdsa_key.algorithm_name == "ecdsa-sha2-nistp256"
    blob = ecdsa_key.get_public_key_bytes()
    assert b"ecdsa-sha2-nistp256" in blob

def test_ecdsa_sign_verify(ecdsa_key):
    data = b"hello world"
    signature = ecdsa_key.sign(data)
    assert ecdsa_key.verify(signature, data)
    assert not ecdsa_key.verify(signature, b"wrong data")

def test_ed25519_key_properties(ed25519_key):
    assert ed25519_key.algorithm_name == "ssh-ed25519"
    blob = ed25519_key.get_public_key_bytes()
    assert blob.startswith(b"\x00\x00\x00\x0bssh-ed25519")

def test_ed25519_sign_verify(ed25519_key):
    data = b"hello world"
    signature = ed25519_key.sign(data)
    assert ed25519_key.verify(signature, data)
    assert not ed25519_key.verify(signature, b"wrong data")

def test_pkey_from_string(rsa_key):
    blob = rsa_key.get_public_key_bytes()
    new_key = PKey.from_string(blob)
    assert isinstance(new_key, RSAKey)
    assert new_key.get_public_key_bytes() == blob

def test_fingerprint(rsa_key):
    fp = rsa_key.get_fingerprint("sha256")
    assert fp.startswith("SHA256:")
    fp_md5 = rsa_key.get_fingerprint("md5")
    assert fp_md5.startswith("MD5:")

def test_unsupported_key_type():
    with pytest.raises(CryptoException):
        PKey.from_string(b"\x00\x00\x00\x07unknown")
