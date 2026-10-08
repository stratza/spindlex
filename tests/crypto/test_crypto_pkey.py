import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

from spindlex.crypto.pkey import ECDSAKey, Ed25519Key, PKey, RSAKey
from spindlex.exceptions import CryptoException


@pytest.fixture
def rsa_key():
    key = RSAKey()
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    key._key = private_key
    return key


@pytest.fixture
def ecdsa_key():
    key = ECDSAKey()
    private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
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
    # The key format is always "ssh-rsa" (RFC 8332 s3); the SHA-2 names only
    # identify signature algorithms.
    assert blob.startswith(b"\x00\x00\x00\x07ssh-rsa")


def test_rsa_public_blob_matches_openssh_encoding(rsa_key):
    import base64

    from cryptography.hazmat.primitives import serialization

    openssh_line = rsa_key._key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH
    )
    assert base64.b64decode(openssh_line.split()[1]) == rsa_key.get_public_key_bytes()
    assert rsa_key.get_openssh_string().startswith("ssh-rsa ")


def test_rsa_sign_with_explicit_algorithm_does_not_mutate_key(rsa_key):
    data = b"exchange hash"
    sig = rsa_key.sign(data, algorithm="rsa-sha2-512")
    assert sig[4:16] == b"rsa-sha2-512"
    assert rsa_key.algorithm_name == "rsa-sha2-256"
    assert rsa_key.verify(sig, data)


def test_rsa_openssh_private_key_round_trip(tmp_path, rsa_key):
    from spindlex.crypto.pkey import load_key_from_file

    path = tmp_path / "id_rsa"
    rsa_key.save_to_file(str(path))
    assert path.read_text().startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    loaded = load_key_from_file(str(path))
    assert loaded.get_public_key_bytes() == rsa_key.get_public_key_bytes()


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


def test_ecdsa_nist_curves():
    # Test generation and signing for all supported NIST curves
    for bits in [256, 384, 521]:
        key = ECDSAKey.generate(bits=bits)
        data = b"hello world"
        sig = key.sign(data)
        assert key.verify(sig, data) is True

        # Test public key bytes round-trip
        pub_bytes = key.get_public_key_bytes()
        key_reloaded = ECDSAKey()
        key_reloaded.load_public_key(pub_bytes)
        assert key_reloaded.curve_name == key.curve_name
        assert key_reloaded.verify(sig, data) is True


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


@pytest.mark.parametrize("bits", [256, 384, 521])
def test_load_public_key_from_string_all_ecdsa_curves(bits):
    from spindlex.crypto.pkey import ECDSAKey, load_public_key_from_string

    key = ECDSAKey.generate(bits=bits)
    loaded = load_public_key_from_string(key.get_openssh_string() + " comment")
    assert loaded.get_public_key_bytes() == key.get_public_key_bytes()


def test_pkeys_are_hashable_and_consistent_with_eq(rsa_key):
    from spindlex.crypto.pkey import PKey

    copy = PKey.from_string(rsa_key.get_public_key_bytes())
    assert copy == rsa_key
    assert hash(copy) == hash(rsa_key)
    assert len({copy, rsa_key}) == 1
