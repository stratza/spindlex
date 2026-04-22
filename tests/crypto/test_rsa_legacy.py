import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

from spindlex.crypto.pkey import RSAKey
from spindlex.exceptions import CryptoException


@pytest.fixture
def rsa_key():
    key = RSAKey()
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    key._key = private_key
    return key


def test_rsa_sha1_disabled_by_default(rsa_key):
    # Set algorithm to legacy ssh-rsa
    rsa_key._algorithm_name = "ssh-rsa"
    data = b"hello world"

    # Signing should fail
    with pytest.raises(
        CryptoException, match="RSA with SHA-1 \(ssh-rsa\) is disabled by default"
    ):
        rsa_key.sign(data)


def test_rsa_sha1_enabled_opt_in(rsa_key):
    # Set algorithm to legacy ssh-rsa
    rsa_key._algorithm_name = "ssh-rsa"
    rsa_key.allow_sha1 = True
    data = b"hello world"

    # Signing should succeed but emit a DeprecationWarning
    with pytest.warns(DeprecationWarning, match="ssh-rsa"):
        signature = rsa_key.sign(data)
    assert signature.startswith(b"\x00\x00\x00\x07ssh-rsa")

    # Verification should succeed (also deprecated)
    with pytest.warns(DeprecationWarning, match="ssh-rsa"):
        assert rsa_key.verify(signature, data)


def test_rsa_sha1_verify_disabled_by_default(rsa_key):
    # Enable SHA-1 just to create a signature
    rsa_key._algorithm_name = "ssh-rsa"
    rsa_key.allow_sha1 = True
    data = b"hello world"
    with pytest.warns(DeprecationWarning, match="ssh-rsa"):
        signature = rsa_key.sign(data)

    # Disable again
    rsa_key.allow_sha1 = False

    # Verification should return False by default for ssh-rsa (no warning —
    # the algorithm is rejected before the SHA-1 code path is reached).
    assert not rsa_key.verify(signature, data)


def test_rsa_sha2_undisturbed(rsa_key):
    # Default is rsa-sha2-256
    data = b"hello world"
    signature = rsa_key.sign(data)
    assert rsa_key.verify(signature, data)
    assert signature.startswith(b"\x00\x00\x00\x0crsa-sha2-256")
