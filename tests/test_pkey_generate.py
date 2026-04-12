import pytest
from spindlex.crypto.pkey import PKey, Ed25519Key, RSAKey, ECDSAKey
from spindlex.exceptions import CryptoException

def test_pkey_generate_ed25519():
    key = PKey.generate('ed25519')
    assert isinstance(key, Ed25519Key)
    assert key.algorithm_name == 'ssh-ed25519'
    assert key._key is not None

def test_pkey_generate_rsa():
    key = PKey.generate('rsa', bits=2048)
    assert isinstance(key, RSAKey)
    assert key.algorithm_name == 'rsa-sha2-256'
    assert key._key.key_size == 2048

def test_pkey_generate_ecdsa():
    key = PKey.generate('ecdsa')
    assert isinstance(key, ECDSAKey)
    assert key.algorithm_name == 'ecdsa-sha2-nistp256'
    assert key.curve_name == 'nistp256'

def test_pkey_generate_invalid():
    with pytest.raises(CryptoException, match="Unsupported key type"):
        PKey.generate('invalid-type')

def test_subclass_generate_still_works():
    key = Ed25519Key.generate()
    assert isinstance(key, Ed25519Key)
    
    key_rsa = RSAKey.generate(bits=1024)
    assert isinstance(key_rsa, RSAKey)
    assert key_rsa._key.key_size == 1024
