
import pytest
from spindlex.crypto.backend import CryptographyBackend

def test_backend_hash():
    backend = CryptographyBackend()
    data = b"hello"
    h = backend.hash_data("sha256", data)
    assert len(h) == 32
    
    h1 = backend.hash_data("sha1", data)
    assert len(h1) == 20

def test_backend_random():
    backend = CryptographyBackend()
    r = backend.generate_random(16)
    assert len(r) == 16
    assert r != backend.generate_random(16)

def test_backend_key_derivation():
    backend = CryptographyBackend()
    K = b"shared_secret"
    H = b"exchange_hash"
    session_id = b"session_id"
    key = backend.derive_key("sha256", K, H, session_id, b"C", 32)
    assert len(key) == 32
    
    # Check that derivation is deterministic
    key2 = backend.derive_key("sha256", K, H, session_id, b"C", 32)
    assert key == key2
    
    # Check that different key type gives different key
    key3 = backend.derive_key("sha256", K, H, session_id, b"D", 32)
    assert key != key3

def test_backend_encryption_decryption():
    backend = CryptographyBackend()
    key = backend.generate_random(32)
    iv = backend.generate_random(16)
    data = b"hello world 1234" # 16 bytes
    
    encrypted = backend.encrypt("aes256-ctr", key, iv, data)
    assert encrypted != data
    
    decrypted = backend.decrypt("aes256-ctr", key, iv, encrypted)
    assert decrypted == data

def test_backend_hmac():
    backend = CryptographyBackend()
    key = backend.generate_random(32)
    data = b"some data"
    mac = backend.compute_mac("hmac-sha2-256", key, data)
    assert len(mac) == 32
    
    # CryptographyBackend doesn't have verify_hmac, but we can compare
    mac2 = backend.compute_mac("hmac-sha2-256", key, data)
    assert mac == mac2
