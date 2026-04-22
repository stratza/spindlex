import pytest

from spindlex.crypto.backend import CryptographyBackend
from spindlex.exceptions import CryptoException


def test_backend_unsupported_hash():
    backend = CryptographyBackend()
    with pytest.raises(CryptoException, match="Unsupported hash algorithm"):
        backend.hash_data("md5", b"data")


def test_backend_unsupported_mac():
    backend = CryptographyBackend()
    with pytest.raises(CryptoException, match="Unsupported MAC algorithm"):
        backend.compute_mac("hmac-md5", b"key", b"data")


def test_backend_unsupported_cipher():
    backend = CryptographyBackend()
    with pytest.raises(CryptoException, match="Unsupported cipher algorithm"):
        backend.encrypt("unknown-cipher", b"k" * 16, b"iv" * 8, b"data")


def test_backend_unsupported_derive_key():
    backend = CryptographyBackend()
    with pytest.raises(CryptoException, match="Unsupported hash algorithm"):
        backend.derive_key("md5", b"k", b"h", b"id", b"X", 32)


def test_backend_chacha20_invalid_key_len():
    backend = CryptographyBackend()
    with pytest.raises(CryptoException, match="ChaCha20-Poly1305 key must be 64 bytes"):
        backend.encrypt("chacha20-poly1305@openssh.com", b"short", b"iv" * 4, b"data")


def test_backend_decrypt_short_data():
    backend = CryptographyBackend()
    with pytest.raises(CryptoException, match="Data too short for decryption"):
        backend.decrypt(
            "chacha20-poly1305@openssh.com", b"k" * 64, b"iv" * 4, b"too_short"
        )


def test_backend_create_cipher_unsupported():
    backend = CryptographyBackend()
    with pytest.raises(CryptoException, match="Streaming cipher not supported"):
        backend.create_cipher("unknown", b"k" * 16, b"iv" * 8)


def test_backend_decrypt_length_non_chacha():
    backend = CryptographyBackend()
    # Should return data as is for non-chacha
    data = b"1234"
    assert backend.decrypt_length("aes256-ctr", b"k" * 32, b"iv" * 16, data) == data
