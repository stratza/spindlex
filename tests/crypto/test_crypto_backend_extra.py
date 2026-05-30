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


def test_backend_create_cipher_unsupported():
    backend = CryptographyBackend()
    with pytest.raises(CryptoException, match="Streaming cipher not supported"):
        backend.create_cipher("unknown", b"k" * 16, b"iv" * 8)


def test_backend_decrypt_length_passthrough():
    backend = CryptographyBackend()
    # Should return data as is for all ciphers now
    data = b"1234"
    assert backend.decrypt_length("aes256-ctr", b"k" * 32, b"iv" * 16, data) == data


def test_backend_hash_data_wraps_unexpected_exception():
    """hash_data wraps non-CryptoException errors in CryptoException."""
    from unittest.mock import MagicMock, patch

    from cryptography.hazmat.primitives import hashes

    backend = CryptographyBackend()
    mock_digest = MagicMock()
    mock_digest.update.side_effect = RuntimeError("digest exploded")
    with patch.object(hashes, "Hash", return_value=mock_digest):
        with pytest.raises(CryptoException, match="Hash operation failed"):
            backend.hash_data("sha256", b"data")
