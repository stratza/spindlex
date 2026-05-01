import pytest

from spindlex.crypto.ciphers import CipherSuite
from spindlex.exceptions import CryptoException


def test_cipher_suite_negotiation():
    suite = CipherSuite()
    client_algs = {
        "kex_algorithms": ["curve25519-sha256", "diffie-hellman-group14-sha256"],
        "server_host_key_algorithms": ["ssh-ed25519", "rsa-sha2-256"],
        "encryption_algorithms_client_to_server": ["aes256-ctr"],
        "encryption_algorithms_server_to_client": ["aes256-ctr"],
        "mac_algorithms_client_to_server": ["hmac-sha2-256"],
        "mac_algorithms_server_to_client": ["hmac-sha2-256"],
    }
    server_algs = {
        "kex_algorithms": ["diffie-hellman-group14-sha256"],
        "server_host_key_algorithms": ["rsa-sha2-256"],
        "encryption_algorithms_client_to_server": ["aes256-ctr"],
        "encryption_algorithms_server_to_client": ["aes256-ctr"],
        "mac_algorithms_client_to_server": ["hmac-sha2-256"],
        "mac_algorithms_server_to_client": ["hmac-sha2-256"],
    }

    negotiated = suite.negotiate_algorithms(client_algs, server_algs)
    assert negotiated["kex"] == "diffie-hellman-group14-sha256"
    assert negotiated["server_host_key"] == "rsa-sha2-256"


def test_cipher_info():
    suite = CipherSuite()
    info = suite.get_cipher_info("aes256-ctr")
    assert info["key_len"] == 32


def test_mac_info():
    suite = CipherSuite()
    info = suite.get_mac_info("hmac-sha2-256")
    assert info["key_len"] == 32
    assert info["digest_len"] == 32


def test_unsupported_cipher():
    suite = CipherSuite()
    with pytest.raises(CryptoException):
        suite.get_cipher_info("unknown-cipher")
