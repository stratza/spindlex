import pytest
from spindlex.crypto.kex import (
    Curve25519KeyExchange,
    DHGroup14KeyExchange,
    ECDHKeyExchange,
    KeyExchangeManager,
)
from spindlex.exceptions import CryptoException


class TestCurve25519KeyExchange:
    def test_key_exchange(self):
        kex1 = Curve25519KeyExchange()
        kex2 = Curve25519KeyExchange()

        pub1 = kex1.generate_keypair()
        pub2 = kex2.generate_keypair()

        assert len(pub1) == 32
        assert len(pub2) == 32

        secret1 = kex1.compute_shared_secret(pub2)
        secret2 = kex2.compute_shared_secret(pub1)

        assert secret1 == secret2
        assert len(secret1) == 32

    def test_invalid_key_length(self):
        kex = Curve25519KeyExchange()
        kex.generate_keypair()
        with pytest.raises(
            CryptoException, match="Invalid Curve25519 public key length"
        ):
            kex.compute_shared_secret(b"short")

    def test_missing_private_key(self):
        kex = Curve25519KeyExchange()
        with pytest.raises(CryptoException, match="Private key not generated"):
            kex.compute_shared_secret(b"a" * 32)


class TestECDHKeyExchange:
    def test_key_exchange(self):
        kex1 = ECDHKeyExchange()
        kex2 = ECDHKeyExchange()

        pub1 = kex1.generate_keypair()
        pub2 = kex2.generate_keypair()

        assert len(pub1) == 65
        assert pub1[0] == 0x04

        secret1 = kex1.compute_shared_secret(pub2)
        secret2 = kex2.compute_shared_secret(pub1)

        assert secret1 == secret2
        assert len(secret1) == 32

    def test_invalid_key_format(self):
        kex = ECDHKeyExchange()
        kex.generate_keypair()
        with pytest.raises(CryptoException, match="Invalid ECDH public key format"):
            # Wrong leading byte
            kex.compute_shared_secret(b"\x05" + b"a" * 64)


class TestDHGroup14KeyExchange:
    def test_key_exchange(self):
        kex1 = DHGroup14KeyExchange()
        kex2 = DHGroup14KeyExchange()

        pub1 = kex1.generate_keypair()
        pub2 = kex2.generate_keypair()

        assert len(pub1) == 256  # 2048 bits

        secret1 = kex1.compute_shared_secret(pub2)
        secret2 = kex2.compute_shared_secret(pub1)

        assert secret1 == secret2

    def test_invalid_dh_value(self):
        kex = DHGroup14KeyExchange()
        kex.generate_keypair()

        # Invalid peer public key (too small)
        with pytest.raises(CryptoException, match="Invalid DH public key value"):
            kex.compute_shared_secret(b"\x00" * 256)

        # Invalid peer public key (too large - greater than P)
        with pytest.raises(CryptoException, match="Invalid DH public key value"):
            kex.compute_shared_secret(b"\xff" * 256)


class TestKeyExchangeManager:
    def test_negotiate_algorithm(self):
        manager = KeyExchangeManager()

        # Simple match
        client = ["curve25519-sha256", "ecdh-sha2-nistp256"]
        server = ["ecdh-sha2-nistp256", "diffie-hellman-group14-sha256"]
        assert manager.negotiate_algorithm(client, server) == "ecdh-sha2-nistp256"

        # Preference order
        client = ["diffie-hellman-group14-sha256", "curve25519-sha256"]
        server = ["curve25519-sha256", "diffie-hellman-group14-sha256"]
        # Manager usually has its own preference order (see negotiate_algorithm implementation)
        # In current implementation, it iterates over its OWN preference list
        assert manager.negotiate_algorithm(client, server) == "curve25519-sha256"

    def test_no_compatible_algorithm(self):
        manager = KeyExchangeManager()
        with pytest.raises(
            CryptoException, match="No compatible key exchange algorithm found"
        ):
            manager.negotiate_algorithm(["none"], ["none"])

    def test_create_kex(self):
        manager = KeyExchangeManager()
        kex = manager.create_kex("curve25519-sha256")
        assert isinstance(kex, Curve25519KeyExchange)

        with pytest.raises(CryptoException, match="Unsupported key exchange algorithm"):
            manager.create_kex("unsupported")

    def test_get_hash_algorithm(self):
        manager = KeyExchangeManager()
        assert manager.get_hash_algorithm("curve25519-sha256") == "sha256"

        with pytest.raises(CryptoException, match="Unknown key exchange algorithm"):
            manager.get_hash_algorithm("unknown")
