"""
Additional unit tests for spindlex/transport/kex.py

Covers the crypto algorithm implementations (DH, ECDH, Curve25519) and
key-derivation helpers using mocks — no real SSH connections.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import CryptoException
from spindlex.protocol.utils import write_mpint, write_string
from spindlex.transport.kex import KeyExchange

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_kex() -> tuple[KeyExchange, MagicMock]:
    """Return a KeyExchange with a fully-mocked transport (client mode)."""
    transport = MagicMock()
    transport._send_message = MagicMock()
    transport._expect_message = MagicMock()
    transport.session_id = b"\x00" * 32
    transport._client_version = "SSH-2.0-SpindleX_Test"
    transport._server_version = "SSH-2.0-MockServer"
    transport._server_mode = False
    transport._peer_kexinit = None
    transport._client_kexinit_blob = b"\x00" * 16
    transport._logger = MagicMock()
    transport._server_key = None
    transport._server_host_key_blob = None
    kex = KeyExchange(transport)
    return kex, transport


def _make_reply_msg(server_host_key: bytes, server_pub: bytes, sig: bytes) -> MagicMock:
    """Build a fake reply Message whose ._data encodes three strings."""
    data = write_string(server_host_key) + write_string(server_pub) + write_string(sig)
    msg = MagicMock()
    msg._data = data
    return msg


def _make_dh_reply_msg(
    server_host_key: bytes, server_f_int: int, sig: bytes
) -> MagicMock:
    """Build a fake KEXDH_REPLY whose ._data encodes host_key, mpint(f), sig."""
    data = write_string(server_host_key) + write_mpint(server_f_int) + write_string(sig)
    msg = MagicMock()
    msg._data = data
    return msg


def _kex_with_kexinit_blobs(kex: KeyExchange) -> None:
    """Populate KEXINIT blobs so exchange-hash methods don't fail."""
    kex._client_kexinit = b"\x01" * 16
    kex._server_kexinit = b"\x02" * 16


# ---------------------------------------------------------------------------
# _perform_dh_group14_sha256 (client side) — lines 253-325
# ---------------------------------------------------------------------------


class TestDhGroup14Sha256Client:
    """Mock out the cryptography.hazmat.primitives.asymmetric.dh calls."""

    def _build_mock_dh(self, pub_y: int = 0x1234ABCD):
        """Return a mock DH private key that reports pub_y as its public number."""
        mock_priv = MagicMock()
        mock_pub_numbers = MagicMock()
        mock_pub_numbers.y = pub_y
        mock_pub = MagicMock()
        mock_pub.public_numbers.return_value = mock_pub_numbers
        mock_priv.public_key.return_value = mock_pub

        # exchange() must return bytes
        mock_priv.exchange.return_value = (42).to_bytes(32, "big")
        return mock_priv

    def test_dh_group14_sends_kexdh_init(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        mock_priv = self._build_mock_dh()
        server_f = KeyExchange.DH_GROUP14_G  # small but valid

        # server_f must be > 1 and < P-1; use G (= 2) which satisfies > 1
        # but not < P-1 reliably in a unit-test, so use a mid-range value
        server_f = KeyExchange.DH_GROUP14_P - 2
        reply = _make_dh_reply_msg(b"hostkey", server_f, b"sig")
        transport._expect_message.return_value = reply

        with (
            patch("spindlex.transport.kex.dh") as mock_dh_module,
            patch("spindlex.transport.kex.default_backend"),
            patch.object(kex, "_verify_server_signature"),
        ):
            mock_params = MagicMock()
            mock_params.generate_private_key.return_value = mock_priv
            mock_params.parameter_numbers.return_value = MagicMock()
            mock_dh_module.DHParameterNumbers.return_value.parameters.return_value = (
                mock_params
            )
            mock_dh_module.DHPublicNumbers.return_value.public_key.return_value = (
                MagicMock()
            )
            kex._perform_dh_group14_sha256()

        transport._send_message.assert_called_once()

    def test_dh_group14_sets_shared_secret(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)
        mock_priv = self._build_mock_dh()
        server_f = KeyExchange.DH_GROUP14_P - 2
        reply = _make_dh_reply_msg(b"hostkey", server_f, b"sig")
        transport._expect_message.return_value = reply

        with (
            patch("spindlex.transport.kex.dh") as mock_dh_module,
            patch("spindlex.transport.kex.default_backend"),
            patch.object(kex, "_verify_server_signature"),
        ):
            mock_params = MagicMock()
            mock_params.generate_private_key.return_value = mock_priv
            mock_params.parameter_numbers.return_value = MagicMock()
            mock_dh_module.DHParameterNumbers.return_value.parameters.return_value = (
                mock_params
            )
            mock_dh_module.DHPublicNumbers.return_value.public_key.return_value = (
                MagicMock()
            )
            kex._perform_dh_group14_sha256()

        assert kex._shared_secret is not None

    def test_dh_group14_sets_session_id_first_time(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)
        mock_priv = self._build_mock_dh()
        server_f = KeyExchange.DH_GROUP14_P - 2
        reply = _make_dh_reply_msg(b"hostkey", server_f, b"sig")
        transport._expect_message.return_value = reply

        with (
            patch("spindlex.transport.kex.dh") as mock_dh_module,
            patch("spindlex.transport.kex.default_backend"),
            patch.object(kex, "_verify_server_signature"),
        ):
            mock_params = MagicMock()
            mock_params.generate_private_key.return_value = mock_priv
            mock_params.parameter_numbers.return_value = MagicMock()
            mock_dh_module.DHParameterNumbers.return_value.parameters.return_value = (
                mock_params
            )
            mock_dh_module.DHPublicNumbers.return_value.public_key.return_value = (
                MagicMock()
            )
            kex._perform_dh_group14_sha256()

        # session_id should be set (was None before)
        assert kex._session_id is not None

    def test_dh_group14_does_not_override_existing_session_id(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)
        existing_sid = b"\xfe" * 32
        kex._session_id = existing_sid
        mock_priv = self._build_mock_dh()
        server_f = KeyExchange.DH_GROUP14_P - 2
        reply = _make_dh_reply_msg(b"hostkey", server_f, b"sig")
        transport._expect_message.return_value = reply

        with (
            patch("spindlex.transport.kex.dh") as mock_dh_module,
            patch("spindlex.transport.kex.default_backend"),
            patch.object(kex, "_verify_server_signature"),
        ):
            mock_params = MagicMock()
            mock_params.generate_private_key.return_value = mock_priv
            mock_params.parameter_numbers.return_value = MagicMock()
            mock_dh_module.DHParameterNumbers.return_value.parameters.return_value = (
                mock_params
            )
            mock_dh_module.DHPublicNumbers.return_value.public_key.return_value = (
                MagicMock()
            )
            kex._perform_dh_group14_sha256()

        assert kex._session_id == existing_sid

    def test_dh_group14_invalid_server_key_raises(self):
        """server_public_int == 1 should raise CryptoException."""
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)
        mock_priv = self._build_mock_dh()
        # server_f = 1 is invalid (<= 1)
        reply = _make_dh_reply_msg(b"hostkey", 1, b"sig")
        transport._expect_message.return_value = reply

        with (
            patch("spindlex.transport.kex.dh") as mock_dh_module,
            patch("spindlex.transport.kex.default_backend"),
        ):
            mock_params = MagicMock()
            mock_params.generate_private_key.return_value = mock_priv
            mock_params.parameter_numbers.return_value = MagicMock()
            mock_dh_module.DHParameterNumbers.return_value.parameters.return_value = (
                mock_params
            )
            with pytest.raises(CryptoException):
                kex._perform_dh_group14_sha256()


# ---------------------------------------------------------------------------
# _perform_ecdh_sha2_nistp256 (client side) — lines 344-401
# ---------------------------------------------------------------------------


class TestEcdhNistp256Client:
    def _build_mock_ec(self):
        mock_priv = MagicMock()
        # 65-byte uncompressed point: 0x04 + 32 bytes x + 32 bytes y
        mock_priv.public_key.return_value.public_bytes.return_value = (
            b"\x04" + b"\xaa" * 64
        )
        # exchange() returns 32 bytes
        mock_priv.exchange.return_value = b"\xbb" * 32
        return mock_priv

    def test_ecdh_nistp256_sends_init(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        server_pub_bytes = b"\x04" + b"\xcc" * 64
        reply = _make_reply_msg(b"hostkey", server_pub_bytes, b"sig")
        transport._expect_message.return_value = reply

        mock_priv = self._build_mock_ec()

        with (
            patch("cryptography.hazmat.primitives.asymmetric.ec") as mock_ec_module,
            patch("spindlex.transport.kex.default_backend"),
            patch("spindlex.transport.kex.serialization"),
            patch.object(kex, "_verify_server_signature"),
        ):
            mock_ec_module.generate_private_key.return_value = mock_priv
            mock_ec_module.EllipticCurvePublicKey.from_encoded_point.return_value = (
                MagicMock()
            )
            mock_ec_module.ECDH.return_value = MagicMock()
            kex._perform_ecdh_sha2_nistp256()

        transport._send_message.assert_called_once()

    def test_ecdh_nistp256_sets_shared_secret(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        server_pub_bytes = b"\x04" + b"\xcc" * 64
        reply = _make_reply_msg(b"hostkey", server_pub_bytes, b"sig")
        transport._expect_message.return_value = reply

        mock_priv = self._build_mock_ec()

        with (
            patch("cryptography.hazmat.primitives.asymmetric.ec") as mock_ec_module,
            patch("spindlex.transport.kex.default_backend"),
            patch("spindlex.transport.kex.serialization"),
            patch.object(kex, "_verify_server_signature"),
        ):
            mock_ec_module.generate_private_key.return_value = mock_priv
            mock_ec_module.EllipticCurvePublicKey.from_encoded_point.return_value = (
                MagicMock()
            )
            mock_ec_module.ECDH.return_value = MagicMock()
            kex._perform_ecdh_sha2_nistp256()

        assert kex._shared_secret is not None

    def test_ecdh_nistp256_stores_server_host_key_blob(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        server_pub_bytes = b"\x04" + b"\xcc" * 64
        reply = _make_reply_msg(b"myhostkey", server_pub_bytes, b"sig")
        transport._expect_message.return_value = reply

        mock_priv = self._build_mock_ec()

        with (
            patch("cryptography.hazmat.primitives.asymmetric.ec") as mock_ec_module,
            patch("spindlex.transport.kex.default_backend"),
            patch("spindlex.transport.kex.serialization"),
            patch.object(kex, "_verify_server_signature"),
        ):
            mock_ec_module.generate_private_key.return_value = mock_priv
            mock_ec_module.EllipticCurvePublicKey.from_encoded_point.return_value = (
                MagicMock()
            )
            mock_ec_module.ECDH.return_value = MagicMock()
            kex._perform_ecdh_sha2_nistp256()

        assert transport._server_host_key_blob == b"myhostkey"


# ---------------------------------------------------------------------------
# _compute_ecdh_exchange_hash — lines 415-457
# ---------------------------------------------------------------------------


class TestComputeEcdhExchangeHash:
    def _setup_kex(self, kex: KeyExchange) -> None:
        _kex_with_kexinit_blobs(kex)
        kex._ecdh_public_key_bytes = b"\x04" + b"\xaa" * 64
        kex._shared_secret = write_mpint(12345)

    def test_raises_without_client_kexinit(self):
        kex, _ = make_kex()
        kex._client_kexinit = None
        kex._server_kexinit = b"\x02" * 16
        kex._ecdh_public_key_bytes = b"\x04" + b"\xaa" * 64
        kex._shared_secret = write_mpint(1)
        with pytest.raises(CryptoException, match="Missing client KEXINIT"):
            kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_without_server_kexinit(self):
        kex, _ = make_kex()
        kex._client_kexinit = b"\x01" * 16
        kex._server_kexinit = None
        kex._ecdh_public_key_bytes = b"\x04" + b"\xaa" * 64
        kex._shared_secret = write_mpint(1)
        with pytest.raises(CryptoException, match="Missing server KEXINIT"):
            kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_without_ecdh_public_key(self):
        kex, _ = make_kex()
        _kex_with_kexinit_blobs(kex)
        kex._ecdh_public_key_bytes = None
        kex._shared_secret = write_mpint(1)
        with pytest.raises(CryptoException, match="Missing ECDH client public key"):
            kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_without_shared_secret(self):
        kex, _ = make_kex()
        _kex_with_kexinit_blobs(kex)
        kex._ecdh_public_key_bytes = b"\x04" + b"\xaa" * 64
        kex._shared_secret = None
        with pytest.raises(CryptoException, match="Missing shared secret"):
            kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_override_client_ecdh_public_key(self):
        kex, _ = make_kex()
        self._setup_kex(kex)
        override_key = b"\x04" + b"\xbb" * 64
        # Should not raise; exchange_hash is computed
        kex._compute_ecdh_exchange_hash(
            b"hostkey", b"serverpub", b"sig", client_ecdh_public_key=override_key
        )
        assert kex._exchange_hash is not None

    def test_computes_exchange_hash(self):
        kex, _ = make_kex()
        self._setup_kex(kex)
        kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")
        assert isinstance(kex._exchange_hash, bytes)
        assert len(kex._exchange_hash) > 0


# ---------------------------------------------------------------------------
# _compute_exchange_hash (DH) — lines 725-767
# ---------------------------------------------------------------------------


class TestComputeExchangeHash:
    def test_raises_without_client_kexinit(self):
        kex, _ = make_kex()
        kex._client_kexinit = None
        kex._server_kexinit = b"\x02" * 16
        kex._dh_public_key_mpint = write_mpint(7)
        kex._shared_secret = write_mpint(42)
        with pytest.raises(CryptoException, match="Missing client KEXINIT"):
            kex._compute_exchange_hash(b"hostkey", b"serverdh", b"sig")

    def test_raises_without_server_kexinit(self):
        kex, _ = make_kex()
        kex._client_kexinit = b"\x01" * 16
        kex._server_kexinit = None
        kex._dh_public_key_mpint = write_mpint(7)
        kex._shared_secret = write_mpint(42)
        with pytest.raises(CryptoException, match="Missing server KEXINIT"):
            kex._compute_exchange_hash(b"hostkey", b"serverdh", b"sig")

    def test_raises_without_dh_public_key(self):
        kex, _ = make_kex()
        _kex_with_kexinit_blobs(kex)
        kex._dh_public_key_mpint = None
        kex._shared_secret = write_mpint(42)
        with pytest.raises(CryptoException, match="Missing DH client public key"):
            kex._compute_exchange_hash(b"hostkey", b"serverdh", b"sig")

    def test_raises_without_shared_secret(self):
        kex, _ = make_kex()
        _kex_with_kexinit_blobs(kex)
        kex._dh_public_key_mpint = write_mpint(7)
        kex._shared_secret = None
        with pytest.raises(CryptoException, match="Missing shared secret"):
            kex._compute_exchange_hash(b"hostkey", b"serverdh", b"sig")

    def test_override_client_dh_key(self):
        kex, _ = make_kex()
        _kex_with_kexinit_blobs(kex)
        kex._dh_public_key_mpint = None  # not set
        kex._shared_secret = write_mpint(42)
        override = write_mpint(999)
        kex._compute_exchange_hash(
            b"hostkey", b"serverdh", b"sig", client_dh_public_mpint=override
        )
        assert kex._exchange_hash is not None

    def test_computes_hash_successfully(self):
        kex, _ = make_kex()
        _kex_with_kexinit_blobs(kex)
        kex._dh_public_key_mpint = write_mpint(7)
        kex._shared_secret = write_mpint(42)
        kex._compute_exchange_hash(b"hostkey", b"serverdh", b"sig")
        assert isinstance(kex._exchange_hash, bytes)


# ---------------------------------------------------------------------------
# _perform_curve25519_sha256 (client side) — lines 640-689
# ---------------------------------------------------------------------------


class TestCurve25519Sha256Client:
    def test_curve25519_client_sends_init(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        mock_priv = MagicMock()
        mock_priv.public_key.return_value.public_bytes.return_value = b"\xaa" * 32
        mock_priv.exchange.return_value = b"\xbb" * 32

        server_pub_bytes = b"\xcc" * 32
        reply = _make_reply_msg(b"hostkey", server_pub_bytes, b"sig")
        transport._expect_message.return_value = reply

        with (
            patch("spindlex.transport.kex.serialization"),
            patch.object(kex, "_verify_server_signature"),
        ):
            # Patch x25519 inside the method's local import
            with patch(
                "cryptography.hazmat.primitives.asymmetric.x25519", create=True
            ) as mock_x:
                mock_x.X25519PrivateKey.generate.return_value = mock_priv
                mock_x.X25519PublicKey.from_public_bytes.return_value = MagicMock()
                kex._perform_curve25519_sha256()

        transport._send_message.assert_called()

    def test_curve25519_client_raises_on_failure(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)
        transport._expect_message.side_effect = RuntimeError("connection died")

        with pytest.raises(CryptoException, match="Curve25519 client KEX failed"):
            kex._perform_curve25519_sha256()


# ---------------------------------------------------------------------------
# _perform_curve25519_sha256_server — lines 461-513
# ---------------------------------------------------------------------------


class TestCurve25519Sha256Server:
    def test_server_curve25519_sends_reply(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        # Fake client init message with 32-byte client public key
        client_pub = b"\xaa" * 32
        init_msg = MagicMock()
        init_msg._data = write_string(client_pub)
        transport._expect_message.return_value = init_msg

        mock_server_priv = MagicMock()
        mock_server_priv.public_key.return_value.public_bytes.return_value = (
            b"\xbb" * 32
        )
        mock_server_priv.exchange.return_value = b"\xcc" * 32

        mock_server_key = MagicMock()
        mock_server_key.get_public_key_bytes.return_value = b"server_host_key"
        mock_server_key.sign.return_value = b"signature"
        transport._server_key = mock_server_key

        with patch("spindlex.transport.kex.serialization"):
            with patch(
                "cryptography.hazmat.primitives.asymmetric.x25519", create=True
            ) as mock_x:
                mock_x.X25519PrivateKey.generate.return_value = mock_server_priv
                mock_x.X25519PublicKey.from_public_bytes.return_value = MagicMock()
                kex._perform_curve25519_sha256_server()

        transport._send_message.assert_called_once()

    def test_server_curve25519_sets_session_id(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        client_pub = b"\xaa" * 32
        init_msg = MagicMock()
        init_msg._data = write_string(client_pub)
        transport._expect_message.return_value = init_msg

        mock_server_priv = MagicMock()
        mock_server_priv.public_key.return_value.public_bytes.return_value = (
            b"\xbb" * 32
        )
        mock_server_priv.exchange.return_value = b"\xcc" * 32

        mock_server_key = MagicMock()
        mock_server_key.get_public_key_bytes.return_value = b"server_host_key"
        mock_server_key.sign.return_value = b"signature"
        transport._server_key = mock_server_key

        with patch("spindlex.transport.kex.serialization"):
            with patch(
                "cryptography.hazmat.primitives.asymmetric.x25519", create=True
            ) as mock_x:
                mock_x.X25519PrivateKey.generate.return_value = mock_server_priv
                mock_x.X25519PublicKey.from_public_bytes.return_value = MagicMock()
                kex._perform_curve25519_sha256_server()

        assert kex._session_id is not None

    def test_server_curve25519_raises_on_failure(self):
        kex, transport = make_kex()
        transport._expect_message.side_effect = RuntimeError("recv failed")

        with pytest.raises(CryptoException, match="Curve25519 server KEX failed"):
            kex._perform_curve25519_sha256_server()


# ---------------------------------------------------------------------------
# _perform_dh_group14_sha256_server — lines 515-569
# ---------------------------------------------------------------------------


class TestDhGroup14Sha256Server:
    def test_server_dh_sends_reply(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        # Encode a valid small client public key e = 5
        client_e = 5
        init_msg = MagicMock()
        init_msg._data = write_mpint(client_e)
        transport._expect_message.return_value = init_msg

        mock_server_priv = MagicMock()
        mock_pub_numbers = MagicMock()
        mock_pub_numbers.y = 0xDEADBEEF
        mock_server_priv.public_key.return_value.public_numbers.return_value = (
            mock_pub_numbers
        )
        mock_server_priv.exchange.return_value = b"\xcc" * 32

        mock_server_key = MagicMock()
        mock_server_key.get_public_key_bytes.return_value = b"server_host_key"
        mock_server_key.sign.return_value = b"signature"
        transport._server_key = mock_server_key

        with (
            patch("spindlex.transport.kex.dh") as mock_dh_module,
            patch("spindlex.transport.kex.default_backend"),
        ):
            mock_params = MagicMock()
            mock_params.generate_private_key.return_value = mock_server_priv
            mock_params.parameter_numbers.return_value = MagicMock()
            mock_dh_module.DHParameterNumbers.return_value.parameters.return_value = (
                mock_params
            )
            mock_dh_module.DHPublicNumbers.return_value.public_key.return_value = (
                MagicMock()
            )
            kex._perform_dh_group14_sha256_server()

        transport._send_message.assert_called_once()

    def test_server_dh_raises_on_failure(self):
        kex, transport = make_kex()
        transport._expect_message.side_effect = RuntimeError("broken")

        with pytest.raises(CryptoException, match="DH Group 14 server KEX failed"):
            kex._perform_dh_group14_sha256_server()


# ---------------------------------------------------------------------------
# _perform_ecdh_sha2_nistp256_server — lines 571-628
# ---------------------------------------------------------------------------


class TestEcdhNistp256Server:
    def test_server_ecdh_sends_reply(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)

        client_pub = b"\x04" + b"\xaa" * 64
        init_msg = MagicMock()
        init_msg._data = write_string(client_pub)
        transport._expect_message.return_value = init_msg

        mock_server_priv = MagicMock()
        mock_server_priv.public_key.return_value.public_bytes.return_value = (
            b"\x04" + b"\xbb" * 64
        )
        mock_server_priv.exchange.return_value = b"\xcc" * 32

        mock_server_key = MagicMock()
        mock_server_key.get_public_key_bytes.return_value = b"server_host_key"
        mock_server_key.sign.return_value = b"signature"
        transport._server_key = mock_server_key

        with (
            patch("cryptography.hazmat.primitives.asymmetric.ec") as mock_ec_module,
            patch("spindlex.transport.kex.default_backend"),
            patch("spindlex.transport.kex.serialization"),
        ):
            mock_ec_module.generate_private_key.return_value = mock_server_priv
            mock_ec_module.EllipticCurvePublicKey.from_encoded_point.return_value = (
                MagicMock()
            )
            mock_ec_module.ECDH.return_value = MagicMock()
            kex._perform_ecdh_sha2_nistp256_server()

        transport._send_message.assert_called_once()

    def test_server_ecdh_raises_on_failure(self):
        kex, transport = make_kex()
        transport._expect_message.side_effect = RuntimeError("boom")

        with pytest.raises(CryptoException, match="ECDH P-256 server KEX failed"):
            kex._perform_ecdh_sha2_nistp256_server()


# ---------------------------------------------------------------------------
# _compute_curve25519_exchange_hash — (called via server / client paths)
# ---------------------------------------------------------------------------


class TestComputeCurve25519ExchangeHash:
    def test_computes_hash(self):
        kex, _ = make_kex()
        _kex_with_kexinit_blobs(kex)
        kex._shared_secret = write_mpint(99)
        kex._compute_curve25519_exchange_hash(
            b"host_key_blob", b"\xaa" * 32, b"\xbb" * 32
        )
        assert isinstance(kex._exchange_hash, bytes)
        assert len(kex._exchange_hash) > 0

    def test_hash_uses_client_version(self):
        kex, transport = make_kex()
        _kex_with_kexinit_blobs(kex)
        kex._shared_secret = write_mpint(99)
        transport._client_version = None  # triggers fallback
        kex._compute_curve25519_exchange_hash(
            b"host_key_blob", b"\xaa" * 32, b"\xbb" * 32
        )
        assert kex._exchange_hash is not None


# ---------------------------------------------------------------------------
# generate_keys raises when missing (line 921)
# ---------------------------------------------------------------------------


class TestGenerateKeysLine921:
    def test_generate_keys_raises_when_no_mac_key(self):
        kex, _ = make_kex()
        # Set encryption keys but leave mac_key_c2s empty/falsy
        kex._encryption_key_c2s = b"\x00" * 32
        kex._encryption_key_s2c = b"\x00" * 32
        kex._mac_key_c2s = b""
        kex._mac_key_s2c = b"\x00" * 32
        with pytest.raises(CryptoException, match="Keys not generated"):
            kex.generate_keys()
