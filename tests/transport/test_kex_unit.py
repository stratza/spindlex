"""
Unit tests for spindlex/transport/kex.py

All tests are mock-based — no real SSH connections are made.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import CryptoException, ProtocolException
from spindlex.protocol.constants import (
    KEX_CURVE25519_SHA256,
    KEX_DH_GROUP14_SHA256,
    KEX_ECDH_SHA2_NISTP256,
    KEX_ECDH_SHA2_NISTP384,
    KEX_ECDH_SHA2_NISTP521,
    MSG_NEWKEYS,
)
from spindlex.transport.kex import KeyExchange

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_kex() -> tuple[KeyExchange, MagicMock]:
    """Return a KeyExchange instance with a fully-mocked transport."""
    transport = MagicMock()
    transport._send_message = MagicMock()
    transport._expect_message = MagicMock()
    transport.session_id = b"\x00" * 32  # Added for unit2 compatibility
    transport._session_id = None
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


def _make_peer_kexinit():
    """Return a MagicMock that looks like a KexInitMessage from the peer."""
    peer = MagicMock()
    peer.kex_algorithms = ["curve25519-sha256", "diffie-hellman-group14-sha256"]
    peer.server_host_key_algorithms = ["ssh-ed25519"]
    peer.encryption_algorithms_client_to_server = ["aes256-ctr"]
    peer.encryption_algorithms_server_to_client = ["aes256-ctr"]
    peer.mac_algorithms_client_to_server = ["hmac-sha2-256"]
    peer.mac_algorithms_server_to_client = ["hmac-sha2-256"]
    peer.pack.return_value = b"\x01" * 16
    return peer


def _make_reply_msg(server_host_key: bytes, server_pub: bytes, sig: bytes) -> MagicMock:
    """Build a fake reply Message whose ._data encodes three strings."""
    from spindlex.protocol.utils import write_string

    data = write_string(server_host_key) + write_string(server_pub) + write_string(sig)
    msg = MagicMock()
    msg._data = data
    return msg


def _make_dh_reply_msg(
    server_host_key: bytes, server_f_int: int, sig: bytes
) -> MagicMock:
    """Build a fake KEXDH_REPLY whose ._data encodes host_key, mpint(f), sig."""
    from spindlex.protocol.utils import write_mpint, write_string

    data = write_string(server_host_key) + write_mpint(server_f_int) + write_string(sig)
    msg = MagicMock()
    msg._data = data
    return msg


def _kex_with_kexinit_blobs(kex: KeyExchange) -> None:
    """Populate KEXINIT blobs so exchange-hash methods don't fail."""
    kex._client_kexinit = b"\x01" * 16
    kex._server_kexinit = b"\x02" * 16


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestKeyExchangeInit:
    def test_init_stores_transport(self):
        kex, transport = make_kex()
        assert kex._transport is transport


class TestKeyExchangeHashSelection:
    def test_kex_hash_selection(self):
        kex, _ = make_kex()

        # Mock state for _generate_session_keys
        kex._encryption_algorithm_c2s = "aes256-ctr"
        kex._encryption_algorithm_s2c = "aes256-ctr"
        kex._mac_algorithm_c2s = "hmac-sha2-256"
        kex._mac_algorithm_s2c = "hmac-sha2-256"
        kex._cipher_suite = MagicMock()
        kex._cipher_suite.get_cipher_info.return_value = {"key_len": 32, "iv_len": 16}
        kex._cipher_suite.get_mac_info.return_value = {"key_len": 32}
        kex._shared_secret = b"secret"
        kex._exchange_hash = b"hash"

        with patch(
            "spindlex.crypto.backend.default_crypto_backend.derive_key"
        ) as mock_derive:
            # P-384 -> SHA384
            kex._kex_algorithm = KEX_ECDH_SHA2_NISTP384
            kex._generate_session_keys()
            assert mock_derive.call_args_list[0][0][0] == "sha384"

            mock_derive.reset_mock()

            # P-521 -> SHA512
            kex._kex_algorithm = KEX_ECDH_SHA2_NISTP521
            kex._generate_session_keys()
            assert mock_derive.call_args_list[0][0][0] == "sha512"

    def test_algorithm_initially_none(self):
        kex, _ = make_kex()
        assert kex._algorithm is None

    def test_shared_secret_initially_none(self):
        kex, _ = make_kex()
        assert kex._shared_secret is None

    def test_exchange_hash_initially_none(self):
        kex, _ = make_kex()
        assert kex._exchange_hash is None

    def test_session_id_initially_none(self):
        kex, _ = make_kex()
        assert kex._session_id is None

    def test_kex_algorithm_negotiated_initially_none(self):
        kex, _ = make_kex()
        assert kex._kex_algorithm is None


# ---------------------------------------------------------------------------
# _send_kexinit
# ---------------------------------------------------------------------------


class TestSendKexinit:
    def test_send_kexinit_calls_transport(self):
        kex, transport = make_kex()
        kex._send_kexinit()
        transport._send_message.assert_called_once()
        # The sent message should be a KexInitMessage
        from spindlex.protocol.messages import KexInitMessage

        sent = transport._send_message.call_args[0][0]
        assert isinstance(sent, KexInitMessage)

    def test_send_kexinit_stores_client_kexinit_blob(self):
        kex, _ = make_kex()
        kex._send_kexinit()
        assert kex._client_kexinit is not None
        assert isinstance(kex._client_kexinit, bytes)


# ---------------------------------------------------------------------------
# _receive_kexinit
# ---------------------------------------------------------------------------


class TestReceiveKexinit:
    def test_receive_kexinit_stores_server_blob(self):
        kex, transport = make_kex()
        peer = _make_peer_kexinit()

        from spindlex.protocol.messages import KexInitMessage

        peer.__class__ = KexInitMessage  # make isinstance check pass
        transport._expect_message.return_value = peer

        # Patch isinstance so we can bypass actual class hierarchy
        with patch("spindlex.transport.kex.isinstance", return_value=True):
            kex._receive_kexinit()

        assert transport._peer_kexinit is peer
        assert kex._server_kexinit is not None

    def test_receive_kexinit_wrong_type_raises(self):
        kex, transport = make_kex()
        # Return something that isn't a KexInitMessage
        transport._expect_message.return_value = MagicMock(spec=object)
        with pytest.raises(ProtocolException, match="Expected KEXINIT"):
            kex._receive_kexinit()


# ---------------------------------------------------------------------------
# _negotiate_algorithms
# ---------------------------------------------------------------------------


class TestNegotiateAlgorithms:
    def test_negotiate_raises_without_peer_kexinit(self):
        kex, transport = make_kex()
        transport._peer_kexinit = None
        with pytest.raises(CryptoException, match="No peer KEXINIT"):
            kex._negotiate_algorithms()

    def test_negotiate_sets_kex_algorithm(self):
        kex, transport = make_kex()
        transport._peer_kexinit = _make_peer_kexinit()
        kex._negotiate_algorithms()
        # curve25519-sha256 is first in both lists
        assert kex._kex_algorithm == "curve25519-sha256"

    def test_negotiate_sets_encryption_algorithms(self):
        kex, transport = make_kex()
        transport._peer_kexinit = _make_peer_kexinit()
        kex._negotiate_algorithms()
        assert kex._encryption_algorithm_c2s == "aes256-ctr"
        assert kex._encryption_algorithm_s2c == "aes256-ctr"

    def test_negotiate_sets_mac_algorithms(self):
        kex, transport = make_kex()
        transport._peer_kexinit = _make_peer_kexinit()
        kex._negotiate_algorithms()
        assert kex._mac_algorithm_c2s == "hmac-sha2-256"
        assert kex._mac_algorithm_s2c == "hmac-sha2-256"

    def test_negotiate_sets_compression_to_none(self):
        kex, transport = make_kex()
        transport._peer_kexinit = _make_peer_kexinit()
        kex._negotiate_algorithms()
        from spindlex.protocol.constants import COMPRESS_NONE

        assert kex._compression_algorithm_c2s == COMPRESS_NONE


# ---------------------------------------------------------------------------
# _perform_client_kex dispatch
# ---------------------------------------------------------------------------


class TestPerformClientKexDispatch:
    def test_unsupported_algorithm_raises(self):
        kex, _ = make_kex()
        kex._kex_algorithm = "unknown-kex-algo"
        with pytest.raises(CryptoException, match="Unsupported KEX"):
            kex._perform_client_kex()

    def test_curve25519_dispatched(self):
        kex, _ = make_kex()
        kex._kex_algorithm = KEX_CURVE25519_SHA256
        with patch.object(kex, "_perform_curve25519_sha256") as mock_method:
            kex._perform_client_kex()
            mock_method.assert_called_once()

    def test_curve25519_libssh_alias_dispatched(self):
        kex, _ = make_kex()
        kex._kex_algorithm = "curve25519-sha256@libssh.org"
        with patch.object(kex, "_perform_curve25519_sha256") as mock_method:
            kex._perform_client_kex()
            mock_method.assert_called_once()

    def test_ecdh_nistp256_dispatched(self):
        kex, _ = make_kex()
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP256
        with patch.object(kex, "_perform_ecdh_sha2_nistp256") as mock_method:
            kex._perform_client_kex()
            mock_method.assert_called_once()

    def test_dh_group14_dispatched(self):
        kex, _ = make_kex()
        kex._kex_algorithm = KEX_DH_GROUP14_SHA256
        with patch.object(kex, "_perform_dh_group14_sha256") as mock_method:
            kex._perform_client_kex()
            mock_method.assert_called_once()


# ---------------------------------------------------------------------------
# _perform_server_kex dispatch
# ---------------------------------------------------------------------------


class TestPerformServerKexDispatch:
    def test_unsupported_algorithm_raises(self):
        kex, _ = make_kex()
        kex._kex_algorithm = "unknown-kex-algo"
        with pytest.raises(CryptoException, match="Unsupported KEX"):
            kex._perform_server_kex()

    def test_curve25519_server_dispatched(self):
        kex, _ = make_kex()
        kex._kex_algorithm = KEX_CURVE25519_SHA256
        with patch.object(kex, "_perform_curve25519_sha256_server") as mock_method:
            kex._perform_server_kex()
            mock_method.assert_called_once()

    def test_ecdh_server_dispatched(self):
        kex, _ = make_kex()
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP256
        with patch.object(kex, "_perform_ecdh_sha2_nistp256_server") as mock_method:
            kex._perform_server_kex()
            mock_method.assert_called_once()

    def test_dh_group14_server_dispatched(self):
        kex, _ = make_kex()
        kex._kex_algorithm = KEX_DH_GROUP14_SHA256
        with patch.object(kex, "_perform_dh_group14_sha256_server") as mock_method:
            kex._perform_server_kex()
            mock_method.assert_called_once()


# ---------------------------------------------------------------------------
# _send_newkeys / _receive_newkeys
# ---------------------------------------------------------------------------


class TestNewKeys:
    def test_send_newkeys_sends_message(self):
        kex, transport = make_kex()
        kex._send_newkeys()
        transport._send_message.assert_called_once()
        from spindlex.protocol.messages import Message

        sent = transport._send_message.call_args[0][0]
        assert isinstance(sent, Message)

    def test_receive_newkeys_calls_expect_message(self):
        kex, transport = make_kex()
        kex._receive_newkeys()
        transport._expect_message.assert_called_once_with(MSG_NEWKEYS)


# ---------------------------------------------------------------------------
# _generate_session_keys
# ---------------------------------------------------------------------------


class TestGenerateSessionKeys:
    def _prepare_kex_for_keygen(self, kex: KeyExchange) -> None:
        """Set minimal state so _generate_session_keys can run."""
        kex._kex_algorithm = "curve25519-sha256"
        kex._encryption_algorithm_c2s = "aes256-ctr"
        kex._encryption_algorithm_s2c = "aes256-ctr"
        kex._mac_algorithm_c2s = "hmac-sha2-256"
        kex._mac_algorithm_s2c = "hmac-sha2-256"
        # Minimal shared-secret / exchange-hash placeholders
        # write_mpint(1) = b"\x00\x00\x00\x01\x01"
        from spindlex.protocol.utils import write_mpint

        kex._shared_secret = write_mpint(1)
        kex._exchange_hash = b"\xab" * 32
        kex._session_id = b"\xab" * 32

    def test_generate_session_keys_raises_without_data(self):
        kex, _ = make_kex()
        # Don't set any of the required fields
        kex._encryption_algorithm_c2s = None
        with pytest.raises(CryptoException, match="Missing key exchange data"):
            kex._generate_session_keys()

    def test_generate_session_keys_updates_transport(self):
        kex, transport = make_kex()
        self._prepare_kex_for_keygen(kex)
        kex._generate_session_keys()
        # Transport should have received the derived keys
        assert transport._encryption_key_c2s is not None
        assert transport._session_id == kex._session_id

    def test_generate_session_keys_sha512_path(self):
        kex, transport = make_kex()
        self._prepare_kex_for_keygen(kex)
        kex._kex_algorithm = "diffie-hellman-group18-sha512"
        # Should not raise
        kex._generate_session_keys()


# ---------------------------------------------------------------------------
# generate_keys (public API)
# ---------------------------------------------------------------------------


class TestGenerateKeys:
    def test_generate_keys_raises_if_not_run(self):
        """generate_keys() before _generate_session_keys() raises because
        _encryption_key_c2s etc. don't exist yet (AttributeError) or are
        falsy (CryptoException).  Either way it must not succeed."""
        kex, _ = make_kex()
        with pytest.raises((CryptoException, AttributeError)):
            kex.generate_keys()

    def test_generate_keys_returns_tuple_after_keygen(self):
        kex, transport = make_kex()
        kex._kex_algorithm = "curve25519-sha256"
        kex._encryption_algorithm_c2s = "aes256-ctr"
        kex._encryption_algorithm_s2c = "aes256-ctr"
        kex._mac_algorithm_c2s = "hmac-sha2-256"
        kex._mac_algorithm_s2c = "hmac-sha2-256"
        from spindlex.protocol.utils import write_mpint

        kex._shared_secret = write_mpint(1)
        kex._exchange_hash = b"\xab" * 32
        kex._session_id = b"\xab" * 32
        kex._generate_session_keys()
        result = kex.generate_keys()
        assert isinstance(result, tuple)
        assert len(result) == 4


# ---------------------------------------------------------------------------
# _sign_exchange_hash
# ---------------------------------------------------------------------------


class TestSignExchangeHash:
    def test_sign_raises_if_no_server_key(self):
        kex, transport = make_kex()
        transport._server_key = None
        with pytest.raises(CryptoException, match="Server key not set"):
            kex._sign_exchange_hash(b"\x00" * 32)

    def test_sign_delegates_to_server_key(self):
        kex, transport = make_kex()
        mock_key = MagicMock()
        mock_key.sign.return_value = b"fakesig"
        transport._server_key = mock_key
        result = kex._sign_exchange_hash(b"\x00" * 32)
        assert result == b"fakesig"
        mock_key.sign.assert_called_once_with(b"\x00" * 32)

    def test_sign_raises_if_sign_returns_none(self):
        kex, transport = make_kex()
        mock_key = MagicMock()
        mock_key.sign.return_value = None
        transport._server_key = mock_key
        with pytest.raises(CryptoException, match="Failed to sign"):
            kex._sign_exchange_hash(b"\x00" * 32)


# ---------------------------------------------------------------------------
# start_kex — top-level integration (mocked internals)
# ---------------------------------------------------------------------------


class TestStartKex:
    def test_start_kex_raises_when_kex_method_fails(self):
        """If _perform_client_kex raises, start_kex wraps it in CryptoException."""
        kex, transport = make_kex()
        transport._peer_kexinit = _make_peer_kexinit()
        transport._client_kexinit_blob = b"\x00" * 16
        kex._transport._server_mode = False

        with (
            patch.object(kex, "_negotiate_algorithms"),
            patch.object(
                kex,
                "_perform_client_kex",
                side_effect=RuntimeError("unexpected"),
            ),
        ):
            with pytest.raises(CryptoException, match="Key exchange failed"):
                kex.start_kex()

    def test_start_kex_calls_send_kexinit_when_no_peer_kexinit(self):
        kex, transport = make_kex()
        transport._peer_kexinit = None  # not yet exchanged

        with (
            patch.object(kex, "_send_kexinit") as mock_send,
            patch.object(kex, "_receive_kexinit") as mock_recv,
            patch.object(kex, "_negotiate_algorithms"),
            patch.object(kex, "_perform_client_kex"),
            patch.object(kex, "_generate_session_keys"),
            patch.object(kex, "_send_newkeys"),
            patch.object(kex, "_receive_newkeys"),
        ):
            # After _receive_kexinit is called, simulate peer_kexinit being set
            def set_peer(*a, **kw):
                transport._peer_kexinit = _make_peer_kexinit()

            mock_recv.side_effect = set_peer
            kex.start_kex()
            mock_send.assert_called_once()
            mock_recv.assert_called_once()

    def test_start_kex_skips_kexinit_when_peer_already_set(self):
        kex, transport = make_kex()
        transport._peer_kexinit = _make_peer_kexinit()
        transport._client_kexinit_blob = b"\x00" * 16
        transport._server_mode = False

        with (
            patch.object(kex, "_send_kexinit") as mock_send,
            patch.object(kex, "_receive_kexinit") as mock_recv,
            patch.object(kex, "_negotiate_algorithms"),
            patch.object(kex, "_perform_client_kex"),
            patch.object(kex, "_generate_session_keys"),
            patch.object(kex, "_send_newkeys"),
            patch.object(kex, "_receive_newkeys"),
        ):
            kex.start_kex()
            mock_send.assert_not_called()
            mock_recv.assert_not_called()

    def test_start_kex_server_mode_calls_server_kex(self):
        kex, transport = make_kex()
        transport._peer_kexinit = _make_peer_kexinit()
        transport._client_kexinit_blob = b"\x00" * 16
        transport._server_mode = True

        with (
            patch.object(kex, "_negotiate_algorithms"),
            patch.object(kex, "_perform_server_kex") as mock_server,
            patch.object(kex, "_perform_client_kex") as mock_client,
            patch.object(kex, "_generate_session_keys"),
            patch.object(kex, "_send_newkeys"),
            patch.object(kex, "_receive_newkeys"),
        ):
            kex.start_kex()
            mock_server.assert_called_once()
            mock_client.assert_not_called()

    def test_start_kex_reraises_crypto_exception(self):
        kex, transport = make_kex()
        transport._peer_kexinit = _make_peer_kexinit()
        transport._server_mode = False

        with (
            patch.object(kex, "_negotiate_algorithms"),
            patch.object(
                kex,
                "_perform_client_kex",
                side_effect=CryptoException("crypto err"),
            ),
        ):
            with pytest.raises(CryptoException, match="crypto err"):
                kex.start_kex()


# ---------------------------------------------------------------------------
# Merged tests from test_kex_unit2.py
# ---------------------------------------------------------------------------


class TestDhGroup14Sha256Client:
    """Mock out the cryptography.hazmat.primitives.asymmetric.dh calls."""

    def _build_mock_dh(self, pub_y: int = 0x1234ABCD):
        """Return a mock DH private key that reports pub_y as its public number."""
        from unittest.mock import MagicMock

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
        # server_f must be > 1 and < P-1; use G (= 2) which satisfies > 1
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


class TestEcdhNistp256Client:
    def _build_mock_ec(self):
        from unittest.mock import MagicMock

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


class TestComputeEcdhExchangeHash:
    def _setup_kex(self, kex: KeyExchange) -> None:
        _kex_with_kexinit_blobs(kex)
        kex._ecdh_public_key_bytes = b"\x04" + b"\xaa" * 64
        from spindlex.protocol.utils import write_mpint

        kex._shared_secret = write_mpint(12345)

    def test_computes_exchange_hash(self):
        kex, _ = make_kex()
        self._setup_kex(kex)
        kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")
        assert isinstance(kex._exchange_hash, bytes)
        assert len(kex._exchange_hash) > 0


class TestComputeCurve25519ExchangeHash:
    def test_computes_hash(self):
        kex, _ = make_kex()
        _kex_with_kexinit_blobs(kex)
        from spindlex.protocol.utils import write_mpint

        kex._shared_secret = write_mpint(99)
        kex._compute_curve25519_exchange_hash(
            b"host_key_blob", b"\xaa" * 32, b"\xbb" * 32
        )
        assert isinstance(kex._exchange_hash, bytes)
        assert len(kex._exchange_hash) > 0
