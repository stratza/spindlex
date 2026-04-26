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


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


class TestKeyExchangeInit:
    def test_init_stores_transport(self):
        kex, transport = make_kex()
        assert kex._transport is transport

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
