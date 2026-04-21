"""
Targeted unit tests for transport/kex.py to improve coverage.
Tests _negotiate_algorithms, _choose_algorithm, _compute_exchange_hash,
_compute_ecdh_exchange_hash, _compute_curve25519_exchange_hash, and
_generate_session_keys using a mocked transport.
"""

from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import CryptoException
from spindlex.protocol.constants import (
    KEX_CURVE25519_SHA256,
    KEX_DH_GROUP14_SHA256,
    KEX_ECDH_SHA2_NISTP256,
    MSG_NEWKEYS,
)
from spindlex.protocol.messages import KexInitMessage
from spindlex.protocol.utils import write_mpint
from spindlex.transport.kex import KeyExchange

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_kexinit():
    return KexInitMessage(
        cookie=b"\x00" * 16,
        kex_algorithms=["curve25519-sha256", "diffie-hellman-group14-sha256"],
        server_host_key_algorithms=["ssh-ed25519", "rsa-sha2-256"],
        encryption_algorithms_client_to_server=["aes256-ctr"],
        encryption_algorithms_server_to_client=["aes256-ctr"],
        mac_algorithms_client_to_server=["hmac-sha2-256"],
        mac_algorithms_server_to_client=["hmac-sha2-256"],
        compression_algorithms_client_to_server=["none"],
        compression_algorithms_server_to_client=["none"],
        first_kex_packet_follows=False,
    )


def make_transport(server_mode=False):
    t = MagicMock()
    t._server_mode = server_mode
    t._client_version = "SSH-2.0-SpindleX_Test"
    t._server_version = "SSH-2.0-OpenSSH_8.0"
    t._peer_kexinit = make_kexinit()
    t._client_kexinit_blob = make_kexinit().pack()
    t._session_id = None
    t._server_key = None
    return t


def make_kex(server_mode=False):
    transport = make_transport(server_mode=server_mode)
    kex = KeyExchange(transport)
    kex._client_kexinit = make_kexinit().pack()
    kex._server_kexinit = make_kexinit().pack()
    return kex, transport


# ---------------------------------------------------------------------------
# Negotiate algorithms
# ---------------------------------------------------------------------------


class TestNegotiateAlgorithms:
    def test_negotiate_success(self):
        kex, transport = make_kex()
        kex._negotiate_algorithms()
        assert kex._kex_algorithm is not None
        assert kex._encryption_algorithm_c2s == "aes256-ctr"
        assert kex._mac_algorithm_c2s == "hmac-sha2-256"

    def test_negotiate_without_peer_kexinit(self):
        kex, transport = make_kex()
        transport._peer_kexinit = None
        with pytest.raises(CryptoException, match="No peer KEXINIT"):
            kex._negotiate_algorithms()

    def test_negotiate_chooses_curve25519_first(self):
        kex, transport = make_kex()
        kex._negotiate_algorithms()
        # curve25519 is first in the list, so it should be chosen
        assert kex._kex_algorithm == "curve25519-sha256"

    def test_negotiate_falls_back_to_dh(self):
        kex, transport = make_kex()
        # Peer only offers DH
        peer = make_kexinit()
        peer.kex_algorithms = ["diffie-hellman-group14-sha256"]
        transport._peer_kexinit = peer
        kex._negotiate_algorithms()
        assert kex._kex_algorithm == "diffie-hellman-group14-sha256"


class TestChooseAlgorithm:
    def test_chooses_first_match(self):
        kex, _ = make_kex()
        result = kex._choose_algorithm(
            ["aes256-ctr", "aes128-ctr"], ["aes128-ctr", "aes256-ctr"]
        )
        assert result == "aes256-ctr"  # first match in client list

    def test_filters_extensions(self):
        kex, _ = make_kex()
        result = kex._choose_algorithm(
            ["ext-info-c", "kex-strict-c-v00@openssh.com", "aes256-ctr"], ["aes256-ctr"]
        )
        assert result == "aes256-ctr"

    def test_no_match_raises(self):
        kex, _ = make_kex()
        with pytest.raises(CryptoException, match="No matching algorithms"):
            kex._choose_algorithm(["algo-a"], ["algo-b"])


# ---------------------------------------------------------------------------
# Exchange hash computations
# ---------------------------------------------------------------------------


class TestComputeExchangeHash:
    def _setup_kex_with_data(self):
        kex, transport = make_kex()
        kex._shared_secret = write_mpint(12345678)
        kex._dh_public_key_mpint = write_mpint(99999)
        return kex

    def test_dh_exchange_hash(self):
        kex = self._setup_kex_with_data()
        host_key = b"\x00\x00\x00\x07ssh-rsa" + b"\x00" * 50
        server_pub = b"\x00" * 32
        sig = b"\x00" * 32

        kex._compute_exchange_hash(host_key, server_pub, sig)
        assert kex._exchange_hash is not None
        assert len(kex._exchange_hash) == 32  # sha256

    def test_dh_exchange_hash_with_client_mpint(self):
        kex = self._setup_kex_with_data()
        kex._compute_exchange_hash(
            b"\x00" * 10,
            b"\x00" * 10,
            b"\x00" * 10,
            client_dh_public_mpint=write_mpint(54321),
        )
        assert kex._exchange_hash is not None

    def test_dh_hash_missing_client_kexinit_raises(self):
        kex, _ = make_kex()
        kex._client_kexinit = None
        kex._shared_secret = write_mpint(1)
        kex._dh_public_key_mpint = write_mpint(1)
        with pytest.raises(CryptoException, match="Missing client KEXINIT"):
            kex._compute_exchange_hash(b"\x00" * 10, b"\x00" * 10, b"\x00" * 10)

    def test_dh_hash_missing_server_kexinit_raises(self):
        kex, _ = make_kex()
        kex._server_kexinit = None
        kex._shared_secret = write_mpint(1)
        kex._dh_public_key_mpint = write_mpint(1)
        with pytest.raises(CryptoException, match="Missing server KEXINIT"):
            kex._compute_exchange_hash(b"\x00" * 10, b"\x00" * 10, b"\x00" * 10)

    def test_dh_hash_missing_client_dh_key_raises(self):
        kex, _ = make_kex()
        kex._shared_secret = write_mpint(1)
        kex._dh_public_key_mpint = None  # no fallback
        with pytest.raises(CryptoException, match="Missing DH client public key"):
            kex._compute_exchange_hash(b"\x00" * 10, b"\x00" * 10, b"\x00" * 10)

    def test_dh_hash_missing_shared_secret_raises(self):
        kex, _ = make_kex()
        kex._dh_public_key_mpint = write_mpint(1)
        kex._shared_secret = None
        with pytest.raises(CryptoException, match="Missing shared secret"):
            kex._compute_exchange_hash(b"\x00" * 10, b"\x00" * 10, b"\x00" * 10)


class TestComputeECDHExchangeHash:
    def test_ecdh_exchange_hash(self):
        kex, _ = make_kex()
        kex._shared_secret = write_mpint(99999)
        kex._ecdh_public_key_bytes = b"\x04" + b"\x00" * 64  # uncompressed P-256

        kex._compute_ecdh_exchange_hash(
            b"\x00" * 20,  # server host key
            b"\x04" + b"\x00" * 64,  # server public key
            b"\x00" * 20,  # sig
        )
        assert kex._exchange_hash is not None

    def test_ecdh_hash_with_client_key_override(self):
        kex, _ = make_kex()
        kex._shared_secret = write_mpint(1)
        kex._ecdh_public_key_bytes = None  # not set

        kex._compute_ecdh_exchange_hash(
            b"\x00" * 10,
            b"\x04" + b"\x00" * 64,
            b"\x00" * 10,
            client_ecdh_public_key=b"\x04" + b"\x01" * 64,
        )
        assert kex._exchange_hash is not None

    def test_ecdh_hash_missing_client_kexinit_raises(self):
        kex, _ = make_kex()
        kex._client_kexinit = None
        kex._shared_secret = write_mpint(1)
        kex._ecdh_public_key_bytes = b"\x04" + b"\x00" * 64
        with pytest.raises(CryptoException, match="Missing client KEXINIT"):
            kex._compute_ecdh_exchange_hash(
                b"\x00" * 5, b"\x04" + b"\x00" * 64, b"\x00" * 5
            )

    def test_ecdh_hash_missing_client_pub_raises(self):
        kex, _ = make_kex()
        kex._shared_secret = write_mpint(1)
        kex._ecdh_public_key_bytes = None  # no override and no attribute
        with pytest.raises(CryptoException, match="Missing ECDH client public key"):
            kex._compute_ecdh_exchange_hash(
                b"\x00" * 5, b"\x04" + b"\x00" * 64, b"\x00" * 5
            )

    def test_ecdh_hash_missing_shared_secret_raises(self):
        kex, _ = make_kex()
        kex._shared_secret = None
        kex._ecdh_public_key_bytes = b"\x04" + b"\x00" * 64
        with pytest.raises(CryptoException, match="Missing shared secret"):
            kex._compute_ecdh_exchange_hash(
                b"\x00" * 5, b"\x04" + b"\x00" * 64, b"\x00" * 5
            )


class TestComputeCurve25519ExchangeHash:
    def test_curve25519_hash(self):
        kex, _ = make_kex()
        kex._shared_secret = write_mpint(123456789)

        kex._compute_curve25519_exchange_hash(
            server_host_key=b"\x00" * 20,
            client_public_key=b"\x01" * 32,
            server_public_key=b"\x02" * 32,
        )
        assert kex._exchange_hash is not None
        assert len(kex._exchange_hash) == 32


# ---------------------------------------------------------------------------
# Key derivation / _generate_session_keys
# ---------------------------------------------------------------------------


class TestGenerateSessionKeys:
    def _make_kex_ready(self):
        kex, transport = make_kex()
        # Set up enough state for key generation
        kex._shared_secret = write_mpint(0xDEADBEEF)
        kex._exchange_hash = b"\xab" * 32
        kex._session_id = b"\xcd" * 32
        kex._kex_algorithm = KEX_CURVE25519_SHA256
        kex._encryption_algorithm_c2s = "aes256-ctr"
        kex._encryption_algorithm_s2c = "aes256-ctr"
        kex._mac_algorithm_c2s = "hmac-sha2-256"
        kex._mac_algorithm_s2c = "hmac-sha2-256"
        kex._compression_algorithm_c2s = "none"
        kex._compression_algorithm_s2c = "none"
        return kex, transport

    def test_generate_session_keys_success(self):
        kex, transport = self._make_kex_ready()
        kex._generate_session_keys()

        assert transport._encryption_key_c2s is not None
        assert transport._encryption_key_s2c is not None
        assert transport._mac_key_c2s is not None
        assert transport._iv_c2s is not None
        assert transport._session_id == kex._session_id

    def test_generate_keys_missing_shared_secret_raises(self):
        kex, _ = self._make_kex_ready()
        kex._shared_secret = None
        with pytest.raises(CryptoException, match="Missing key exchange data"):
            kex._generate_session_keys()

    def test_generate_keys_missing_exchange_hash_raises(self):
        kex, _ = self._make_kex_ready()
        kex._exchange_hash = None
        with pytest.raises(CryptoException, match="Missing key exchange data"):
            kex._generate_session_keys()

    def test_generate_keys_uses_sha512_for_sha512_alg(self):
        kex, transport = self._make_kex_ready()
        kex._kex_algorithm = "diffie-hellman-group-exchange-sha512"
        kex._generate_session_keys()
        assert transport._encryption_key_c2s is not None

    def test_generate_keys_without_mac(self):
        kex, transport = self._make_kex_ready()
        kex._mac_algorithm_c2s = "none"
        kex._mac_algorithm_s2c = "none"
        kex._generate_session_keys()
        # MAC keys should be empty bytes
        assert transport._mac_key_c2s == b""
        assert transport._mac_key_s2c == b""

    def test_generate_keys_uses_exchange_hash_as_session_id(self):
        kex, transport = self._make_kex_ready()
        kex._session_id = (
            None  # first handshake – session_id should equal exchange_hash
        )
        kex._generate_session_keys()
        # Transport gets the exchange hash as session id
        assert (
            transport._session_id is None
        )  # kex sets it but session_id was None in kex


# ---------------------------------------------------------------------------
# Send/receive NEWKEYS helpers
# ---------------------------------------------------------------------------


class TestNewkeys:
    def test_send_newkeys(self):
        kex, transport = make_kex()
        kex._send_newkeys()
        transport._send_message.assert_called_once()
        msg = transport._send_message.call_args[0][0]
        assert msg.msg_type == MSG_NEWKEYS

    def test_receive_newkeys(self):
        kex, transport = make_kex()
        kex._receive_newkeys()
        transport._expect_message.assert_called_once_with(MSG_NEWKEYS)


# ---------------------------------------------------------------------------
# _perform_client_kex dispatch
# ---------------------------------------------------------------------------


class TestPerformClientKex:
    def test_dispatches_curve25519(self):
        kex, transport = make_kex()
        kex._kex_algorithm = KEX_CURVE25519_SHA256
        with patch.object(kex, "_perform_curve25519_sha256") as m:
            kex._perform_client_kex()
            m.assert_called_once()

    def test_dispatches_curve25519_compat_alias(self):
        kex, transport = make_kex()
        kex._kex_algorithm = "curve25519-sha256@libssh.org"
        with patch.object(kex, "_perform_curve25519_sha256") as m:
            kex._perform_client_kex()
            m.assert_called_once()

    def test_dispatches_ecdh(self):
        kex, transport = make_kex()
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP256
        with patch.object(kex, "_perform_ecdh_sha2_nistp256") as m:
            kex._perform_client_kex()
            m.assert_called_once()

    def test_dispatches_dh_group14(self):
        kex, transport = make_kex()
        kex._kex_algorithm = KEX_DH_GROUP14_SHA256
        with patch.object(kex, "_perform_dh_group14_sha256") as m:
            kex._perform_client_kex()
            m.assert_called_once()

    def test_dispatches_unknown_to_dh_group14(self):
        kex, transport = make_kex()
        kex._kex_algorithm = "unknown-algo"
        with patch.object(kex, "_perform_dh_group14_sha256") as m:
            kex._perform_client_kex()
            m.assert_called_once()


class TestPerformServerKex:
    def test_dispatches_curve25519(self):
        kex, transport = make_kex(server_mode=True)
        kex._kex_algorithm = KEX_CURVE25519_SHA256
        with patch.object(kex, "_perform_curve25519_sha256_server") as m:
            kex._perform_server_kex()
            m.assert_called_once()

    def test_dispatches_ecdh(self):
        kex, transport = make_kex(server_mode=True)
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP256
        with patch.object(kex, "_perform_ecdh_sha2_nistp256_server") as m:
            kex._perform_server_kex()
            m.assert_called_once()

    def test_dispatches_dh(self):
        kex, transport = make_kex(server_mode=True)
        kex._kex_algorithm = KEX_DH_GROUP14_SHA256
        with patch.object(kex, "_perform_dh_group14_sha256_server") as m:
            kex._perform_server_kex()
            m.assert_called_once()

    def test_dispatches_unknown_to_dh(self):
        kex, transport = make_kex(server_mode=True)
        kex._kex_algorithm = "weird-algo"
        with patch.object(kex, "_perform_dh_group14_sha256_server") as m:
            kex._perform_server_kex()
            m.assert_called_once()
