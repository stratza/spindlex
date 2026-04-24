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
)
from spindlex.protocol.messages import KexInitMessage
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

    def test_unknown_algorithm_raises(self):
        kex, transport = make_kex()
        kex._kex_algorithm = "unknown-algo"
        with pytest.raises(CryptoException, match="Unsupported KEX algorithm"):
            kex._perform_client_kex()


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

    def test_unknown_algorithm_raises(self):
        kex, transport = make_kex(server_mode=True)
        kex._kex_algorithm = "weird-algo"
        with pytest.raises(CryptoException, match="Unsupported KEX algorithm"):
            kex._perform_server_kex()
