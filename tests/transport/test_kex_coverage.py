"""
Additional coverage tests for spindlex/transport/kex.py.

Covers the guard-raise paths that are missed in test_kex_unit.py:
- _perform_client_kex with NISTP384/521 dispatch
- _perform_server_kex with NISTP384/521 dispatch
- _compute_ecdh_exchange_hash guard paths (lines 459, 464, 477, 485)
- _compute_exchange_hash guard paths (lines 801, 806, 819, 827)
- _verify_server_signature failure paths (lines 347-351)
- _perform_ecdh unsupported-algorithm guard (lines 363-370)
- _perform_ecdh exception wrapping (lines 426-432)
- generate_keys() before key exchange (line 989)
- _perform_dh_group14_sha256 public-key-le-0 guard (line 283)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import CryptoException
from spindlex.protocol.constants import (
    KEX_ECDH_SHA2_NISTP384,
    KEX_ECDH_SHA2_NISTP521,
)
from spindlex.transport.kex import KeyExchange

# ---------------------------------------------------------------------------
# Helpers (mirrored from test_kex_unit.py)
# ---------------------------------------------------------------------------


def _make_kex() -> tuple[KeyExchange, MagicMock]:
    transport = MagicMock()
    transport._send_message = MagicMock()
    transport._expect_message = MagicMock()
    transport.session_id = b"\x00" * 32
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


def _set_kexinit_blobs(kex: KeyExchange) -> None:
    kex._client_kexinit = b"\x01" * 16
    kex._server_kexinit = b"\x02" * 16


# ---------------------------------------------------------------------------
# _perform_client_kex — NISTP384 / NISTP521 dispatch
# ---------------------------------------------------------------------------


class TestPerformClientKexNistDispatch:
    def test_nistp384_dispatches_to_perform_ecdh(self):
        kex, _ = _make_kex()
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP384
        with patch.object(kex, "_perform_ecdh") as mock_method:
            kex._perform_client_kex()
            mock_method.assert_called_once()

    def test_nistp521_dispatches_to_perform_ecdh(self):
        kex, _ = _make_kex()
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP521
        with patch.object(kex, "_perform_ecdh") as mock_method:
            kex._perform_client_kex()
            mock_method.assert_called_once()


# ---------------------------------------------------------------------------
# _perform_server_kex — NISTP384 / NISTP521 dispatch
# ---------------------------------------------------------------------------


class TestPerformServerKexNistDispatch:
    def test_nistp384_dispatches_to_perform_ecdh_server(self):
        kex, _ = _make_kex()
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP384
        with patch.object(kex, "_perform_ecdh_server") as mock_method:
            kex._perform_server_kex()
            mock_method.assert_called_once()

    def test_nistp521_dispatches_to_perform_ecdh_server(self):
        kex, _ = _make_kex()
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP521
        with patch.object(kex, "_perform_ecdh_server") as mock_method:
            kex._perform_server_kex()
            mock_method.assert_called_once()


# ---------------------------------------------------------------------------
# _compute_ecdh_exchange_hash guard paths
# ---------------------------------------------------------------------------


class TestComputeEcdhExchangeHashGuards:
    def _base_kex(self) -> KeyExchange:
        kex, _ = _make_kex()
        from spindlex.protocol.utils import write_mpint

        kex._shared_secret = write_mpint(99)
        kex._ecdh_public_key_bytes = b"\x04" + b"\xaa" * 64
        return kex

    def test_raises_when_client_kexinit_is_none(self):
        kex = self._base_kex()
        kex._client_kexinit = None
        kex._server_kexinit = b"\x02" * 16
        with pytest.raises(CryptoException, match="Missing client KEXINIT"):
            kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_when_server_kexinit_is_none(self):
        kex = self._base_kex()
        kex._client_kexinit = b"\x01" * 16
        kex._server_kexinit = None
        with pytest.raises(CryptoException, match="Missing server KEXINIT"):
            kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_when_client_pub_key_is_none(self):
        kex = self._base_kex()
        _set_kexinit_blobs(kex)
        kex._ecdh_public_key_bytes = None  # type: ignore[assignment]
        with pytest.raises(CryptoException, match="Missing ECDH client public key"):
            kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_when_shared_secret_is_none(self):
        kex = self._base_kex()
        _set_kexinit_blobs(kex)
        kex._shared_secret = None
        with pytest.raises(CryptoException, match="Missing shared secret for ECDH"):
            kex._compute_ecdh_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_override_client_pub_key_works(self):
        """client_ecdh_public_key parameter overrides self._ecdh_public_key_bytes."""
        kex = self._base_kex()
        _set_kexinit_blobs(kex)
        kex._ecdh_public_key_bytes = None  # type: ignore[assignment]
        # Should not raise when override is provided
        kex._compute_ecdh_exchange_hash(
            b"hostkey",
            b"serverpub",
            b"sig",
            client_ecdh_public_key=b"\x04" + b"\xbb" * 64,
        )
        assert kex._exchange_hash is not None


# ---------------------------------------------------------------------------
# _compute_exchange_hash guard paths
# ---------------------------------------------------------------------------


class TestComputeExchangeHashGuards:
    def _base_kex(self) -> KeyExchange:
        kex, _ = _make_kex()
        from spindlex.protocol.utils import write_mpint

        kex._shared_secret = write_mpint(99)
        kex._dh_public_key_mpint = write_mpint(42)
        return kex

    def test_raises_when_client_kexinit_is_none(self):
        kex = self._base_kex()
        kex._client_kexinit = None
        kex._server_kexinit = b"\x02" * 16
        with pytest.raises(CryptoException, match="Missing client KEXINIT"):
            kex._compute_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_when_server_kexinit_is_none(self):
        kex = self._base_kex()
        kex._client_kexinit = b"\x01" * 16
        kex._server_kexinit = None
        with pytest.raises(CryptoException, match="Missing server KEXINIT"):
            kex._compute_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_when_client_dh_public_key_mpint_is_none(self):
        kex = self._base_kex()
        _set_kexinit_blobs(kex)
        kex._dh_public_key_mpint = None
        with pytest.raises(CryptoException, match="Missing DH client public key"):
            kex._compute_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_raises_when_shared_secret_is_none(self):
        kex = self._base_kex()
        _set_kexinit_blobs(kex)
        kex._shared_secret = None
        with pytest.raises(CryptoException, match="Missing shared secret"):
            kex._compute_exchange_hash(b"hostkey", b"serverpub", b"sig")

    def test_client_dh_public_mpint_override_works(self):
        """client_dh_public_mpint parameter overrides self._dh_public_key_mpint."""
        from spindlex.protocol.utils import write_mpint

        kex = self._base_kex()
        _set_kexinit_blobs(kex)
        kex._dh_public_key_mpint = None
        kex._compute_exchange_hash(
            b"hostkey",
            write_mpint(100),
            b"sig",
            client_dh_public_mpint=write_mpint(99),
        )
        assert kex._exchange_hash is not None


# ---------------------------------------------------------------------------
# _verify_server_signature failure paths
# ---------------------------------------------------------------------------


class TestVerifyServerSignatureFailurePaths:
    def test_verify_reraises_crypto_exception(self):
        kex, _ = _make_kex()
        kex._exchange_hash = b"\xab" * 32
        with patch(
            "spindlex.crypto.pkey.PKey.from_string",
            side_effect=CryptoException("bad key"),
        ):
            with pytest.raises(CryptoException, match="bad key"):
                kex._verify_server_signature(b"hostkey", b"sig")

    def test_verify_wraps_generic_exception(self):
        kex, _ = _make_kex()
        kex._exchange_hash = b"\xab" * 32
        with patch(
            "spindlex.crypto.pkey.PKey.from_string",
            side_effect=ValueError("malformed"),
        ):
            with pytest.raises(
                CryptoException, match="Failed to verify server signature"
            ):
                kex._verify_server_signature(b"hostkey", b"sig")

    def test_verify_raises_when_signature_check_fails(self):
        kex, _ = _make_kex()
        kex._exchange_hash = b"\xab" * 32
        mock_key = MagicMock()
        mock_key.verify.return_value = False
        with patch("spindlex.crypto.pkey.PKey.from_string", return_value=mock_key):
            with pytest.raises(CryptoException, match="signature verification failed"):
                kex._verify_server_signature(b"hostkey", b"sig")


# ---------------------------------------------------------------------------
# _perform_ecdh — unsupported algorithm guard and exception wrapping
# ---------------------------------------------------------------------------


class TestPerformEcdhGuards:
    def test_unsupported_algorithm_raises_crypto_exception(self):
        """When kex_algorithm is not P256/384/521, _perform_ecdh raises."""
        kex, _ = _make_kex()
        _set_kexinit_blobs(kex)
        kex._kex_algorithm = "unknown-ecdh-algo"
        # The exception is caught and re-wrapped, but CryptoException is the type.
        with pytest.raises(CryptoException):
            kex._perform_ecdh()

    def test_exception_wrapping_includes_curve_label_p384(self):
        """Exception from ECDH for P-384 includes 'P-384' in message."""
        kex, _ = _make_kex()
        _set_kexinit_blobs(kex)
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP384

        with patch(
            "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
            side_effect=RuntimeError("gen fail"),
        ):
            with pytest.raises(CryptoException, match="P-384"):
                kex._perform_ecdh()

    def test_exception_wrapping_includes_curve_label_p521(self):
        """Exception from ECDH for P-521 includes 'P-521' in message."""
        kex, _ = _make_kex()
        _set_kexinit_blobs(kex)
        kex._kex_algorithm = KEX_ECDH_SHA2_NISTP521

        with patch(
            "cryptography.hazmat.primitives.asymmetric.ec.generate_private_key",
            side_effect=RuntimeError("gen fail"),
        ):
            with pytest.raises(CryptoException, match="P-521"):
                kex._perform_ecdh()


# ---------------------------------------------------------------------------
# generate_keys() before key exchange raises CryptoException
# ---------------------------------------------------------------------------


class TestGenerateKeysBeforeKeyExchange:
    def test_raises_if_keys_not_generated(self):
        """generate_keys() before _generate_session_keys() should raise."""
        kex, _ = _make_kex()
        # No _encryption_key_c2s attribute set
        with pytest.raises((CryptoException, AttributeError)):
            kex.generate_keys()

    def test_raises_with_explicit_none_keys(self):
        """When key attributes exist but are falsy, CryptoException is raised."""
        kex, _ = _make_kex()
        kex._encryption_key_c2s = None  # type: ignore[assignment]
        kex._encryption_key_s2c = None  # type: ignore[assignment]
        kex._mac_key_c2s = None  # type: ignore[assignment]
        kex._mac_key_s2c = None  # type: ignore[assignment]
        with pytest.raises(CryptoException, match="Keys not generated"):
            kex.generate_keys()


# ---------------------------------------------------------------------------
# _perform_dh_group14_sha256 — public key <= 0 guard
# ---------------------------------------------------------------------------


class TestDHPublicKeyGuard:
    def test_raises_when_dh_public_key_is_zero(self):
        """If DH public key is 0 (or negative), CryptoException is raised."""
        kex, transport = _make_kex()
        _set_kexinit_blobs(kex)

        # Build a mock DH private key whose public number's y == 0
        mock_priv = MagicMock()
        mock_pub_numbers = MagicMock()
        mock_pub_numbers.y = 0  # <= 0 triggers the guard
        mock_pub = MagicMock()
        mock_pub.public_numbers.return_value = mock_pub_numbers
        mock_priv.public_key.return_value = mock_pub

        with (
            patch("spindlex.transport.kex.dh") as mock_dh_module,
            patch("spindlex.transport.kex.default_backend"),
        ):
            mock_params = MagicMock()
            mock_params.generate_private_key.return_value = mock_priv
            mock_dh_module.DHParameterNumbers.return_value.parameters.return_value = (
                mock_params
            )
            with pytest.raises(CryptoException, match="Invalid DH public key"):
                kex._perform_dh_group14_sha256()
