"""
Unit tests for:
  - spindlex/auth/publickey.py  (PublicKeyAuth)
  - spindlex/auth/password.py   (PasswordAuth)

All tests are mock-based — no real SSH connections are made.
asyncio_mode = "auto" is configured project-wide so individual async tests
do NOT need @pytest.mark.asyncio.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from spindlex.auth.password import PasswordAuth
from spindlex.auth.publickey import PublicKeyAuth
from spindlex.exceptions import AuthenticationException
from spindlex.protocol.constants import (
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_PK_OK,
    MSG_USERAUTH_SUCCESS,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_mock_key(algorithm: str = "ssh-ed25519") -> MagicMock:
    key = MagicMock()
    key.algorithm_name = algorithm
    key.get_public_key_bytes.return_value = b"pubkeydata"
    key.sign.return_value = b"fakesignature"
    return key


def _success_msg() -> MagicMock:
    m = MagicMock()
    m.msg_type = MSG_USERAUTH_SUCCESS
    return m


def _failure_msg() -> MagicMock:
    m = MagicMock()
    m.msg_type = MSG_USERAUTH_FAILURE
    return m


def _pk_ok_msg() -> MagicMock:
    m = MagicMock()
    m.msg_type = MSG_USERAUTH_PK_OK
    return m


def make_pubkey_auth() -> tuple[PublicKeyAuth, MagicMock]:
    transport = MagicMock()
    transport.session_id = b"\x00" * 32
    auth = PublicKeyAuth(transport)
    return auth, transport


def make_password_auth() -> tuple[PasswordAuth, MagicMock]:
    transport = MagicMock()
    auth = PasswordAuth(transport)
    return auth, transport


# ===========================================================================
# PublicKeyAuth
# ===========================================================================


class TestPublicKeyAuthInit:
    def test_stores_transport(self):
        auth, transport = make_pubkey_auth()
        assert auth._transport is transport


class TestGetMethodData:
    def test_query_mode_no_signature(self):
        auth, _ = make_pubkey_auth()
        key = make_mock_key()
        data = auth.get_method_data(key, is_query=True)
        # Query → boolean False (0x00)
        assert isinstance(data, bytes)
        # First byte is the write_boolean(False) = \x00
        assert data[0] == 0x00

    def test_full_auth_mode_has_signature(self):
        auth, _ = make_pubkey_auth()
        key = make_mock_key()
        data = auth.get_method_data(key, is_query=False, signature=b"sig")
        # Full auth → boolean True (0x01)
        assert data[0] == 0x01
        # Signature bytes must appear somewhere in the payload
        assert b"sig" in data

    def test_query_does_not_include_signature(self):
        auth, _ = make_pubkey_auth()
        key = make_mock_key()
        data = auth.get_method_data(key, is_query=True, signature=b"NOPE")
        assert b"NOPE" not in data

    def test_method_data_includes_algorithm_name(self):
        auth, _ = make_pubkey_auth()
        key = make_mock_key("ssh-ed25519")
        data = auth.get_method_data(key, is_query=True)
        assert b"ssh-ed25519" in data

    def test_method_data_includes_public_key_bytes(self):
        auth, _ = make_pubkey_auth()
        key = make_mock_key()
        data = auth.get_method_data(key, is_query=True)
        assert b"pubkeydata" in data


class TestPublicKeyAuthAuthenticate:
    def test_failure_on_first_query_returns_early(self):
        auth, transport = make_pubkey_auth()
        transport._expect_message.return_value = _failure_msg()

        key = make_mock_key()
        result = auth.authenticate("alice", key)

        assert result.msg_type == MSG_USERAUTH_FAILURE
        # Only one message sent (the query)
        transport._send_message.assert_called_once()

    def test_pk_ok_proceeds_to_full_auth_success(self):
        auth, transport = make_pubkey_auth()
        # First call: PK_OK; second call: SUCCESS
        transport._expect_message.side_effect = [_pk_ok_msg(), _success_msg()]

        key = make_mock_key()
        result = auth.authenticate("alice", key)

        assert result.msg_type == MSG_USERAUTH_SUCCESS
        assert transport._send_message.call_count == 2
        # Key.sign must have been called exactly once
        key.sign.assert_called_once()

    def test_pk_ok_then_failure_returns_failure_msg(self):
        auth, transport = make_pubkey_auth()
        transport._expect_message.side_effect = [_pk_ok_msg(), _failure_msg()]

        key = make_mock_key()
        result = auth.authenticate("alice", key)

        assert result.msg_type == MSG_USERAUTH_FAILURE

    def test_transport_exception_wrapped_as_auth_exception(self):
        auth, transport = make_pubkey_auth()
        transport._send_message.side_effect = OSError("network error")

        key = make_mock_key()
        with pytest.raises(
            AuthenticationException, match="Public key authentication failed"
        ):
            auth.authenticate("alice", key)

    def test_auth_exception_propagated_unchanged(self):
        auth, transport = make_pubkey_auth()
        transport._send_message.side_effect = AuthenticationException("direct fail")

        key = make_mock_key()
        with pytest.raises(AuthenticationException, match="direct fail"):
            auth.authenticate("alice", key)

    def test_signature_built_with_correct_username(self):
        """The signed blob must contain the username."""
        auth, transport = make_pubkey_auth()
        transport._expect_message.side_effect = [_pk_ok_msg(), _success_msg()]

        key = make_mock_key()
        auth.authenticate("testuser", key)

        signed_data: bytes = key.sign.call_args[0][0]
        assert b"testuser" in signed_data

    def test_first_message_sent_is_query(self):
        """First _send_message call must be a UserAuthRequestMessage with query data."""
        auth, transport = make_pubkey_auth()
        transport._expect_message.return_value = _failure_msg()

        key = make_mock_key()
        auth.authenticate("alice", key)

        from spindlex.protocol.messages import UserAuthRequestMessage

        sent_msg = transport._send_message.call_args[0][0]
        assert isinstance(sent_msg, UserAuthRequestMessage)


class TestPublicKeyAuthAuthenticateAsync:
    async def test_async_failure_on_query_returns_early(self):
        auth, transport = make_pubkey_auth()
        transport._send_message_async = AsyncMock()
        transport._expect_message_async = AsyncMock(return_value=_failure_msg())

        key = make_mock_key()
        result = await auth.authenticate_async("alice", key)

        assert result.msg_type == MSG_USERAUTH_FAILURE
        transport._send_message_async.assert_called_once()

    async def test_async_pk_ok_leads_to_success(self):
        auth, transport = make_pubkey_auth()
        transport._send_message_async = AsyncMock()
        transport._expect_message_async = AsyncMock(
            side_effect=[_pk_ok_msg(), _success_msg()]
        )

        key = make_mock_key()
        result = await auth.authenticate_async("alice", key)

        assert result.msg_type == MSG_USERAUTH_SUCCESS
        assert transport._send_message_async.call_count == 2

    async def test_async_transport_error_wrapped(self):
        auth, transport = make_pubkey_auth()
        transport._send_message_async = AsyncMock(side_effect=OSError("broken"))

        key = make_mock_key()
        with pytest.raises(
            AuthenticationException, match="Public key authentication failed"
        ):
            await auth.authenticate_async("alice", key)

    async def test_async_auth_exception_propagated(self):
        auth, transport = make_pubkey_auth()
        transport._send_message_async = AsyncMock(
            side_effect=AuthenticationException("direct")
        )

        key = make_mock_key()
        with pytest.raises(AuthenticationException, match="direct"):
            await auth.authenticate_async("alice", key)

    async def test_async_pk_ok_then_failure(self):
        auth, transport = make_pubkey_auth()
        transport._send_message_async = AsyncMock()
        transport._expect_message_async = AsyncMock(
            side_effect=[_pk_ok_msg(), _failure_msg()]
        )

        key = make_mock_key()
        result = await auth.authenticate_async("alice", key)
        assert result.msg_type == MSG_USERAUTH_FAILURE


# ===========================================================================
# PasswordAuth
# ===========================================================================


class TestPasswordAuthInit:
    def test_stores_transport(self):
        auth, transport = make_password_auth()
        assert auth._transport is transport


class TestPasswordAuthAuthenticate:
    def test_success_returns_success_message(self):
        auth, transport = make_password_auth()
        transport._expect_message.return_value = _success_msg()

        result = auth.authenticate("bob", "s3cr3t")

        assert result.msg_type == MSG_USERAUTH_SUCCESS
        transport._send_message.assert_called_once()

    def test_failure_returns_failure_message(self):
        auth, transport = make_password_auth()
        transport._expect_message.return_value = _failure_msg()

        result = auth.authenticate("bob", "wrong")

        assert result.msg_type == MSG_USERAUTH_FAILURE

    def test_send_message_called_with_userauth_request(self):
        auth, transport = make_password_auth()
        transport._expect_message.return_value = _success_msg()

        auth.authenticate("alice", "pass")

        from spindlex.protocol.messages import UserAuthRequestMessage

        sent = transport._send_message.call_args[0][0]
        assert isinstance(sent, UserAuthRequestMessage)

    def test_method_is_password(self):
        auth, transport = make_password_auth()
        transport._expect_message.return_value = _success_msg()

        auth.authenticate("alice", "mypass")

        sent = transport._send_message.call_args[0][0]
        assert sent.method == "password"

    def test_method_data_starts_with_false_byte(self):
        """Per RFC 4252 password auth payload: FALSE + string password."""
        auth, transport = make_password_auth()
        transport._expect_message.return_value = _success_msg()

        auth.authenticate("alice", "pw")
        sent = transport._send_message.call_args[0][0]
        assert sent.method_data[0:1] == b"\x00"

    def test_transport_exception_wrapped(self):
        auth, transport = make_password_auth()
        transport._send_message.side_effect = ConnectionResetError("disconnected")

        with pytest.raises(
            AuthenticationException, match="Password authentication failed"
        ):
            auth.authenticate("alice", "pw")

    def test_auth_exception_propagated(self):
        auth, transport = make_password_auth()
        transport._send_message.side_effect = AuthenticationException("denied")

        with pytest.raises(AuthenticationException, match="denied"):
            auth.authenticate("alice", "pw")


class TestPasswordAuthAuthenticateAsync:
    async def test_async_success(self):
        auth, transport = make_password_auth()
        transport._send_message_async = AsyncMock()
        transport._expect_message_async = AsyncMock(return_value=_success_msg())

        result = await auth.authenticate_async("carol", "pw")
        assert result.msg_type == MSG_USERAUTH_SUCCESS

    async def test_async_failure(self):
        auth, transport = make_password_auth()
        transport._send_message_async = AsyncMock()
        transport._expect_message_async = AsyncMock(return_value=_failure_msg())

        result = await auth.authenticate_async("carol", "wrongpw")
        assert result.msg_type == MSG_USERAUTH_FAILURE

    async def test_async_transport_error_wrapped(self):
        auth, transport = make_password_auth()
        transport._send_message_async = AsyncMock(side_effect=OSError("gone"))

        with pytest.raises(
            AuthenticationException, match="Password authentication failed"
        ):
            await auth.authenticate_async("carol", "pw")

    async def test_async_auth_exception_propagated(self):
        auth, transport = make_password_auth()
        transport._send_message_async = AsyncMock(
            side_effect=AuthenticationException("locked out")
        )

        with pytest.raises(AuthenticationException, match="locked out"):
            await auth.authenticate_async("carol", "pw")

    async def test_async_sends_userauth_request(self):
        auth, transport = make_password_auth()
        transport._send_message_async = AsyncMock()
        transport._expect_message_async = AsyncMock(return_value=_success_msg())

        await auth.authenticate_async("dave", "pw")
        transport._send_message_async.assert_called_once()

        from spindlex.protocol.messages import UserAuthRequestMessage

        sent = transport._send_message_async.call_args[0][0]
        assert isinstance(sent, UserAuthRequestMessage)
