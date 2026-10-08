import sys
from unittest.mock import MagicMock, patch

import pytest

# Mock GSSAPI modules before they are used
mock_gssapi = MagicMock()
sys.modules["gssapi"] = mock_gssapi
sys.modules["gssapi.raw"] = MagicMock()

from spindlex.auth.gssapi import GSSAPIAuth  # noqa: E402


@pytest.fixture
def mock_transport():
    transport = MagicMock()
    transport.active = True
    transport.authenticated = False
    transport._userauth_service_requested = True
    return transport


def test_gssapi_auth_success(mock_transport):
    with patch("spindlex.auth.gssapi.GSSAPI_AVAILABLE", True):
        # Patch specifically the classes that the module uses
        with patch("spindlex.auth.gssapi.Credentials"):
            with patch("spindlex.auth.gssapi.SecurityContext") as mock_ctx_cls:
                with patch("spindlex.auth.gssapi.Name"):
                    mock_ctx = mock_ctx_cls.return_value
                    mock_ctx.complete = True

                    auth = GSSAPIAuth(mock_transport)

                    with patch.object(
                        auth, "_perform_gssapi_exchange", return_value=True
                    ):
                        res = auth.authenticate("alice")
                        assert res is True


def test_gssapi_auth_handshake_fail(mock_transport):
    with patch("spindlex.auth.gssapi.GSSAPI_AVAILABLE", True):
        with patch("spindlex.auth.gssapi.Credentials", MagicMock()):
            with patch("spindlex.auth.gssapi.SecurityContext", MagicMock()):
                with patch("spindlex.auth.gssapi.Name", MagicMock()):
                    auth = GSSAPIAuth(mock_transport)
                    with patch.object(
                        auth, "_perform_gssapi_exchange", return_value=False
                    ):
                        res = auth.authenticate("alice")
                        assert res is False


# ---- RFC 4462 exchange against a scripted server ----

from spindlex.protocol.constants import (  # noqa: E402
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_GSSAPI_MIC,
    MSG_USERAUTH_GSSAPI_RESPONSE,
    MSG_USERAUTH_GSSAPI_TOKEN,
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_SUCCESS,
)
from spindlex.protocol.messages import Message  # noqa: E402
from spindlex.protocol.utils import write_string  # noqa: E402


def _msg(msg_type, payload=b""):
    m = Message(msg_type)
    m._data.extend(payload)
    return m


class _ScriptedTransport:
    def __init__(self, replies):
        self.replies = list(replies)
        self.sent = []
        self.session_id = b"SESSION"
        self._authenticated = False

    def _send_message(self, msg):
        self.sent.append(msg)

    def _expect_message(self, *types):
        reply = self.replies.pop(0)
        assert reply.msg_type in types, (reply.msg_type, types)
        return reply


class _FakeContext:
    """Needs one round trip: first step emits a token, second completes."""

    def __init__(self):
        self.complete = False
        self.steps = []
        self.signed = None

    def step(self, token):
        self.steps.append(token)
        if token is None:
            return b"client-token-1"
        self.complete = True
        return b"client-token-2"

    def get_signature(self, data):
        self.signed = data
        return b"MIC"


def _run(replies):
    transport = _ScriptedTransport(replies)
    auth = GSSAPIAuth(transport)
    auth._gss_context = _FakeContext()
    return auth, transport, auth._perform_gssapi_exchange("alice")


def test_gssapi_exchange_follows_rfc4462():
    oid = GSSAPIAuth._KRB5_OID
    auth, transport, result = _run(
        [
            _msg(MSG_USERAUTH_GSSAPI_RESPONSE, write_string(oid)),
            _msg(MSG_USERAUTH_GSSAPI_TOKEN, write_string(b"server-token")),
            _msg(MSG_USERAUTH_SUCCESS),
        ]
    )
    assert result is True
    assert transport._authenticated is True
    assert [m.msg_type for m in transport.sent] == [
        MSG_USERAUTH_REQUEST,  # mechanism list only - no token
        MSG_USERAUTH_GSSAPI_TOKEN,
        MSG_USERAUTH_GSSAPI_TOKEN,
        MSG_USERAUTH_GSSAPI_MIC,
    ]
    assert auth._gss_context.steps == [None, b"server-token"]
    # The MIC covers session id, USERAUTH_REQUEST, user, service and method.
    assert auth._gss_context.signed == (
        write_string(b"SESSION")
        + bytes([MSG_USERAUTH_REQUEST])
        + write_string("alice")
        + write_string("ssh-connection")
        + write_string("gssapi-with-mic")
    )


def test_gssapi_success_requires_server_confirmation():
    oid = GSSAPIAuth._KRB5_OID
    _, transport, result = _run(
        [
            _msg(MSG_USERAUTH_GSSAPI_RESPONSE, write_string(oid)),
            _msg(MSG_USERAUTH_GSSAPI_TOKEN, write_string(b"server-token")),
            _msg(MSG_USERAUTH_FAILURE, write_string("publickey") + b"\x00"),
        ]
    )
    assert result is False
    assert transport._authenticated is False


def test_gssapi_mechanism_refused():
    _, transport, result = _run(
        [_msg(MSG_USERAUTH_FAILURE, write_string("publickey") + b"\x00")]
    )
    assert result is False
    assert [m.msg_type for m in transport.sent] == [MSG_USERAUTH_REQUEST]
