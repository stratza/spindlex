import socket
import struct
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import *
from spindlex.protocol.constants import *
from spindlex.protocol.messages import *
from spindlex.transport.transport import Transport


def _make_sock():
    s = MagicMock(spec=socket.socket)
    s.fileno.return_value = 3
    return s


def _make_transport(**kw):
    t = Transport(_make_sock())
    for k, v in kw.items():
        setattr(t, k, v)
    return t


class TestTransportCoverage:
    def test_auth_password_success(self):
        t = _make_transport(_active=True, _authenticated=False)
        msg = Message(MSG_USERAUTH_SUCCESS)
        with patch.object(t, "_request_userauth_service"):
            with patch("spindlex.auth.password.PasswordAuth") as mock_auth:
                mock_auth.return_value.authenticate.return_value = msg
                assert t.auth_password("user", "pass") is True
                assert t._authenticated is True

    def test_auth_publickey_success(self):
        t = _make_transport(_active=True, _authenticated=False)
        msg = Message(MSG_USERAUTH_SUCCESS)
        key = MagicMock()
        with patch.object(t, "_request_userauth_service"):
            with patch("spindlex.auth.publickey.PublicKeyAuth") as mock_auth:
                mock_auth.return_value.authenticate.return_value = msg
                assert t.auth_publickey("user", key) is True
                assert t._authenticated is True

    def test_handle_channel_success(self):
        t = _make_transport()
        chan = MagicMock()
        t._channels[1] = chan
        msg = MagicMock()
        msg._data = struct.pack(">I", 1)
        t._handle_channel_success(msg)
        chan._handle_request_success.assert_called_once()

    def test_handle_channel_failure(self):
        t = _make_transport()
        chan = MagicMock()
        t._channels[1] = chan
        msg = MagicMock()
        msg._data = struct.pack(">I", 1)
        t._handle_channel_failure(msg)
        chan._handle_request_failure.assert_called_once()

    def test_handle_auth_response_success(self):
        t = _make_transport()
        msg = Message(MSG_USERAUTH_SUCCESS)
        assert t._handle_auth_response_message(msg) is True
        assert t._authenticated is True

    def test_handle_auth_response_failure(self):
        t = _make_transport()
        msg = UserAuthFailureMessage(["password"], False)
        assert t._handle_auth_response_message(msg) is False
        assert t._authenticated is False

    def test_handle_auth_response_unexpected(self):
        t = _make_transport()
        msg = Message(MSG_IGNORE)
        with pytest.raises(
            AuthenticationException, match="Unexpected authentication response"
        ):
            t._handle_auth_response_message(msg)

    def test_handle_channel_window_adjust(self):
        t = _make_transport()
        chan = MagicMock()
        t._channels[1] = chan
        msg = MagicMock()
        msg._data = struct.pack(">II", 1, 1000)  # recipient 1, adjust 1000
        t._handle_channel_window_adjust(msg)
        chan._handle_window_adjust.assert_called_with(1000)

    def test_handle_channel_data(self):
        t = _make_transport()
        chan = MagicMock()
        t._channels[1] = chan
        msg = ChannelDataMessage(1, b"some data")
        t._handle_channel_data(msg)
        chan._handle_data.assert_called_with(b"some data")

    def test_handle_channel_extended_data(self):
        t = _make_transport()
        chan = MagicMock()
        t._channels[1] = chan
        msg = MagicMock()
        # Extended data: recipient(4) + type(4) + length-prefixed string
        payload = b"stderr data"
        msg._data = struct.pack(">II", 1, 1) + struct.pack(">I", len(payload)) + payload
        t._handle_channel_extended_data(msg)
        chan._handle_extended_data.assert_called_with(1, b"stderr data")

    def test_handle_channel_eof(self):
        t = _make_transport()
        chan = MagicMock()
        t._channels[1] = chan
        msg = MagicMock()
        msg._data = struct.pack(">I", 1)
        t._handle_channel_eof(msg)
        chan._handle_eof.assert_called_once()

    def test_handle_channel_close(self):
        t = _make_transport()
        chan = MagicMock()
        t._channels[1] = chan
        msg = ChannelCloseMessage(1)
        t._handle_channel_close(msg)
        chan._handle_close.assert_called_once()
