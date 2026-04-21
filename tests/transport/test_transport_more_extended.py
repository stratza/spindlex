import socket
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import AuthenticationException
from spindlex.protocol.constants import *
from spindlex.protocol.messages import (
    ChannelDataMessage,
    ChannelOpenConfirmationMessage,
    ChannelOpenFailureMessage,
    ChannelOpenMessage,
    Message,
)
from spindlex.transport.transport import Transport


@pytest.fixture
def mock_socket():
    sock = MagicMock(spec=socket.socket)
    sock.gettimeout.return_value = 30
    return sock


@pytest.fixture
def transport(mock_socket):
    t = Transport(mock_socket)
    t._active = True
    t._authenticated = True
    return t


def test_transport_auth_keyboard_interactive(transport):
    with patch(
        "spindlex.auth.keyboard_interactive.KeyboardInteractiveAuth"
    ) as mock_auth_cls:
        mock_auth = mock_auth_cls.return_value
        mock_auth.authenticate.return_value = True

        with patch.object(transport, "_request_userauth_service"):
            with patch.object(transport, "_send_message"):
                transport._authenticated = False
                res = transport.auth_keyboard_interactive("alice", lambda x: "y")
                assert res is True
                assert transport.authenticated is True


def test_transport_auth_gssapi_not_available(transport):
    # This should raise AuthenticationException due to ImportError in the code
    with patch.dict("sys.modules", {"spindlex.auth.gssapi": None}):
        transport._authenticated = False
        with pytest.raises(
            AuthenticationException, match="GSSAPI authentication not available"
        ):
            transport.auth_gssapi("alice")


def test_transport_open_channel_direct_tcpip(transport):
    with patch.object(transport, "_expect_message") as mock_expect:
        mock_expect.return_value = ChannelOpenConfirmationMessage(0, 10, 1024, 512)

        channel = transport.open_channel(CHANNEL_DIRECT_TCPIP, ("1.2.3.4", 80))
        assert channel._remote_channel_id == 10
        assert transport._channels[0] == channel


def test_transport_handle_channel_message_data(transport):
    channel = MagicMock()
    transport._channels[1] = channel

    # MSG_CHANNEL_DATA message
    msg = ChannelDataMessage(1, b"hello")
    transport._handle_channel_message(msg)
    channel._handle_data.assert_called_with(b"hello")


def test_transport_handle_channel_message_eof_close(transport):
    channel = MagicMock()
    transport._channels[1] = channel

    # EOF
    msg = Message(MSG_CHANNEL_EOF)
    msg._data = b"\x00\x00\x00\x01"  # recipient channel 1
    transport._handle_channel_message(msg)
    channel._handle_eof.assert_called_once()

    # CLOSE
    msg = Message(MSG_CHANNEL_CLOSE)
    msg._data = b"\x00\x00\x00\x01"
    transport._handle_channel_message(msg)
    channel._handle_close.assert_called_once()
    assert 1 not in transport._channels


def test_transport_close_channel(transport):
    channel = MagicMock()
    channel.closed = False
    channel._remote_channel_id = 10
    transport._channels[1] = channel

    with patch.object(transport, "_send_message") as mock_send:
        transport._close_channel(1)
        assert mock_send.called
        assert 1 not in transport._channels


def test_transport_handle_global_request(transport):
    with patch.object(transport, "_handle_global_request") as mock_handle:
        msg = Message(MSG_GLOBAL_REQUEST)
        transport._handle_channel_message(msg)
        mock_handle.assert_called_with(msg)


def test_transport_handle_forwarded_tcpip_open(transport):
    # Channel type specified in message
    msg = ChannelOpenMessage(
        channel_type=CHANNEL_FORWARDED_TCPIP,
        sender_channel=20,
        initial_window_size=1024,
        maximum_packet_size=512,
        type_specific_data=(
            b"\x00\x00\x00\x09localhost"  # connected address
            + b"\x00\x00\x00\x50"  # connected port 80
            + b"\x00\x00\x00\x09127.0.0.1"  # originator address
            + b"\x00\x00\x00\x00"  # originator port
        ),
    )

    with patch.object(transport, "_send_message") as mock_send:
        transport._handle_channel_open(msg)

        # Should have sent confirmation
        sent_msg = mock_send.call_args[0][0]
        assert isinstance(sent_msg, ChannelOpenConfirmationMessage)
        assert sent_msg.recipient_channel == 20
        assert 0 in transport._channels


def test_transport_handle_unknown_channel_open(transport):
    msg = ChannelOpenMessage(
        channel_type="unknown-type",
        sender_channel=20,
        initial_window_size=1024,
        maximum_packet_size=512,
        type_specific_data=b"",
    )

    with patch.object(transport, "_send_message") as mock_send:
        transport._handle_channel_open(msg)

        sent_msg = mock_send.call_args[0][0]
        assert isinstance(sent_msg, ChannelOpenFailureMessage)
        assert sent_msg.reason_code == SSH_OPEN_UNKNOWN_CHANNEL_TYPE


def test_transport_auth_password_already_auth(transport):
    res = transport.auth_password("alice", "pass")
    assert res is True  # already auth


def test_transport_auth_publickey_already_auth(transport):
    res = transport.auth_publickey("alice", MagicMock())
    assert res is True
