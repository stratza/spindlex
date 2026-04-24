from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import AuthenticationException
from spindlex.protocol.constants import (
    MSG_CHANNEL_DATA,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_SUCCESS,
)
from spindlex.protocol.messages import (
    ChannelDataMessage,
    Message,
    UserAuthFailureMessage,
    UserAuthSuccessMessage,
)
from spindlex.protocol.utils import write_boolean, write_string, write_uint32
from spindlex.transport.async_transport import AsyncTransport
from spindlex.transport.transport import Transport


def test_handle_auth_response_message_success():
    sock = MagicMock()
    transport = Transport(sock)
    msg = UserAuthSuccessMessage()
    assert transport._handle_auth_response_message(msg) is True


def test_handle_auth_response_message_failure():
    sock = MagicMock()
    transport = Transport(sock)
    msg = UserAuthFailureMessage(authentications=["password"], partial_success=False)
    assert transport._handle_auth_response_message(msg) is False


def test_handle_auth_response_message_partial_success():
    sock = MagicMock()
    transport = Transport(sock)
    msg = UserAuthFailureMessage(
        authentications=["publickey", "password"], partial_success=True
    )
    with pytest.raises(
        AuthenticationException,
        match="Partial success - additional methods required: publickey, password",
    ):
        transport._handle_auth_response_message(msg)


def test_handle_auth_response_message_reunpack_path():
    sock = MagicMock()
    transport = Transport(sock)
    # Create a generic message with type MSG_USERAUTH_FAILURE
    msg = Message(msg_type=MSG_USERAUTH_FAILURE)
    # Manually pack a UserAuthFailureMessage data
    data = bytearray()
    data.extend(write_string("password"))
    data.extend(write_boolean(False))
    msg._data = bytes(data)

    # This should trigger the "if not isinstance(msg, UserAuthFailureMessage)" path
    assert transport._handle_auth_response_message(msg) is False


def test_handle_channel_message_data_reunpack_path():
    sock = MagicMock()
    transport = Transport(sock)

    # Mock a channel
    channel = MagicMock()
    transport._channels[1] = channel

    # Create a generic message with type MSG_CHANNEL_DATA
    msg = Message(msg_type=MSG_CHANNEL_DATA)

    data = bytearray()
    data.extend(write_uint32(1))  # recipient channel
    data.extend(write_string("some data"))
    msg._data = bytes(data)

    # This should trigger the "if not isinstance(msg, ChannelDataMessage)" path
    # inside _handle_channel_message
    transport._handle_channel_message(msg)

    channel._handle_data.assert_called_with(b"some data")


def test_handle_channel_message_data_isinstance():
    sock = MagicMock()
    transport = Transport(sock)

    # Mock a channel
    channel = MagicMock()
    transport._channels[1] = channel

    msg = ChannelDataMessage(recipient_channel=1, data=b"more data")

    transport._handle_channel_message(msg)
    channel._handle_data.assert_called_with(b"more data")


def test_expect_message_with_optional_channel_id():
    sock = MagicMock()
    transport = Transport(sock)

    # Mock _read_message to return a success message
    msg = UserAuthSuccessMessage()
    with patch.object(Transport, "_read_message", return_value=msg):
        # Test with channel_id=None (default)
        res = transport._expect_message(MSG_USERAUTH_SUCCESS)
        assert res == msg

        # Test with explicit channel_id
        transport._message_queue.append(msg)
        res = transport._expect_message(MSG_USERAUTH_SUCCESS, channel_id=None)
        assert res == msg


@pytest.mark.asyncio
async def test_async_expect_message_with_optional_channel_id():
    sock = MagicMock()
    # AsyncTransport constructor might need a running loop or mock it
    with patch("asyncio.get_event_loop", return_value=MagicMock()):
        transport = AsyncTransport(sock)

        # Mock _recv_message_async to return a success message
        msg = UserAuthSuccessMessage()
        with patch.object(AsyncTransport, "_recv_message_async", return_value=msg):
            # Test with channel_id=None (default)
            res = await transport._expect_message_async(MSG_USERAUTH_SUCCESS)
            assert res == msg

            # Test with explicit channel_id=None
            transport._message_queue.append(msg)
            res = await transport._expect_message_async(
                MSG_USERAUTH_SUCCESS, channel_id=None
            )
            assert res == msg
