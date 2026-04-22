from unittest.mock import AsyncMock, MagicMock

import pytest

from spindlex.auth.keyboard_interactive import (
    AsyncKeyboardInteractiveAuth,
    KeyboardInteractiveAuth,
    console_handler,
)
from spindlex.exceptions import AuthenticationException
from spindlex.protocol.constants import (
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_INFO_REQUEST,
    MSG_USERAUTH_SUCCESS,
)
from spindlex.protocol.messages import (
    UserAuthFailureMessage,
    UserAuthInfoRequestMessage,
    UserAuthInfoResponseMessage,
    UserAuthSuccessMessage,
)


class TestKeyboardInteractiveAuth:
    def test_authenticate_success(self):
        transport = MagicMock()
        # Mock success message
        transport._expect_message.return_value = UserAuthSuccessMessage()

        auth = KeyboardInteractiveAuth(transport)
        handler = MagicMock(return_value=["response1"])

        assert auth.authenticate("alice", handler) is True
        transport._expect_message.assert_called_with(
            MSG_USERAUTH_SUCCESS,
            MSG_USERAUTH_FAILURE,
            MSG_USERAUTH_INFO_REQUEST,
        )

    def test_authenticate_failure(self):
        transport = MagicMock()
        # Mock failure message
        transport._expect_message.return_value = UserAuthFailureMessage(
            authentications=["password"], partial_success=False
        )

        auth = KeyboardInteractiveAuth(transport)
        handler = MagicMock()

        assert auth.authenticate("alice", handler) is False

    def test_authenticate_partial_success(self):
        transport = MagicMock()
        # Mock partial success message
        transport._expect_message.return_value = UserAuthFailureMessage(
            authentications=["publickey"], partial_success=True
        )

        auth = KeyboardInteractiveAuth(transport)
        handler = MagicMock()

        with pytest.raises(AuthenticationException, match="Partial success"):
            auth.authenticate("alice", handler)

    def test_authenticate_with_info_request(self):
        transport = MagicMock()

        # 1. Info Request
        info_req = UserAuthInfoRequestMessage(
            name="Title",
            instruction="Instruction",
            language="en-US",
            prompts=[("Password: ", False)],
        )
        # We need to set the msg_type and _data correctly for unpack
        info_req_msg = MagicMock()
        info_req_msg.msg_type = MSG_USERAUTH_INFO_REQUEST
        # Generic Message.unpack returns payload[1:], so _data should not have the type byte
        info_req_msg._data = info_req._data

        # 2. Success
        success_msg = UserAuthSuccessMessage()

        transport._expect_message.side_effect = [info_req_msg, success_msg]

        auth = KeyboardInteractiveAuth(transport)
        handler = MagicMock(return_value=["secret"])

        assert auth.authenticate("alice", handler) is True

        # Verify handler called
        handler.assert_called_with("Title", "Instruction", [("Password: ", False)])

        # Verify response sent
        sent_msg = transport._send_message.call_args[0][0]
        assert isinstance(sent_msg, UserAuthInfoResponseMessage)
        assert sent_msg.responses == ["secret"]


class TestAsyncKeyboardInteractiveAuth:
    @pytest.mark.asyncio
    async def test_authenticate_async_success(self):
        transport = AsyncMock()
        transport._expect_message_async.return_value = UserAuthSuccessMessage()

        auth = AsyncKeyboardInteractiveAuth(transport)
        handler = AsyncMock(return_value=["response1"])

        assert await auth.authenticate_async("alice", handler) is True

    @pytest.mark.asyncio
    async def test_authenticate_async_with_info_request(self):
        transport = AsyncMock()

        info_req = UserAuthInfoRequestMessage(
            name="Title",
            instruction="Instruction",
            language="en-US",
            prompts=[("OTP: ", True)],
        )
        info_req_msg = MagicMock()
        info_req_msg.msg_type = MSG_USERAUTH_INFO_REQUEST
        # Generic Message.unpack returns payload[1:], so _data should not have the type byte
        info_req_msg._data = info_req._data

        success_msg = UserAuthSuccessMessage()

        transport._expect_message_async.side_effect = [info_req_msg, success_msg]

        auth = AsyncKeyboardInteractiveAuth(transport)

        # Test with async handler
        async def async_handler(name, inst, prompts):
            return ["123456"]

        assert await auth.authenticate_async("alice", async_handler) is True

        # Verify response sent
        sent_msg = transport._send_message_async.call_args[0][0]
        assert isinstance(sent_msg, UserAuthInfoResponseMessage)
        assert sent_msg.responses == ["123456"]

    @pytest.mark.asyncio
    async def test_authenticate_async_with_sync_handler(self):
        transport = AsyncMock()

        info_req = UserAuthInfoRequestMessage(
            name="Title",
            instruction="Instruction",
            language="en-US",
            prompts=[("OTP: ", True)],
        )
        info_req_msg = MagicMock()
        info_req_msg.msg_type = MSG_USERAUTH_INFO_REQUEST
        # Generic Message.unpack returns payload[1:], so _data should not have the type byte
        info_req_msg._data = info_req._data

        success_msg = UserAuthSuccessMessage()

        transport._expect_message_async.side_effect = [info_req_msg, success_msg]

        auth = AsyncKeyboardInteractiveAuth(transport)

        # Test with sync handler
        def sync_handler(name, inst, prompts):
            return ["654321"]

        assert await auth.authenticate_async("alice", sync_handler) is True

        # Verify response sent
        sent_msg = transport._send_message_async.call_args[0][0]
        assert isinstance(sent_msg, UserAuthInfoResponseMessage)
        assert sent_msg.responses == ["654321"]


def test_console_handler():
    with pytest.raises(
        NotImplementedError, match="Interactive console handler is disabled by default"
    ):
        console_handler("My Title", "My Instruction", [("Username: ", True)])
