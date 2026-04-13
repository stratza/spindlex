from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from spindlex.auth.keyboard_interactive import (
    AsyncKeyboardInteractiveAuth,
    KeyboardInteractiveAuth,
    console_handler,
)
from spindlex.exceptions import AuthenticationException
from spindlex.protocol.messages import (
    UserAuthFailureMessage,
    UserAuthInfoResponseMessage,
    UserAuthSuccessMessage,
)


def test_keyboard_interactive_auth_success():
    transport = MagicMock()
    # Mock sequence of messages: Request -> Success
    transport._expect_message.side_effect = [UserAuthSuccessMessage()]

    auth = KeyboardInteractiveAuth(transport)

    def handler(name, instruction, prompts):
        return []

    assert auth.authenticate("alice", handler) is True


def test_keyboard_interactive_auth_failure():
    transport = MagicMock()
    # Mock sequence of messages: Request -> Failure
    transport._expect_message.side_effect = [
        UserAuthFailureMessage(authentications=["password"], partial_success=False)
    ]

    auth = KeyboardInteractiveAuth(transport)

    def handler(name, instruction, prompts):
        return []

    assert auth.authenticate("alice", handler) is False


def test_keyboard_interactive_auth_loop():
    transport = MagicMock()

    # Create an info request message
    # We need to craft the raw data for InfoRequestMessage.unpack if we use it,
    # but the code uses InfoRequestMessage.unpack(msg._data)
    info_req_msg = MagicMock()
    info_req_msg.msg_type = 60
    info_req_msg._data = b"dummy"

    # Mock InfoRequestMessage.unpack to return a usable object
    info_req = MagicMock()
    info_req.name = "Title"
    info_req.instruction = "Inst"
    info_req.prompts = [("Password:", False)]

    with patch(
        "spindlex.auth.keyboard_interactive.UserAuthInfoRequestMessage.unpack",
        return_value=info_req,
    ):
        # Loop: InfoRequest -> Success
        transport._expect_message.side_effect = [info_req_msg, UserAuthSuccessMessage()]

        auth = KeyboardInteractiveAuth(transport)

        def handler(name, instruction, prompts):
            assert name == "Title"
            assert instruction == "Inst"
            return ["secret"]

        assert auth.authenticate("alice", handler) is True

        # Verify response was sent
        assert transport._send_message.called
        sent_msg = transport._send_message.call_args[0][0]
        assert isinstance(sent_msg, UserAuthInfoResponseMessage)
        assert sent_msg.responses == ["secret"]


def test_keyboard_interactive_partial_success():
    transport = MagicMock()
    transport._expect_message.side_effect = [
        UserAuthFailureMessage(authentications=["publickey"], partial_success=True)
    ]

    auth = KeyboardInteractiveAuth(transport)
    with pytest.raises(AuthenticationException, match="Partial success"):
        auth.authenticate("alice", lambda n, i, p: [])


@pytest.mark.asyncio
async def test_async_keyboard_interactive_auth_success():
    transport = AsyncMock()
    transport._expect_message_async.side_effect = [UserAuthSuccessMessage()]

    auth = AsyncKeyboardInteractiveAuth(transport)

    async def handler(name, instruction, prompts):
        return []

    assert await auth.authenticate_async("alice", handler) is True


@pytest.mark.asyncio
async def test_async_keyboard_interactive_auth_loop():
    transport = AsyncMock()

    info_req_msg = MagicMock()
    info_req_msg.msg_type = 60
    info_req_msg._data = b"dummy"

    info_req = MagicMock()
    info_req.name = "Title"
    info_req.instruction = "Inst"
    info_req.prompts = [("Code:", True)]

    with patch(
        "spindlex.auth.keyboard_interactive.UserAuthInfoRequestMessage.unpack",
        return_value=info_req,
    ):
        transport._expect_message_async.side_effect = [
            info_req_msg,
            UserAuthSuccessMessage(),
        ]

        auth = AsyncKeyboardInteractiveAuth(transport)

        async def handler(name, instruction, prompts):
            return ["123456"]

        assert await auth.authenticate_async("alice", handler) is True
        assert transport._send_message_async.called
        sent_msg = transport._send_message_async.call_args[0][0]
        assert sent_msg.responses == ["123456"]


def test_console_handler():
    with (
        patch("builtins.print") as mock_print,
        patch("builtins.input", return_value="answer1") as mock_input,
        patch("getpass.getpass", return_value="answer2") as mock_getpass,
    ):
        prompts = [("Prompt 1:", True), ("Prompt 2:", False)]
        responses = console_handler("Title", "Instruction", prompts)

        assert responses == ["answer1", "answer2"]
        mock_print.assert_any_call("\nTitle")
        mock_print.assert_any_call("Instruction")
        mock_input.assert_called_with("Prompt 1:")
        mock_getpass.assert_called_with("Prompt 2:")
