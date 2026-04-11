"""
Keyboard-Interactive Authentication Implementation

Implements SSH keyboard-interactive authentication method according to RFC 4256.
"""

from typing import Any, Callable, cast

from ..exceptions import AuthenticationException
from ..protocol.constants import (
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_INFO_REQUEST,
    MSG_USERAUTH_SUCCESS,
)
from ..protocol.messages import (
    UserAuthFailureMessage,
    UserAuthInfoRequestMessage,
    UserAuthInfoResponseMessage,
    UserAuthSuccessMessage,
)


class KeyboardInteractiveAuth:
    """
    SSH keyboard-interactive authentication implementation.

    Handles interactive authentication with support for
    multi-factor authentication and custom prompts.
    """

    def __init__(self, transport: Any) -> None:
        """
        Initialize keyboard-interactive authentication.

        Args:
            transport: SSH transport instance
        """
        self._transport = transport

    def authenticate(
        self,
        username: str,
        handler: Callable[[str, str, list[tuple[str, bool]]], list[str]],
    ) -> bool:
        """
        Perform keyboard-interactive authentication.

        Args:
            username: Username for authentication
            handler: Interactive handler for prompts.
                     Signature: handler(name, instruction, prompts) -> responses
                     where prompts is list of (prompt_text, echo_boolean)

        Returns:
            True if authentication successful

        Raises:
            AuthenticationException: If authentication fails
        """
        try:
            # The initial request is already sent by Transport.auth_keyboard_interactive
            # but we can also implement it here if we want this class to be self-contained.
            # For consistency with other auth classes, let's assume Transport calls this
            # after the initial MSG_USERAUTH_REQUEST.

            # Actually, Transport.auth_keyboard_interactive currently calls its own
            # _handle_keyboard_interactive_auth. Let's make this class the source of truth.

            return self._handle_auth_loop(handler)

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(
                f"Keyboard-interactive authentication failed: {e}"
            )

    def _handle_auth_loop(self, handler: Callable) -> bool:
        """Handle the interactive information exchange loop."""
        while True:
            msg = self._transport._expect_message(
                MSG_USERAUTH_SUCCESS,
                MSG_USERAUTH_FAILURE,
                MSG_USERAUTH_INFO_REQUEST,
            )

            if isinstance(msg, UserAuthSuccessMessage):
                return True
            elif isinstance(msg, UserAuthFailureMessage):
                if msg.partial_success:
                    raise AuthenticationException(
                        f"Partial success - more methods required: {', '.join(msg.authentications)}"
                    )
                return False
            elif msg.msg_type == MSG_USERAUTH_INFO_REQUEST:
                # MSG_USERAUTH_INFO_REQUEST is message type 60
                # We need to unpack it properly
                info_req = cast(
                    UserAuthInfoRequestMessage,
                    UserAuthInfoRequestMessage.unpack(msg._data),
                )

                # Call user handler
                responses = handler(
                    info_req.name, info_req.instruction, info_req.prompts
                )

                # Send response
                info_resp = UserAuthInfoResponseMessage(responses)
                self._transport._send_message(info_resp)
            else:
                raise AuthenticationException(
                    f"Unexpected message during auth: {msg.msg_type}"
                )
