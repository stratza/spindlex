"""
Password Authentication Implementation

Implements SSH password authentication method according to RFC 4252.
"""

from typing import Any

from ..exceptions import AuthenticationException
from ..protocol.utils import write_string


class PasswordAuth:
    """
    SSH password authentication implementation.

    Handles password-based authentication with secure credential handling
    and protection against timing attacks.
    """

    def __init__(self, transport: Any) -> None:
        """
        Initialize password authentication.

        Args:
            transport: SSH transport instance
        """
        self._transport = transport

    def authenticate(self, username: str, password: str) -> Any:
        """
        Perform password authentication.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            Authentication response message

        Raises:
            AuthenticationException: If authentication fails
        """
        try:
            from ..protocol.constants import (
                MSG_USERAUTH_FAILURE,
                MSG_USERAUTH_SUCCESS,
                SERVICE_CONNECTION,
            )
            from ..protocol.messages import UserAuthRequestMessage

            # Build password authentication request
            auth_msg = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method="password",
                method_data=b"\x00" + write_string(password),
            )

            # Send authentication request
            self._transport._send_message(auth_msg)

            # Wait for response
            return self._transport._expect_message(
                MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE
            )

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Password authentication failed: {e}") from e

    async def authenticate_async(self, username: str, password: str) -> Any:
        """
        Perform password authentication asynchronously.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            Authentication response message

        Raises:
            AuthenticationException: If authentication fails
        """
        try:
            from ..protocol.constants import (
                MSG_USERAUTH_FAILURE,
                MSG_USERAUTH_SUCCESS,
                SERVICE_CONNECTION,
            )
            from ..protocol.messages import UserAuthRequestMessage

            # Build password authentication request
            auth_msg = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method="password",
                method_data=b"\x00" + write_string(password),
            )

            # Send authentication request
            await self._transport._send_message_async(auth_msg)

            # Wait for response
            return await self._transport._expect_message_async(
                MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE
            )

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Password authentication failed: {e}") from e

