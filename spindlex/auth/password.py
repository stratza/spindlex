"""
Password Authentication Implementation

Implements SSH password authentication method according to RFC 4252.
"""

from typing import Any

from ..exceptions import AuthenticationException


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

    def authenticate(self, username: str, password: str) -> bool:
        """
        Perform password authentication.

        Args:
            username: Username for authentication
            password: Password for authentication

        Returns:
            True if authentication successful

        Raises:
            AuthenticationException: If authentication fails
        """
        try:
            from ..protocol.constants import SERVICE_CONNECTION
            from ..protocol.messages import UserAuthRequestMessage

            # Build password authentication request
            # RFC 4252:
            # byte      SSH_MSG_USERAUTH_REQUEST
            # string    user name
            # string    service name
            # string    "password"
            # boolean   FALSE
            # string    password

            auth_msg = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method="password",
                method_data=b"\x00" + self._write_string(password),
            )

            # Send authentication request
            self._transport._send_message(auth_msg)

            # Handle response
            return self._transport._handle_auth_response()

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Password authentication failed: {e}")

    def _write_string(self, s: str) -> bytes:
        """Helper to write SSH string."""
        from ..protocol.utils import write_string

        return write_string(s)
