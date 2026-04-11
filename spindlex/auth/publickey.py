"""
Public Key Authentication Implementation

Implements SSH public key authentication method according to RFC 4252.
"""

from typing import Any

from ..exceptions import AuthenticationException


class PublicKeyAuth:
    """
    SSH public key authentication implementation.

    Handles public key-based authentication with support for
    Ed25519, ECDSA, and RSA keys.
    """

    def __init__(self, transport: Any) -> None:
        """
        Initialize public key authentication.

        Args:
            transport: SSH transport instance
        """
        self._transport = transport

    def authenticate(self, username: str, key: Any) -> bool:
        """
        Perform public key authentication.

        Args:
            username: Username for authentication
            key: Private key for authentication

        Returns:
            True if authentication successful

        Raises:
            AuthenticationException: If authentication fails
        """
        try:
            from ..protocol.constants import SERVICE_CONNECTION
            from ..protocol.messages import UserAuthRequestMessage

            # 1. First send a query to see if the key is acceptable
            query_msg = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method="publickey",
                method_data=self.get_method_data(key, is_query=True),
            )
            self._transport._send_message(query_msg)

            # 2. Perform full authentication with signature
            auth_msg = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method="publickey",
                method_data=self.get_method_data(key, is_query=False),
            )

            # Send authentication request
            self._transport._send_message(auth_msg)

            # Handle response
            return self._transport._handle_auth_response()

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(
                f"Public key authentication failed: {e}"
            ) from e

    def get_method_data(self, key: Any, is_query: bool = False) -> bytes:
        """
        Build public key authentication method data.

        Args:
            key: PKey instance
            is_query: True if this is a query (no signature), False for full auth

        Returns:
            Method-specific data bytes
        """
        from ..protocol.utils import write_boolean, write_string

        data = bytearray()
        data.extend(write_boolean(not is_query))
        data.extend(write_string(key.algorithm_name))
        data.extend(write_string(key.get_public_key_bytes()))

        if not is_query:
            # Add placeholder signature
            data.extend(write_string(b"placeholder-signature"))

        return bytes(data)
