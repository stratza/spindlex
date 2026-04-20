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
            from ..protocol.constants import (
                AUTH_PUBLICKEY,
                MSG_USERAUTH_REQUEST,
                SERVICE_CONNECTION,
            )
            from ..protocol.messages import UserAuthRequestMessage
            from ..protocol.utils import write_string

            # 1. First send a query to see if the key is acceptable
            query_msg = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method=AUTH_PUBLICKEY,
                method_data=self.get_method_data(key, is_query=True),
            )
            self._transport._send_message(query_msg)

            # Handle response to query
            # Expect MSG_USERAUTH_FAILURE or MSG_USERAUTH_PK_OK
            from ..protocol.constants import MSG_USERAUTH_FAILURE, MSG_USERAUTH_PK_OK

            msg = self._transport._expect_message(
                MSG_USERAUTH_FAILURE, MSG_USERAUTH_PK_OK
            )

            if msg.msg_type == MSG_USERAUTH_FAILURE:
                return False

            # If PK_OK, proceed to full auth

            # 2. Perform full authentication with real signature
            # RFC 4252 Section 7:
            # The signature is over a blob of:
            #  string    session identifier
            #  byte      SSH_MSG_USERAUTH_REQUEST
            #  string    user name
            #  string    service name
            #  string    "publickey"
            #  boolean   TRUE
            #  string    public key algorithm name
            #  string    public key blob

            auth_algo = "ssh-rsa"
            sig_blob = bytearray()
            sig_blob.extend(self._transport.session_id)
            sig_blob.append(MSG_USERAUTH_REQUEST)
            sig_blob.extend(write_string(username))
            sig_blob.extend(write_string(SERVICE_CONNECTION))
            sig_blob.extend(write_string(AUTH_PUBLICKEY))
            sig_blob.append(1)  # TRUE
            sig_blob.extend(write_string(auth_algo))
            sig_blob.extend(write_string(key.get_public_key_bytes()))

            signature = key.sign(bytes(sig_blob))

            auth_msg = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method=AUTH_PUBLICKEY,
                method_data=self.get_method_data(
                    key, is_query=False, signature=signature
                ),
            )

            # Send authentication request
            self._transport._send_message(auth_msg)

            # Handle final response
            return bool(self._transport._handle_auth_response())

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(
                f"Public key authentication failed: {e}"
            ) from e

    def get_method_data(
        self, key: Any, is_query: bool = False, signature: bytes = b""
    ) -> bytes:
        """
        Build public key authentication method data.

        Args:
            key: PKey instance
            is_query: True if this is a query (no signature), False for full auth
            signature: Signature bytes if not a query

        Returns:
            Method-specific data bytes
        """
        from ..protocol.utils import write_boolean, write_string

        data = bytearray()
        data.extend(write_boolean(not is_query))
        # Use algorithm_name (e.g. rsa-sha2-256 or ssh-rsa) for both
        data.extend(write_string(key.algorithm_name))
        data.extend(write_string(key.get_public_key_bytes()))

        if not is_query:
            data.extend(write_string(signature))

        return bytes(data)
