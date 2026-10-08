"""
GSSAPI Authentication Implementation

Implements SSH GSSAPI authentication method for Kerberos integration.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..exceptions import AuthenticationException
from ..protocol.constants import (
    AUTH_GSSAPI_WITH_MIC,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_GSSAPI_ERROR,
    MSG_USERAUTH_GSSAPI_ERRTOK,
    MSG_USERAUTH_GSSAPI_MIC,
    MSG_USERAUTH_GSSAPI_RESPONSE,
    MSG_USERAUTH_GSSAPI_TOKEN,
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_SUCCESS,
    SERVICE_CONNECTION,
)
from ..protocol.messages import Message, UserAuthRequestMessage
from ..protocol.utils import read_string, write_string, write_uint32

if TYPE_CHECKING:
    try:
        import gssapi
        from gssapi import Credentials, Name, SecurityContext

        GSSAPI_AVAILABLE = True
    except ImportError:
        GSSAPI_AVAILABLE = False
else:
    try:
        import gssapi as _gssapi
        from gssapi import Credentials as _Credentials
        from gssapi import Name as _Name
        from gssapi import SecurityContext as _SecurityContext

        GSSAPI_AVAILABLE = True
    except (ImportError, OSError):
        GSSAPI_AVAILABLE = False

        # Create mock classes for testing when gssapi is not available
        class MockCredentials:
            def __init__(self, usage: str | None = None) -> None:
                pass

        class MockName:
            class NameType:
                hostbased_service = "hostbased_service"
                user = "user"
                anonymous = "anonymous"

            def __init__(self, name: str, name_type: str | None = None) -> None:
                self.name = name
                self.name_type = name_type

        class MockSecurityContext:
            def __init__(
                self,
                name: Any = None,
                creds: Any = None,
                usage: Any = None,
                flags: Any = None,
            ) -> None:
                self.complete = False

            def step(self, token: bytes | None = None) -> bytes:
                return b""

        # Create a mock gssapi module with RequirementFlag
        class MockGSSAPIModule:
            class RequirementFlag:
                mutual_authentication = 1
                delegate_to_peer = 2

        _gssapi = MockGSSAPIModule()
        _Credentials = MockCredentials
        _Name = MockName
        _SecurityContext = MockSecurityContext

    # Expose the names for use in the rest of the module
    # Use cast(Any, ...) or simple assignment where it doesn't break types
    gssapi: Any = _gssapi
    Credentials: Any = _Credentials
    Name: Any = _Name
    SecurityContext: Any = _SecurityContext


class GSSAPIAuth:
    """
    SSH GSSAPI authentication implementation.

    Handles GSSAPI-based authentication with Kerberos ticket support
    for enterprise authentication scenarios.
    """

    def __init__(self, transport: Any) -> None:
        """
        Initialize GSSAPI authentication.

        Args:
            transport: SSH transport instance
        """
        self._transport = transport
        self._gss_context: SecurityContext | None = None
        self._gss_credentials: Credentials | None = None

    def authenticate(
        self,
        username: str,
        gss_host: str | None = None,
        gss_deleg_creds: bool = False,
    ) -> bool:
        """
        Perform GSSAPI authentication.

        Args:
            username: Username for authentication
            gss_host: GSSAPI hostname (defaults to transport hostname)
            gss_deleg_creds: Whether to delegate credentials

        Returns:
            True if authentication successful

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport.active:
            raise AuthenticationException("Transport not active")

        if self._transport.authenticated:
            return True

        if not GSSAPI_AVAILABLE:
            raise AuthenticationException("GSSAPI library not available")

        try:
            # Request ssh-userauth service if not already done
            if not self._transport._userauth_service_requested:
                self._transport._request_userauth_service()

            # Initialize GSSAPI context
            target_name = self._get_target_name(gss_host)
            self._init_gss_context(target_name, gss_deleg_creds)

            # Perform GSSAPI authentication exchange
            return self._perform_gssapi_exchange(username)

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"GSSAPI authentication failed: {e}") from e

    def _get_target_name(self, gss_host: str | None) -> Name:
        """
        Get GSSAPI target name for the SSH service.

        Args:
            gss_host: Optional hostname override

        Returns:
            GSSAPI Name object for the target service
        """
        if gss_host is None:
            # Use hostname from transport if available, otherwise get from socket
            hostname = getattr(self._transport, "_hostname", None)
            if not hostname:
                try:
                    hostname = self._transport._socket.getpeername()[0]
                except (OSError, AttributeError):
                    hostname = "localhost"
        else:
            hostname = gss_host

        # Create service principal name for SSH
        service_name = f"host@{hostname}"
        if GSSAPI_AVAILABLE:
            from gssapi import NameType

            return Name(service_name, name_type=NameType.hostbased_service)
        else:
            # In mock mode, Name is MockName which has NameType attribute
            # Use Any to bypass mypy check for the mock
            mock_name_class: Any = Name
            return Name(
                service_name, name_type=mock_name_class.NameType.hostbased_service
            )

    def _init_gss_context(self, target_name: Name, delegate_creds: bool) -> None:
        """
        Initialize GSSAPI security context.

        Args:
            target_name: Target service name
            delegate_creds: Whether to delegate credentials
        """
        try:
            # Get default credentials
            self._gss_credentials = Credentials(usage="initiate")

            # Create security context
            flags: Any = gssapi.RequirementFlag.mutual_authentication
            if delegate_creds:
                flags |= gssapi.RequirementFlag.delegate_to_peer

            self._gss_context = SecurityContext(
                name=target_name, creds=self._gss_credentials, flags=flags
            )

        except Exception as e:
            raise AuthenticationException(
                f"Failed to initialize GSSAPI context: {e}"
            ) from e

    # Kerberos v5 mechanism OID 1.2.840.113554.1.2.2, DER encoded (RFC 4462 s3.2)
    _KRB5_OID = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"

    def _perform_gssapi_exchange(self, username: str) -> bool:
        """
        Run the gssapi-with-mic exchange (RFC 4462 s3).

        1. USERAUTH_REQUEST listing the mechanism OID; the server answers
           USERAUTH_GSSAPI_RESPONSE with the OID it selected.
        2. Context tokens are exchanged as USERAUTH_GSSAPI_TOKEN messages
           until the security context is established.
        3. USERAUTH_GSSAPI_MIC carries a MIC over the session data.
        4. The server's USERAUTH_SUCCESS / USERAUTH_FAILURE decides the result.

        Returns:
            True only if the server answered USERAUTH_SUCCESS
        """
        context = self._gss_context
        if context is None:
            raise AuthenticationException("GSSAPI context not initialised")

        # 1. Propose the Kerberos mechanism.
        self._transport._send_message(
            UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method=AUTH_GSSAPI_WITH_MIC,
                method_data=write_uint32(1) + write_string(self._KRB5_OID),
            )
        )
        reply = self._transport._expect_message(
            MSG_USERAUTH_GSSAPI_RESPONSE, MSG_USERAUTH_FAILURE
        )
        if reply.msg_type == MSG_USERAUTH_FAILURE:
            return False
        selected, _ = read_string(bytes(reply._data), 0)
        if selected != self._KRB5_OID:
            raise AuthenticationException("Server selected an unsupported mechanism")

        # 2. Establish the security context.
        in_token: bytes | None = None
        while True:
            try:
                out_token = context.step(in_token)
            except Exception as e:
                raise AuthenticationException(f"GSSAPI context step failed: {e}") from e
            if out_token:
                msg = Message(MSG_USERAUTH_GSSAPI_TOKEN)
                msg.add_string(out_token)
                self._transport._send_message(msg)
            if context.complete:
                break
            reply = self._transport._expect_message(
                MSG_USERAUTH_GSSAPI_TOKEN,
                MSG_USERAUTH_GSSAPI_ERROR,
                MSG_USERAUTH_GSSAPI_ERRTOK,
                MSG_USERAUTH_FAILURE,
            )
            if reply.msg_type == MSG_USERAUTH_FAILURE:
                return False
            if reply.msg_type in (
                MSG_USERAUTH_GSSAPI_ERROR,
                MSG_USERAUTH_GSSAPI_ERRTOK,
            ):
                raise AuthenticationException(
                    "GSSAPI authentication rejected by server"
                )
            in_token, _ = read_string(bytes(reply._data), 0)

        # 3. Prove possession of the context over the session identifier.
        session_id = self._transport.session_id or b""
        mic_data = (
            write_string(session_id)
            + bytes([MSG_USERAUTH_REQUEST])
            + write_string(username)
            + write_string(SERVICE_CONNECTION)
            + write_string(AUTH_GSSAPI_WITH_MIC)
        )
        try:
            mic = context.get_signature(mic_data)
        except Exception as e:
            raise AuthenticationException(f"GSSAPI MIC generation failed: {e}") from e
        mic_msg = Message(MSG_USERAUTH_GSSAPI_MIC)
        mic_msg.add_string(mic)
        self._transport._send_message(mic_msg)

        # 4. The server decides.
        result = self._transport._expect_message(
            MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE
        )
        if result.msg_type == MSG_USERAUTH_SUCCESS:
            self._transport._authenticated = True
            return True
        return False

    def get_gss_context(self) -> SecurityContext | None:
        """
        Get the GSSAPI security context.

        Returns:
            GSSAPI SecurityContext or None if not initialized
        """
        return self._gss_context

    def get_gss_credentials(self) -> Credentials | None:
        """
        Get the GSSAPI credentials.

        Returns:
            GSSAPI Credentials or None if not initialized
        """
        return self._gss_credentials

    def cleanup(self) -> None:
        """Clean up GSSAPI resources.

        The gssapi library releases the underlying context/credentials via __del__
        (gss_delete_sec_context / gss_release_cred) when the Python objects are
        garbage-collected. Dropping our references here triggers that cleanup.
        """
        self._gss_context = None
        self._gss_credentials = None
