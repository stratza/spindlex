"""
GSSAPI Authentication Implementation

Implements SSH GSSAPI authentication method for Kerberos integration.
"""

import struct
from typing import Any, Optional, Tuple
from ..exceptions import AuthenticationException
from ..protocol.constants import (
    SERVICE_CONNECTION, AUTH_GSSAPI_WITH_MIC, MSG_USERAUTH_GSSAPI_RESPONSE,
    MSG_USERAUTH_GSSAPI_TOKEN, MSG_USERAUTH_GSSAPI_ERROR, MSG_USERAUTH_GSSAPI_ERRTOK,
    MSG_USERAUTH_GSSAPI_MIC
)
from ..protocol.messages import (
    Message, UserAuthRequestMessage, UserAuthSuccessMessage, UserAuthFailureMessage
)
from ..protocol.utils import (
    read_string, write_uint32, write_string
)

try:
    import gssapi
    from gssapi import Credentials, Name, SecurityContext
    GSSAPI_AVAILABLE = True
except ImportError:
    GSSAPI_AVAILABLE = False
    # Create mock classes for testing when gssapi is not available
    class Credentials:
        def __init__(self, usage=None):
            pass
    
    class Name:
        class NameType:
            hostbased_service = "hostbased_service"
            user = "user"
            anonymous = "anonymous"
        
        def __init__(self, name, name_type=None):
            self.name = name
            self.name_type = name_type
    
    class SecurityContext:
        def __init__(self, name=None, creds=None, usage=None, flags=None):
            self.complete = False
    
    # Create a mock gssapi module with RequirementFlag
    class MockGSSAPI:
        class RequirementFlag:
            mutual_authentication = 1
            delegate_to_peer = 2
    
    gssapi = MockGSSAPI()


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
        self._gss_context: Optional[SecurityContext] = None
        self._gss_credentials: Optional[Credentials] = None
    
    def authenticate(
        self, 
        username: str, 
        gss_host: Optional[str] = None,
        gss_deleg_creds: bool = False
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
            raise AuthenticationException(f"GSSAPI authentication failed: {e}")
    
    def _get_target_name(self, gss_host: Optional[str]) -> Name:
        """
        Get GSSAPI target name for the SSH service.
        
        Args:
            gss_host: Optional hostname override
            
        Returns:
            GSSAPI Name object for the target service
        """
        if gss_host is None:
            # Use hostname from transport socket
            hostname = self._transport._socket.getpeername()[0]
        else:
            hostname = gss_host
        
        # Create service principal name for SSH
        service_name = f"host@{hostname}"
        return Name(service_name, name_type=Name.NameType.hostbased_service)
    
    def _init_gss_context(self, target_name: Name, delegate_creds: bool) -> None:
        """
        Initialize GSSAPI security context.
        
        Args:
            target_name: Target service name
            delegate_creds: Whether to delegate credentials
        """
        try:
            # Get default credentials
            self._gss_credentials = Credentials(usage='initiate')
            
            # Create security context
            flags = gssapi.RequirementFlag.mutual_authentication
            if delegate_creds:
                flags |= gssapi.RequirementFlag.delegate_to_peer
            
            self._gss_context = SecurityContext(
                name=target_name,
                creds=self._gss_credentials,
                flags=flags
            )
            
        except Exception as e:
            raise AuthenticationException(f"Failed to initialize GSSAPI context: {e}")
    
    def _perform_gssapi_exchange(self, username: str) -> bool:
        """
        Perform the GSSAPI authentication exchange.
        
        Args:
            username: Username for authentication
            
        Returns:
            True if authentication successful
        """
        try:
            # Start GSSAPI authentication
            token = None
            
            while not self._gss_context.complete:
                # Generate GSSAPI token
                try:
                    token = self._gss_context.step(token)
                except Exception as e:
                    raise AuthenticationException(f"GSSAPI context step failed: {e}")
                
                if token:
                    # Send GSSAPI authentication request
                    if not self._send_gssapi_request(username, token):
                        return False
                    
                    # Receive response if context not complete
                    if not self._gss_context.complete:
                        token = self._receive_gssapi_response()
                        if token is None:
                            return False
            
            # Authentication successful
            return True
            
        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"GSSAPI exchange failed: {e}")
    
    def _send_gssapi_request(self, username: str, token: bytes) -> bool:
        """
        Send GSSAPI authentication request.
        
        Args:
            username: Username for authentication
            token: GSSAPI token to send
            
        Returns:
            True if request sent successfully
        """
        try:
            # Build GSSAPI authentication method data
            method_data = self._build_gssapi_method_data(token)
            
            # Create authentication request
            auth_request = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method=AUTH_GSSAPI_WITH_MIC,
                method_data=method_data
            )
            
            # Send request
            self._transport._send_message(auth_request)
            return True
            
        except Exception as e:
            raise AuthenticationException(f"Failed to send GSSAPI request: {e}")
    
    def _build_gssapi_method_data(self, token: bytes) -> bytes:
        """
        Build GSSAPI method data for authentication request.
        
        Args:
            token: GSSAPI token
            
        Returns:
            Encoded method data
        """
        data = bytearray()
        
        # Add number of OIDs (1 for Kerberos v5)
        data.extend(write_uint32(1))
        
        # Add Kerberos v5 OID (1.2.840.113554.1.2.2)
        krb5_oid = b"\x06\x09\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"
        data.extend(write_string(krb5_oid))
        
        # Add GSSAPI token
        data.extend(write_string(token))
        
        return bytes(data)
    
    def _receive_gssapi_response(self) -> Optional[bytes]:
        """
        Receive GSSAPI authentication response.
        
        Returns:
            GSSAPI token from server or None if authentication failed
        """
        try:
            msg = self._transport._recv_message()
            
            if isinstance(msg, UserAuthSuccessMessage):
                # Authentication successful
                self._transport._authenticated = True
                return None
                
            elif isinstance(msg, UserAuthFailureMessage):
                # Authentication failed
                return None
                
            elif msg.msg_type == MSG_USERAUTH_GSSAPI_RESPONSE:
                # Parse GSSAPI response
                return self._parse_gssapi_response(msg)
                
            elif msg.msg_type == MSG_USERAUTH_GSSAPI_TOKEN:
                # Parse GSSAPI token
                return self._parse_gssapi_token(msg)
                
            else:
                raise AuthenticationException(f"Unexpected message during GSSAPI auth: {type(msg).__name__}")
                
        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Failed to receive GSSAPI response: {e}")
    
    def _parse_gssapi_response(self, msg: Message) -> bytes:
        """
        Parse GSSAPI response message.
        
        Args:
            msg: GSSAPI response message
            
        Returns:
            GSSAPI token from response
        """
        try:
            data = msg._data
            offset = 0
            
            # Read token
            token, offset = read_string(data, offset)
            return token
            
        except Exception as e:
            raise AuthenticationException(f"Failed to parse GSSAPI response: {e}")
    
    def _parse_gssapi_token(self, msg: Message) -> bytes:
        """
        Parse GSSAPI token message.
        
        Args:
            msg: GSSAPI token message
            
        Returns:
            GSSAPI token from message
        """
        try:
            data = msg._data
            offset = 0
            
            # Read token
            token, offset = read_string(data, offset)
            return token
            
        except Exception as e:
            raise AuthenticationException(f"Failed to parse GSSAPI token: {e}")
    
    def get_gss_context(self) -> Optional[SecurityContext]:
        """
        Get the GSSAPI security context.
        
        Returns:
            GSSAPI SecurityContext or None if not initialized
        """
        return self._gss_context
    
    def get_gss_credentials(self) -> Optional[Credentials]:
        """
        Get the GSSAPI credentials.
        
        Returns:
            GSSAPI Credentials or None if not initialized
        """
        return self._gss_credentials
    
    def cleanup(self) -> None:
        """Clean up GSSAPI resources."""
        if self._gss_context:
            try:
                # Context cleanup is handled automatically by gssapi library
                pass
            except Exception:
                pass
            finally:
                self._gss_context = None
        
        if self._gss_credentials:
            try:
                # Credentials cleanup is handled automatically by gssapi library
                pass
            except Exception:
                pass
            finally:
                self._gss_credentials = None