"""
SSH Transport Layer Implementation

Core SSH transport functionality including protocol handshake, key exchange,
authentication, and secure packet transmission.
"""

import os
import struct
import threading
import time
from typing import Optional, Tuple, Any, Dict, List
import socket
from ..exceptions import TransportException, AuthenticationException, ProtocolException
from ..protocol.constants import *
from ..protocol.messages import *
from ..protocol.utils import *
from ..crypto.backend import default_crypto_backend
from .channel import Channel
from .kex import KeyExchange


class Transport:
    """
    SSH transport layer implementation.
    
    Manages SSH protocol handshake, key exchange, authentication,
    and secure packet transmission according to RFC 4251-4254.
    """
    
    def __init__(self, sock: socket.socket) -> None:
        """
        Initialize transport with socket connection.
        
        Args:
            sock: Connected socket for SSH communication
        """
        self._socket = sock
        self._active = False
        self._server_mode = False
        self._channels: Dict[int, Channel] = {}
        self._next_channel_id = 0
        
        # Connection state
        self._authenticated = False
        self._session_id: Optional[bytes] = None
        self._server_version: Optional[str] = None
        self._client_version: Optional[str] = None
        
        # Crypto state
        self._crypto_backend = default_crypto_backend
        self._encryption_key_c2s: Optional[bytes] = None
        self._encryption_key_s2c: Optional[bytes] = None
        self._mac_key_c2s: Optional[bytes] = None
        self._mac_key_s2c: Optional[bytes] = None
        self._cipher_c2s: Optional[str] = None
        self._cipher_s2c: Optional[str] = None
        self._mac_c2s: Optional[str] = None
        self._mac_s2c: Optional[str] = None
        
        # Packet handling
        self._sequence_number_in = 0
        self._sequence_number_out = 0
        self._packet_buffer = b""
        self._lock = threading.RLock()
        
        # KEX state
        self._kex_in_progress = False
        self._kex = KeyExchange(self)
        
        # Timeouts
        self._connect_timeout = DEFAULT_CONNECT_TIMEOUT
        self._auth_timeout = DEFAULT_AUTH_TIMEOUT
        
        # Authentication state
        self._userauth_service_requested = False
        
        # Port forwarding
        self._port_forwarding_manager = None
    
    def start_client(self, timeout: Optional[float] = None) -> None:
        """
        Start SSH client transport.
        
        Args:
            timeout: Handshake timeout in seconds
            
        Raises:
            TransportException: If client start fails
        """
        if timeout is not None:
            self._connect_timeout = timeout
            
        try:
            with self._lock:
                if self._active:
                    raise TransportException("Transport already active")
                
                self._server_mode = False
                
                # Set socket timeout for handshake
                old_timeout = self._socket.gettimeout()
                self._socket.settimeout(self._connect_timeout)
                
                try:
                    # Perform SSH handshake
                    self._do_handshake()
                    
                    # Start key exchange
                    self._start_kex()
                    
                    self._active = True
                    
                finally:
                    # Restore original socket timeout
                    self._socket.settimeout(old_timeout)
                    
        except Exception as e:
            self.close()
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Client start failed: {e}")
    
    def start_server(self, server_key: Any, timeout: Optional[float] = None) -> None:
        """
        Start SSH server transport.
        
        Args:
            server_key: Server's private key
            timeout: Handshake timeout in seconds
            
        Raises:
            TransportException: If server start fails
        """
        if timeout is not None:
            self._connect_timeout = timeout
            
        try:
            with self._lock:
                if self._active:
                    raise TransportException("Transport already active")
                
                self._server_mode = True
                self._server_key = server_key
                
                # Set socket timeout for handshake
                old_timeout = self._socket.gettimeout()
                self._socket.settimeout(self._connect_timeout)
                
                try:
                    # Perform SSH handshake
                    self._do_handshake()
                    
                    # Start key exchange
                    self._start_kex()
                    
                    self._active = True
                    
                finally:
                    # Restore original socket timeout
                    self._socket.settimeout(old_timeout)
                    
        except Exception as e:
            self.close()
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Server start failed: {e}")
    
    def auth_password(self, username: str, password: str) -> bool:
        """
        Authenticate using password.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            
        Returns:
            True if authentication successful
            
        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._active:
            raise AuthenticationException("Transport not active")
        
        if self._authenticated:
            return True
        
        try:
            # Request ssh-userauth service if not already done
            if not self._userauth_service_requested:
                self._request_userauth_service()
            
            # Build password authentication request
            auth_request = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method=AUTH_PASSWORD,
                method_data=self._build_password_auth_data(password)
            )
            
            # Send authentication request
            self._send_message(auth_request)
            
            # Wait for authentication response
            return self._handle_auth_response()
            
        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Password authentication failed: {e}")
    
    def _build_password_auth_data(self, password: str) -> bytes:
        """Build password authentication method data."""
        data = bytearray()
        data.extend(write_boolean(False))  # password change request
        data.extend(write_string(password))
        return bytes(data)
    
    def auth_publickey(self, username: str, key: Any) -> bool:
        """
        Authenticate using public key.
        
        Args:
            username: Username for authentication
            key: Private key for authentication
            
        Returns:
            True if authentication successful
            
        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._active:
            raise AuthenticationException("Transport not active")
        
        if self._authenticated:
            return True
        
        try:
            # Request ssh-userauth service if not already done
            if not self._userauth_service_requested:
                self._request_userauth_service()
            
            # First, try public key without signature (query)
            if self._try_publickey_query(username, key):
                # Server accepts this key, now send with signature
                return self._auth_publickey_with_signature(username, key)
            else:
                raise AuthenticationException("Public key not accepted by server")
                
        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Public key authentication failed: {e}")
    
    def _try_publickey_query(self, username: str, key: Any) -> bool:
        """Try public key authentication without signature (query)."""
        auth_request = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PUBLICKEY,
            method_data=self._build_publickey_query_data(key)
        )
        
        self._send_message(auth_request)
        
        # Wait for response
        msg = self._recv_message()
        
        if isinstance(msg, UserAuthFailureMessage):
            return False
        elif msg.msg_type == MSG_USERAUTH_PK_OK:
            return True
        else:
            raise AuthenticationException(f"Unexpected response to public key query: {type(msg).__name__}")
    
    def _auth_publickey_with_signature(self, username: str, key: Any) -> bool:
        """Authenticate with public key signature."""
        auth_request = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PUBLICKEY,
            method_data=self._build_publickey_auth_data(username, key)
        )
        
        self._send_message(auth_request)
        
        return self._handle_auth_response()
    
    def _build_publickey_query_data(self, key: Any) -> bytes:
        """Build public key query method data."""
        data = bytearray()
        data.extend(write_boolean(False))  # no signature
        data.extend(write_string(key.get_name()))  # algorithm name
        data.extend(write_string(key.get_public_key_bytes()))  # public key blob
        return bytes(data)
    
    def _build_publickey_auth_data(self, username: str, key: Any) -> bytes:
        """Build public key authentication method data with signature."""
        data = bytearray()
        data.extend(write_boolean(True))  # has signature
        data.extend(write_string(key.get_name()))  # algorithm name
        data.extend(write_string(key.get_public_key_bytes()))  # public key blob
        
        # Build signature data
        signature_data = self._build_signature_data(username, key)
        signature = key.sign_data(signature_data)
        
        # Add signature
        sig_blob = bytearray()
        sig_blob.extend(write_string(key.get_name()))
        sig_blob.extend(write_string(signature))
        data.extend(write_string(bytes(sig_blob)))
        
        return bytes(data)
    
    def _build_signature_data(self, username: str, key: Any) -> bytes:
        """Build data to be signed for public key authentication."""
        data = bytearray()
        data.extend(write_string(self._session_id))
        data.extend(write_byte(MSG_USERAUTH_REQUEST))
        data.extend(write_string(username))
        data.extend(write_string(SERVICE_CONNECTION))
        data.extend(write_string(AUTH_PUBLICKEY))
        data.extend(write_boolean(True))  # has signature
        data.extend(write_string(key.get_name()))
        data.extend(write_string(key.get_public_key_bytes()))
        return bytes(data)
    
    def auth_keyboard_interactive(self, username: str, handler: Any) -> bool:
        """
        Authenticate using keyboard-interactive method.
        
        Args:
            username: Username for authentication
            handler: Callback function to handle prompts
            
        Returns:
            True if authentication successful
            
        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._active:
            raise AuthenticationException("Transport not active")
        
        if self._authenticated:
            return True
        
        try:
            # Request ssh-userauth service if not already done
            if not self._userauth_service_requested:
                self._request_userauth_service()
            
            # Send initial keyboard-interactive request
            auth_request = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method=AUTH_KEYBOARD_INTERACTIVE,
                method_data=self._build_keyboard_interactive_data()
            )
            
            self._send_message(auth_request)
            
            # Handle interactive prompts
            return self._handle_keyboard_interactive_auth(handler)
            
        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Keyboard-interactive authentication failed: {e}")
    
    def _build_keyboard_interactive_data(self) -> bytes:
        """Build keyboard-interactive authentication method data."""
        data = bytearray()
        data.extend(write_string(""))  # language tag
        data.extend(write_string(""))  # submethods
        return bytes(data)
    
    def _handle_keyboard_interactive_auth(self, handler: Any) -> bool:
        """Handle keyboard-interactive authentication prompts."""
        while True:
            msg = self._recv_message()
            
            if isinstance(msg, UserAuthSuccessMessage):
                self._authenticated = True
                return True
            elif isinstance(msg, UserAuthFailureMessage):
                return False
            elif msg.msg_type == MSG_USERAUTH_INFO_REQUEST:
                # Handle info request (prompts)
                responses = self._handle_info_request(msg, handler)
                
                # Send responses
                response_msg = self._build_info_response(responses)
                self._send_message(response_msg)
            else:
                raise AuthenticationException(f"Unexpected message during keyboard-interactive auth: {type(msg).__name__}")
    
    def _handle_info_request(self, msg: Message, handler: Any) -> List[str]:
        """Handle keyboard-interactive info request."""
        # Parse info request message
        data = msg._data
        offset = 0
        
        name_bytes, offset = read_string(data, offset)
        instruction_bytes, offset = read_string(data, offset)
        language_bytes, offset = read_string(data, offset)
        num_prompts, offset = read_uint32(data, offset)
        
        name = name_bytes.decode(SSH_STRING_ENCODING, errors='replace')
        instruction = instruction_bytes.decode(SSH_STRING_ENCODING, errors='replace')
        
        prompts = []
        for _ in range(num_prompts):
            prompt_bytes, offset = read_string(data, offset)
            echo, offset = read_boolean(data, offset)
            prompt_text = prompt_bytes.decode(SSH_STRING_ENCODING, errors='replace')
            prompts.append((prompt_text, echo))
        
        # Call handler to get responses
        return handler(name, instruction, prompts)
    
    def _build_info_response(self, responses: List[str]) -> Message:
        """Build keyboard-interactive info response message."""
        msg = Message(MSG_USERAUTH_INFO_RESPONSE)
        msg.add_uint32(len(responses))
        for response in responses:
            msg.add_string(response)
        return msg
    
    def _request_userauth_service(self) -> None:
        """Request ssh-userauth service."""
        if self._userauth_service_requested:
            return
        
        service_request = ServiceRequestMessage(SERVICE_USERAUTH)
        self._send_message(service_request)
        
        # Wait for service accept
        msg = self._recv_message()
        if not isinstance(msg, ServiceAcceptMessage):
            raise AuthenticationException(f"Expected SERVICE_ACCEPT, got {type(msg).__name__}")
        
        if msg.service_name != SERVICE_USERAUTH:
            raise AuthenticationException(f"Service not accepted: {msg.service_name}")
        
        self._userauth_service_requested = True
    
    def _handle_auth_response(self) -> bool:
        """Handle authentication response message."""
        msg = self._recv_message()
        
        if isinstance(msg, UserAuthSuccessMessage):
            self._authenticated = True
            return True
        elif isinstance(msg, UserAuthFailureMessage):
            # Check if partial success
            if msg.partial_success:
                # Partial success - more auth methods required
                raise AuthenticationException(f"Partial success - additional methods required: {', '.join(msg.authentications)}")
            else:
                return False
        else:
            raise AuthenticationException(f"Unexpected authentication response: {type(msg).__name__}")
    
    def open_channel(
        self, 
        kind: str, 
        dest_addr: Optional[Tuple[str, int]] = None
    ) -> Channel:
        """
        Open new SSH channel.
        
        Args:
            kind: Channel type (session, direct-tcpip, etc.)
            dest_addr: Destination address for forwarding channels
            
        Returns:
            New Channel instance
            
        Raises:
            TransportException: If channel creation fails
        """
        if not self._active:
            raise TransportException("Transport not active")
        
        if not self._authenticated:
            raise TransportException("Transport not authenticated")
        
        with self._lock:
            # Check channel limit
            if len(self._channels) >= MAX_CHANNELS:
                raise TransportException("Maximum number of channels reached")
            
            # Get next channel ID
            channel_id = self._next_channel_id
            self._next_channel_id += 1
            
            try:
                # Create channel instance
                channel = Channel(self, channel_id)
                
                # Build channel open message
                type_specific_data = b""
                if kind == CHANNEL_DIRECT_TCPIP and dest_addr:
                    type_specific_data = self._build_direct_tcpip_data(dest_addr)
                
                open_msg = ChannelOpenMessage(
                    channel_type=kind,
                    sender_channel=channel_id,
                    initial_window_size=DEFAULT_WINDOW_SIZE,
                    maximum_packet_size=DEFAULT_MAX_PACKET_SIZE,
                    type_specific_data=type_specific_data
                )
                
                # Send channel open request
                self._send_message(open_msg)
                
                # Wait for response
                response = self._recv_message()
                
                if isinstance(response, ChannelOpenConfirmationMessage):
                    # Channel opened successfully
                    channel._remote_channel_id = response.sender_channel
                    channel._remote_window_size = response.initial_window_size
                    channel._remote_max_packet_size = response.maximum_packet_size
                    channel._local_window_size = DEFAULT_WINDOW_SIZE
                    channel._local_max_packet_size = DEFAULT_MAX_PACKET_SIZE
                    
                    # Add to channels dict
                    self._channels[channel_id] = channel
                    
                    return channel
                    
                elif isinstance(response, ChannelOpenFailureMessage):
                    # Channel open failed
                    raise TransportException(f"Channel open failed: {response.description} (code: {response.reason_code})")
                    
                else:
                    raise TransportException(f"Unexpected response to channel open: {type(response).__name__}")
                    
            except Exception as e:
                if isinstance(e, TransportException):
                    raise
                raise TransportException(f"Failed to open channel: {e}")
    
    def _build_direct_tcpip_data(self, dest_addr: Tuple[str, int]) -> bytes:
        """Build type-specific data for direct-tcpip channel."""
        data = bytearray()
        data.extend(write_string(dest_addr[0]))  # destination host
        data.extend(write_uint32(dest_addr[1]))  # destination port
        data.extend(write_string("127.0.0.1"))  # originator IP
        data.extend(write_uint32(0))  # originator port
        return bytes(data)
    
    def _close_channel(self, channel_id: int) -> None:
        """
        Close channel and remove from channels dict.
        
        Args:
            channel_id: Channel ID to close
        """
        with self._lock:
            if channel_id in self._channels:
                channel = self._channels[channel_id]
                
                # Send channel close message if not already closed
                if not channel.closed:
                    try:
                        close_msg = ChannelCloseMessage(channel._remote_channel_id)
                        self._send_message(close_msg)
                    except:
                        pass  # Ignore errors during close
                
                # Remove from channels dict
                del self._channels[channel_id]
    
    def _handle_channel_message(self, msg: Message) -> None:
        """
        Handle channel-related messages.
        
        Args:
            msg: Channel message to handle
        """
        if msg.msg_type == MSG_CHANNEL_DATA:
            self._handle_channel_data(msg)
        elif msg.msg_type == MSG_CHANNEL_EXTENDED_DATA:
            self._handle_channel_extended_data(msg)
        elif msg.msg_type == MSG_CHANNEL_EOF:
            self._handle_channel_eof(msg)
        elif msg.msg_type == MSG_CHANNEL_CLOSE:
            self._handle_channel_close(msg)
        elif msg.msg_type == MSG_CHANNEL_WINDOW_ADJUST:
            self._handle_channel_window_adjust(msg)
        elif msg.msg_type == MSG_CHANNEL_SUCCESS:
            self._handle_channel_success(msg)
        elif msg.msg_type == MSG_CHANNEL_FAILURE:
            self._handle_channel_failure(msg)
        elif msg.msg_type == MSG_CHANNEL_REQUEST:
            self._handle_channel_request(msg)
        elif msg.msg_type == MSG_CHANNEL_OPEN:
            self._handle_channel_open(msg)
        elif msg.msg_type == MSG_GLOBAL_REQUEST:
            self._handle_global_request(msg)
        else:
            # Unknown channel message - ignore or log
            pass
    
    def _handle_channel_open(self, msg: Message) -> None:
        """
        Handle incoming channel open request.
        
        Args:
            msg: Channel open message
        """
        try:
            if isinstance(msg, ChannelOpenMessage):
                channel_type = msg.channel_type
                sender_channel = msg.sender_channel
                initial_window_size = msg.initial_window_size
                maximum_packet_size = msg.maximum_packet_size
                type_specific_data = msg.type_specific_data
                
                # Handle forwarded-tcpip channels
                if channel_type == CHANNEL_FORWARDED_TCPIP:
                    self._handle_forwarded_tcpip_open(
                        sender_channel, initial_window_size, maximum_packet_size, type_specific_data
                    )
                else:
                    # Unknown channel type - send failure
                    failure_msg = ChannelOpenFailureMessage(
                        recipient_channel=sender_channel,
                        reason_code=SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                        description=f"Unknown channel type: {channel_type}",
                        language_tag=""
                    )
                    self._send_message(failure_msg)
                    
        except Exception as e:
            # Send failure response
            try:
                failure_msg = ChannelOpenFailureMessage(
                    recipient_channel=sender_channel,
                    reason_code=SSH_OPEN_CONNECT_FAILED,
                    description=f"Channel open failed: {e}",
                    language_tag=""
                )
                self._send_message(failure_msg)
            except:
                pass
    
    def _handle_forwarded_tcpip_open(self, sender_channel: int, initial_window_size: int,
                                   maximum_packet_size: int, type_specific_data: bytes) -> None:
        """
        Handle forwarded-tcpip channel open.
        
        Args:
            sender_channel: Remote channel ID
            initial_window_size: Initial window size
            maximum_packet_size: Maximum packet size
            type_specific_data: Channel type specific data
        """
        try:
            # Parse forwarded-tcpip data
            offset = 0
            connected_address_bytes, offset = read_string(type_specific_data, offset)
            connected_port, offset = read_uint32(type_specific_data, offset)
            originator_address_bytes, offset = read_string(type_specific_data, offset)
            originator_port, offset = read_uint32(type_specific_data, offset)
            
            connected_address = connected_address_bytes.decode(SSH_STRING_ENCODING)
            originator_address = originator_address_bytes.decode(SSH_STRING_ENCODING)
            
            # Create local channel
            with self._lock:
                channel_id = self._next_channel_id
                self._next_channel_id += 1
                
                channel = Channel(self, channel_id)
                channel._remote_channel_id = sender_channel
                channel._remote_window_size = initial_window_size
                channel._remote_max_packet_size = maximum_packet_size
                channel._local_window_size = DEFAULT_WINDOW_SIZE
                channel._local_max_packet_size = DEFAULT_MAX_PACKET_SIZE
                
                self._channels[channel_id] = channel
            
            # Send confirmation
            confirm_msg = ChannelOpenConfirmationMessage(
                recipient_channel=sender_channel,
                sender_channel=channel_id,
                initial_window_size=DEFAULT_WINDOW_SIZE,
                maximum_packet_size=DEFAULT_MAX_PACKET_SIZE,
                type_specific_data=b""
            )
            self._send_message(confirm_msg)
            
            # Handle the forwarded connection
            if self._port_forwarding_manager:
                origin_addr = (originator_address, originator_port)
                dest_addr = (connected_address, connected_port)
                self._port_forwarding_manager.handle_forwarded_connection(channel, origin_addr, dest_addr)
            
        except Exception as e:
            # Send failure response
            failure_msg = ChannelOpenFailureMessage(
                recipient_channel=sender_channel,
                reason_code=SSH_OPEN_CONNECT_FAILED,
                description=f"Forwarded connection failed: {e}",
                language_tag=""
            )
            self._send_message(failure_msg)
    
    def _handle_channel_data(self, msg: Message) -> None:
        """Handle channel data message."""
        if isinstance(msg, ChannelDataMessage):
            with self._lock:
                if msg.recipient_channel in self._channels:
                    channel = self._channels[msg.recipient_channel]
                    channel._handle_data(msg.data)
    
    def _handle_channel_extended_data(self, msg: Message) -> None:
        """Handle channel extended data message."""
        # Parse extended data message
        data = msg._data
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        data_type, offset = read_uint32(data, offset)
        message_data, offset = read_string(data, offset)
        
        with self._lock:
            if recipient_channel in self._channels:
                channel = self._channels[recipient_channel]
                channel._handle_extended_data(data_type, message_data)
    
    def _handle_channel_eof(self, msg: Message) -> None:
        """Handle channel EOF message."""
        recipient_channel, _ = read_uint32(msg._data, 0)
        
        with self._lock:
            if recipient_channel in self._channels:
                channel = self._channels[recipient_channel]
                channel._handle_eof()
    
    def _handle_channel_close(self, msg: Message) -> None:
        """Handle channel close message."""
        if isinstance(msg, ChannelCloseMessage):
            with self._lock:
                if msg.recipient_channel in self._channels:
                    channel = self._channels[msg.recipient_channel]
                    channel._handle_close()
                    # Remove from channels dict
                    del self._channels[msg.recipient_channel]
    
    def _handle_channel_window_adjust(self, msg: Message) -> None:
        """Handle channel window adjust message."""
        data = msg._data
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        bytes_to_add, offset = read_uint32(data, offset)
        
        with self._lock:
            if recipient_channel in self._channels:
                channel = self._channels[recipient_channel]
                channel._handle_window_adjust(bytes_to_add)
    
    def _handle_channel_success(self, msg: Message) -> None:
        """Handle channel success message."""
        recipient_channel, _ = read_uint32(msg._data, 0)
        
        with self._lock:
            if recipient_channel in self._channels:
                channel = self._channels[recipient_channel]
                channel._handle_request_success()
    
    def _handle_channel_failure(self, msg: Message) -> None:
        """Handle channel failure message."""
        recipient_channel, _ = read_uint32(msg._data, 0)
        
        with self._lock:
            if recipient_channel in self._channels:
                channel = self._channels[recipient_channel]
                channel._handle_request_failure()
    
    def _handle_channel_request(self, msg: Message) -> None:
        """Handle channel request message."""
        # Parse channel request message
        data = msg._data
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        request_type_bytes, offset = read_string(data, offset)
        want_reply, offset = read_boolean(data, offset)
        
        request_type = request_type_bytes.decode(SSH_STRING_ENCODING)
        request_data = data[offset:] if offset < len(data) else b""
        
        with self._lock:
            if recipient_channel in self._channels:
                channel = self._channels[recipient_channel]
                
                # Handle specific request types
                if request_type == "exit-status":
                    # Parse exit status
                    if len(request_data) >= 4:
                        exit_status, _ = read_uint32(request_data, 0)
                        channel._handle_exit_status(exit_status)
                elif request_type == "exit-signal":
                    # Parse exit signal
                    self._handle_exit_signal_request(channel, request_data)
                
                # Send reply if requested
                if want_reply:
                    # For now, always send success
                    # Server implementations can override this behavior
                    success_msg = Message(MSG_CHANNEL_SUCCESS)
                    success_msg.add_uint32(channel._remote_channel_id)
                    self._send_message(success_msg)
    
    def _handle_exit_signal_request(self, channel: Channel, data: bytes) -> None:
        """Handle exit signal request data."""
        try:
            offset = 0
            signal_name_bytes, offset = read_string(data, offset)
            core_dumped, offset = read_boolean(data, offset)
            error_message_bytes, offset = read_string(data, offset)
            language_tag_bytes, offset = read_string(data, offset)
            
            signal_name = signal_name_bytes.decode(SSH_STRING_ENCODING)
            error_message = error_message_bytes.decode(SSH_STRING_ENCODING, errors='replace')
            language_tag = language_tag_bytes.decode(SSH_STRING_ENCODING, errors='replace')
            
            channel._handle_exit_signal(signal_name, core_dumped, error_message, language_tag)
        except Exception:
            # Ignore malformed exit signal data
            pass
    
    def _send_channel_data(self, channel_id: int, data: bytes) -> None:
        """
        Send data through channel.
        
        Args:
            channel_id: Local channel ID
            data: Data to send
        """
        with self._lock:
            if channel_id not in self._channels:
                raise TransportException(f"Channel {channel_id} not found")
            
            channel = self._channels[channel_id]
            
            # Check window size
            if len(data) > channel._remote_window_size:
                raise TransportException("Remote window size exceeded")
            
            if len(data) > channel._remote_max_packet_size:
                raise TransportException("Remote max packet size exceeded")
            
            # Send data message
            data_msg = ChannelDataMessage(channel._remote_channel_id, data)
            self._send_message(data_msg)
            
            # Update remote window size
            channel._remote_window_size -= len(data)
    
    def _send_channel_window_adjust(self, channel_id: int, bytes_to_add: int) -> None:
        """
        Send channel window adjust message.
        
        Args:
            channel_id: Local channel ID
            bytes_to_add: Number of bytes to add to window
        """
        with self._lock:
            if channel_id not in self._channels:
                return
            
            channel = self._channels[channel_id]
            
            # Build window adjust message
            msg = Message(MSG_CHANNEL_WINDOW_ADJUST)
            msg.add_uint32(channel._remote_channel_id)
            msg.add_uint32(bytes_to_add)
            
            self._send_message(msg)
            
            # Update local window size
            channel._local_window_size += bytes_to_add
    
    def _send_channel_request(self, channel_id: int, request_type: str, want_reply: bool, data: bytes) -> None:
        """
        Send channel request message.
        
        Args:
            channel_id: Local channel ID
            request_type: Type of request
            want_reply: Whether reply is wanted
            data: Request-specific data
        """
        with self._lock:
            if channel_id not in self._channels:
                raise TransportException(f"Channel {channel_id} not found")
            
            channel = self._channels[channel_id]
            
            # Build channel request message
            msg = Message(MSG_CHANNEL_REQUEST)
            msg.add_uint32(channel._remote_channel_id)
            msg.add_string(request_type)
            msg.add_boolean(want_reply)
            if data:
                msg._data.extend(data)
            
            self._send_message(msg)
    
    def _send_channel_eof(self, channel_id: int) -> None:
        """
        Send channel EOF message.
        
        Args:
            channel_id: Local channel ID
        """
        with self._lock:
            if channel_id not in self._channels:
                return
            
            channel = self._channels[channel_id]
            
            # Build EOF message
            msg = Message(MSG_CHANNEL_EOF)
            msg.add_uint32(channel._remote_channel_id)
            
            self._send_message(msg)
    
    def _send_global_request(self, request_name: str, want_reply: bool, data: bytes = b"") -> bool:
        """
        Send global request message.
        
        Args:
            request_name: Name of the global request
            want_reply: Whether to wait for reply
            data: Request-specific data
            
        Returns:
            True if request succeeded (when want_reply=True)
            
        Raises:
            TransportException: If request fails
        """
        if not self._active:
            raise TransportException("Transport not active")
        
        try:
            # Build global request message
            msg = Message(MSG_GLOBAL_REQUEST)
            msg.add_string(request_name)
            msg.add_boolean(want_reply)
            if data:
                msg._data.extend(data)
            
            # Send request
            self._send_message(msg)
            
            if want_reply:
                # Wait for response
                response = self._recv_message()
                
                if response.msg_type == MSG_REQUEST_SUCCESS:
                    return True
                elif response.msg_type == MSG_REQUEST_FAILURE:
                    return False
                else:
                    raise TransportException(f"Unexpected response to global request: {type(response).__name__}")
            
            return True  # No reply requested
            
        except Exception as e:
            if isinstance(e, TransportException):
                raise
            raise TransportException(f"Failed to send global request: {e}")
    
    def _handle_global_request(self, msg: Message) -> None:
        """
        Handle incoming global request.
        
        Args:
            msg: Global request message
        """
        try:
            # Parse global request message
            data = msg._data
            offset = 0
            
            request_name_bytes, offset = read_string(data, offset)
            want_reply, offset = read_boolean(data, offset)
            request_data = data[offset:] if offset < len(data) else b""
            
            request_name = request_name_bytes.decode(SSH_STRING_ENCODING)
            
            # Handle specific request types
            success = False
            
            if request_name == "tcpip-forward":
                success = self._handle_tcpip_forward_request(request_data)
            elif request_name == "cancel-tcpip-forward":
                success = self._handle_cancel_tcpip_forward_request(request_data)
            else:
                # Unknown request type
                success = False
            
            # Send reply if requested
            if want_reply:
                if success:
                    reply_msg = Message(MSG_REQUEST_SUCCESS)
                else:
                    reply_msg = Message(MSG_REQUEST_FAILURE)
                
                self._send_message(reply_msg)
                
        except Exception as e:
            # Send failure reply if requested
            if want_reply:
                try:
                    reply_msg = Message(MSG_REQUEST_FAILURE)
                    self._send_message(reply_msg)
                except:
                    pass
    
    def _handle_tcpip_forward_request(self, data: bytes) -> bool:
        """
        Handle tcpip-forward global request.
        
        Args:
            data: Request data
            
        Returns:
            True if request should be accepted
        """
        try:
            offset = 0
            bind_address_bytes, offset = read_string(data, offset)
            bind_port, offset = read_uint32(data, offset)
            
            bind_address = bind_address_bytes.decode(SSH_STRING_ENCODING)
            
            # For now, accept all tcpip-forward requests
            # Server implementations can override this behavior
            return True
            
        except Exception:
            return False
    
    def _handle_cancel_tcpip_forward_request(self, data: bytes) -> bool:
        """
        Handle cancel-tcpip-forward global request.
        
        Args:
            data: Request data
            
        Returns:
            True if request should be accepted
        """
        try:
            offset = 0
            bind_address_bytes, offset = read_string(data, offset)
            bind_port, offset = read_uint32(data, offset)
            
            bind_address = bind_address_bytes.decode(SSH_STRING_ENCODING)
            
            # For now, accept all cancel requests
            # Server implementations can override this behavior
            return True
            
        except Exception:
            return False
    
    def close(self) -> None:
        """Close transport and cleanup resources."""
        with self._lock:
            self._active = False
            if self._socket:
                try:
                    self._socket.close()
                except:
                    pass
            
            # Close all channels
            for channel in list(self._channels.values()):
                try:
                    channel.close()
                except:
                    pass
            self._channels.clear()
    
    def _do_handshake(self) -> None:
        """
        Perform SSH protocol handshake and version negotiation.
        
        Raises:
            TransportException: If handshake fails
            ProtocolException: If protocol error occurs
        """
        try:
            if self._server_mode:
                # Server sends version first
                self._send_version()
                self._recv_version()
            else:
                # Client receives version first
                self._recv_version()
                self._send_version()
                
        except Exception as e:
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Handshake failed: {e}")
    
    def _send_version(self) -> None:
        """Send SSH version string."""
        version_string = create_version_string()
        self._client_version = version_string
        
        version_line = version_string + "\r\n"
        self._socket.sendall(version_line.encode(SSH_STRING_ENCODING))
    
    def _recv_version(self) -> None:
        """Receive and validate SSH version string."""
        version_line = b""
        
        # Read version line character by character
        while True:
            try:
                char = self._socket.recv(1)
                if not char:
                    raise TransportException("Connection closed during version exchange")
                
                version_line += char
                
                # Check for line ending
                if version_line.endswith(b"\r\n"):
                    version_line = version_line[:-2]
                    break
                elif version_line.endswith(b"\n"):
                    version_line = version_line[:-1]
                    break
                
                # Prevent excessive version line length
                if len(version_line) > 255:
                    raise ProtocolException("Version line too long")
                    
            except socket.timeout:
                raise TransportException("Timeout during version exchange")
            except socket.error as e:
                raise TransportException(f"Socket error during version exchange: {e}")
        
        try:
            version_string = version_line.decode(SSH_STRING_ENCODING)
        except UnicodeDecodeError:
            raise ProtocolException("Invalid version string encoding")
        
        # Parse and validate version
        try:
            protocol_version, software_version = parse_version_string(version_string)
        except ValueError as e:
            raise ProtocolException(f"Invalid version string: {e}")
        
        if not is_supported_version(protocol_version):
            raise ProtocolException(f"Unsupported protocol version: {protocol_version}")
        
        self._server_version = version_string
    
    def _start_kex(self) -> None:
        """Start key exchange process."""
        with self._lock:
            if self._kex_in_progress:
                raise TransportException("Key exchange already in progress")
            
            self._kex_in_progress = True
            
            try:
                # Send KEXINIT message
                self._send_kexinit()
                
                # Receive KEXINIT message
                self._recv_kexinit()
                
                # For now, just mark KEX as complete
                # Full KEX implementation will be in later tasks
                self._kex_in_progress = False
                
            except Exception as e:
                self._kex_in_progress = False
                raise
    
    def _send_kexinit(self) -> None:
        """Send KEXINIT message with supported algorithms."""
        cookie = self._crypto_backend.generate_random(KEX_COOKIE_SIZE)
        
        # Define supported algorithms (modern, secure algorithms only)
        kex_algorithms = [
            KEX_CURVE25519_SHA256,
            KEX_ECDH_SHA2_NISTP256,
            KEX_DH_GROUP14_SHA256
        ]
        
        host_key_algorithms = [
            HOSTKEY_ED25519,
            HOSTKEY_ECDSA_SHA2_NISTP256,
            HOSTKEY_RSA_SHA2_256
        ]
        
        encryption_algorithms = [
            CIPHER_CHACHA20_POLY1305,
            CIPHER_AES256_GCM,
            CIPHER_AES128_GCM,
            CIPHER_AES256_CTR
        ]
        
        mac_algorithms = [
            MAC_HMAC_SHA2_256,
            MAC_HMAC_SHA2_512
        ]
        
        compression_algorithms = [COMPRESS_NONE]
        
        kexinit_msg = KexInitMessage(
            cookie=cookie,
            kex_algorithms=kex_algorithms,
            server_host_key_algorithms=host_key_algorithms,
            encryption_algorithms_client_to_server=encryption_algorithms,
            encryption_algorithms_server_to_client=encryption_algorithms,
            mac_algorithms_client_to_server=mac_algorithms,
            mac_algorithms_server_to_client=mac_algorithms,
            compression_algorithms_client_to_server=compression_algorithms,
            compression_algorithms_server_to_client=compression_algorithms
        )
        
        self._send_message(kexinit_msg)
    
    def _recv_kexinit(self) -> None:
        """Receive and process KEXINIT message."""
        msg = self._recv_message()
        
        if not isinstance(msg, KexInitMessage):
            raise ProtocolException(f"Expected KEXINIT, got {type(msg).__name__}")
        
        # Store peer's KEXINIT for algorithm negotiation
        self._peer_kexinit = msg
    
    def _send_message(self, message: Message) -> None:
        """
        Send SSH message.
        
        Args:
            message: Message to send
            
        Raises:
            TransportException: If send fails
        """
        try:
            payload = message.pack()
            packet = self._build_packet(payload)
            
            with self._lock:
                self._socket.sendall(packet)
                self._sequence_number_out += 1
                
        except Exception as e:
            raise TransportException(f"Failed to send message: {e}")
    
    def _recv_message(self) -> Message:
        """
        Receive SSH message.
        
        Returns:
            Received message
            
        Raises:
            TransportException: If receive fails
            ProtocolException: If message is invalid
        """
        try:
            packet = self._recv_packet()
            payload = extract_message_from_packet(packet)
            
            with self._lock:
                self._sequence_number_in += 1
            
            return Message.unpack(payload)
            
        except Exception as e:
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Failed to receive message: {e}")
    
    def _build_packet(self, payload: bytes) -> bytes:
        """
        Build SSH packet from payload.
        
        Args:
            payload: Message payload
            
        Returns:
            Complete SSH packet
        """
        # Calculate padding
        block_size = 8  # Minimum block size
        padding_length = block_size - ((len(payload) + PADDING_LENGTH_SIZE) % block_size)
        if padding_length < MIN_PADDING_SIZE:
            padding_length += block_size
        
        # Generate random padding
        padding = self._crypto_backend.generate_random(padding_length)
        
        # Build packet
        packet_length = PADDING_LENGTH_SIZE + len(payload) + padding_length
        packet = struct.pack(">I", packet_length)
        packet += struct.pack("B", padding_length)
        packet += payload
        packet += padding
        
        return packet
    
    def _recv_packet(self) -> bytes:
        """
        Receive complete SSH packet.
        
        Returns:
            Complete SSH packet
            
        Raises:
            TransportException: If receive fails
        """
        # Read packet length
        length_data = self._recv_bytes(PACKET_LENGTH_SIZE)
        packet_length = struct.unpack(">I", length_data)[0]
        
        # Validate packet length
        if packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE:
            raise ProtocolException(f"Invalid packet length: {packet_length}")
        
        if packet_length > MAX_PACKET_SIZE - PACKET_LENGTH_SIZE:
            raise ProtocolException(f"Packet too large: {packet_length}")
        
        # Read rest of packet
        packet_data = self._recv_bytes(packet_length)
        
        # Return complete packet
        return length_data + packet_data
    
    def _recv_bytes(self, length: int) -> bytes:
        """
        Receive exact number of bytes from socket.
        
        Args:
            length: Number of bytes to receive
            
        Returns:
            Received bytes
            
        Raises:
            TransportException: If receive fails
        """
        data = b""
        while len(data) < length:
            try:
                chunk = self._socket.recv(length - len(data))
                if not chunk:
                    raise TransportException("Connection closed unexpectedly")
                data += chunk
            except socket.timeout:
                raise TransportException("Timeout receiving data")
            except socket.error as e:
                raise TransportException(f"Socket error: {e}")
        
        return data
    
    @property
    def active(self) -> bool:
        """Check if transport is active."""
        return self._active
    
    @property
    def server_mode(self) -> bool:
        """Check if transport is in server mode."""
        return self._server_mode
    
    @property
    def authenticated(self) -> bool:
        """Check if transport is authenticated."""
        return self._authenticated
    
    @property
    def session_id(self) -> Optional[bytes]:
        """Get session ID."""
        return self._session_id
    
    def get_port_forwarding_manager(self) -> "PortForwardingManager":
        """
        Get port forwarding manager.
        
        Returns:
            Port forwarding manager instance
        """
        if self._port_forwarding_manager is None:
            from .forwarding import PortForwardingManager
            self._port_forwarding_manager = PortForwardingManager(self)
        
        return self._port_forwarding_manager