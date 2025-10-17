"""
Async SSH Transport Layer Implementation

Provides asynchronous SSH transport functionality for high-concurrency applications.
"""

import asyncio
import socket
import struct
from typing import Optional, Any, Dict
from ..exceptions import TransportException, AuthenticationException, ProtocolException
from ..protocol.constants import *
from ..protocol.messages import *
from ..protocol.utils import *
from .transport import Transport


class AsyncTransport(Transport):
    """
    Async SSH transport layer implementation.
    
    Extends the base Transport class to provide asynchronous operations
    for use in async/await applications and high-concurrency scenarios.
    """
    
    def __init__(self, sock: socket.socket) -> None:
        """
        Initialize async transport with socket connection.
        
        Args:
            sock: Connected socket for SSH communication
        """
        super().__init__(sock)
        self._loop = asyncio.get_event_loop()
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
    
    async def start_client(self, timeout: Optional[float] = None) -> None:
        """
        Start SSH client transport asynchronously.
        
        Args:
            timeout: Handshake timeout in seconds
            
        Raises:
            TransportException: If client start fails
        """
        if timeout is not None:
            self._connect_timeout = timeout
        
        try:
            async with self._lock:
                if self._active:
                    raise TransportException("Transport already active")
                
                self._server_mode = False
                
                # Create asyncio streams from socket
                self._reader, self._writer = await asyncio.open_connection(
                    sock=self._socket
                )
                
                # Perform SSH handshake
                await self._do_handshake_async()
                
                # Start key exchange
                await self._start_kex_async()
                
                self._active = True
                
        except Exception as e:
            await self.close()
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Client start failed: {e}")
    
    async def start_server(self, server_key: Any, timeout: Optional[float] = None) -> None:
        """
        Start SSH server transport asynchronously.
        
        Args:
            server_key: Server's private key
            timeout: Handshake timeout in seconds
            
        Raises:
            TransportException: If server start fails
        """
        if timeout is not None:
            self._connect_timeout = timeout
        
        try:
            async with self._lock:
                if self._active:
                    raise TransportException("Transport already active")
                
                self._server_mode = True
                self._server_key = server_key
                
                # Create asyncio streams from socket
                self._reader, self._writer = await asyncio.open_connection(
                    sock=self._socket
                )
                
                # Perform SSH handshake
                await self._do_handshake_async()
                
                # Start key exchange
                await self._start_kex_async()
                
                self._active = True
                
        except Exception as e:
            await self.close()
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Server start failed: {e}")
    
    async def auth_password(self, username: str, password: str) -> bool:
        """
        Authenticate using password asynchronously.
        
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
                await self._request_userauth_service_async()
            
            # Build password authentication request
            auth_request = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method=AUTH_PASSWORD,
                method_data=self._build_password_auth_data(password)
            )
            
            # Send authentication request
            await self._send_message_async(auth_request)
            
            # Wait for authentication response
            return await self._handle_auth_response_async()
            
        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Password authentication failed: {e}")
    
    async def auth_publickey(self, username: str, key: Any) -> bool:
        """
        Authenticate using public key asynchronously.
        
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
                await self._request_userauth_service_async()
            
            # First, try public key without signature (query)
            if await self._try_publickey_query_async(username, key):
                # Server accepts this key, now send with signature
                return await self._auth_publickey_with_signature_async(username, key)
            else:
                raise AuthenticationException("Public key not accepted by server")
                
        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Public key authentication failed: {e}")
    
    async def auth_gssapi(
        self, 
        username: str, 
        gss_host: Optional[str] = None,
        gss_deleg_creds: bool = False
    ) -> bool:
        """
        Authenticate using GSSAPI asynchronously.
        
        Args:
            username: Username for authentication
            gss_host: GSSAPI hostname (optional)
            gss_deleg_creds: Whether to delegate credentials
            
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
            from ..auth.gssapi import GSSAPIAuth
            
            # Create GSSAPI authenticator
            gssapi_auth = GSSAPIAuth(self)
            
            # Perform GSSAPI authentication
            result = gssapi_auth.authenticate(username, gss_host, gss_deleg_creds)
            
            # Clean up GSSAPI resources
            gssapi_auth.cleanup()
            
            return result
            
        except ImportError:
            raise AuthenticationException("GSSAPI authentication not available")
        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"GSSAPI authentication failed: {e}")
    
    async def open_channel(
        self, 
        kind: str, 
        dest_addr: Optional[tuple] = None
    ) -> Any:
        """
        Open new SSH channel asynchronously.
        
        Args:
            kind: Channel type (session, direct-tcpip, etc.)
            dest_addr: Destination address for forwarding channels
            
        Returns:
            New AsyncChannel instance
            
        Raises:
            TransportException: If channel creation fails
        """
        if not self._active:
            raise TransportException("Transport not active")
        
        if not self._authenticated:
            raise TransportException("Transport not authenticated")
        
        async with self._lock:
            # Check channel limit
            if len(self._channels) >= MAX_CHANNELS:
                raise TransportException("Maximum number of channels reached")
            
            # Get next channel ID
            channel_id = self._next_channel_id
            self._next_channel_id += 1
            
            try:
                # Create async channel instance
                from .async_channel import AsyncChannel
                channel = AsyncChannel(self, channel_id)
                
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
                await self._send_message_async(open_msg)
                
                # Wait for response
                response = await self._recv_message_async()
                
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
    
    async def close(self) -> None:
        """Close transport and cleanup resources asynchronously."""
        async with self._lock:
            self._active = False
            
            # Close asyncio streams
            if self._writer:
                self._writer.close()
                await self._writer.wait_closed()
                self._writer = None
            
            self._reader = None
            
            # Close socket
            if self._socket:
                try:
                    self._socket.close()
                except:
                    pass
            
            # Close all channels
            for channel in list(self._channels.values()):
                try:
                    await channel.close()
                except:
                    pass
            self._channels.clear()
    
    async def _do_handshake_async(self) -> None:
        """Perform SSH protocol handshake asynchronously."""
        try:
            if self._server_mode:
                # Server sends version first
                await self._send_version_async()
                await self._recv_version_async()
            else:
                # Client receives version first
                await self._recv_version_async()
                await self._send_version_async()
                
        except Exception as e:
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Handshake failed: {e}")
    
    async def _send_version_async(self) -> None:
        """Send SSH version string asynchronously."""
        version_string = create_version_string()
        self._client_version = version_string
        
        version_line = version_string + "\r\n"
        self._writer.write(version_line.encode(SSH_STRING_ENCODING))
        await self._writer.drain()
    
    async def _recv_version_async(self) -> None:
        """Receive and validate SSH version string asynchronously."""
        version_line = await self._reader.readuntil(b"\n")
        
        # Remove line ending
        if version_line.endswith(b"\r\n"):
            version_line = version_line[:-2]
        elif version_line.endswith(b"\n"):
            version_line = version_line[:-1]
        
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
    
    async def _start_kex_async(self) -> None:
        """Start key exchange process asynchronously."""
        async with self._lock:
            if self._kex_in_progress:
                raise TransportException("Key exchange already in progress")
            
            self._kex_in_progress = True
            
            try:
                # Send KEXINIT message
                await self._send_kexinit_async()
                
                # Receive KEXINIT message
                await self._recv_kexinit_async()
                
                # For now, just mark KEX as complete
                # Full KEX implementation will be in later tasks
                self._kex_in_progress = False
                
            except Exception as e:
                self._kex_in_progress = False
                raise
    
    async def _send_kexinit_async(self) -> None:
        """Send KEXINIT message asynchronously."""
        # Use the same logic as sync version
        self._send_kexinit()
    
    async def _recv_kexinit_async(self) -> None:
        """Receive KEXINIT message asynchronously."""
        msg = await self._recv_message_async()
        
        if not isinstance(msg, KexInitMessage):
            raise ProtocolException(f"Expected KEXINIT, got {type(msg).__name__}")
        
        # Store peer's KEXINIT for algorithm negotiation
        self._peer_kexinit = msg
    
    async def _send_message_async(self, message: Message) -> None:
        """Send SSH message asynchronously."""
        try:
            payload = message.pack()
            packet = self._build_packet(payload)
            
            async with self._lock:
                self._writer.write(packet)
                await self._writer.drain()
                self._sequence_number_out += 1
                
        except Exception as e:
            raise TransportException(f"Failed to send message: {e}")
    
    async def _recv_message_async(self) -> Message:
        """Receive SSH message asynchronously."""
        try:
            packet = await self._recv_packet_async()
            payload = extract_message_from_packet(packet)
            
            async with self._lock:
                self._sequence_number_in += 1
            
            return Message.unpack(payload)
            
        except Exception as e:
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Failed to receive message: {e}")
    
    async def _recv_packet_async(self) -> bytes:
        """Receive complete SSH packet asynchronously."""
        # Read packet length
        length_data = await self._reader.readexactly(PACKET_LENGTH_SIZE)
        packet_length = struct.unpack(">I", length_data)[0]
        
        # Validate packet length
        if packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE:
            raise ProtocolException(f"Invalid packet length: {packet_length}")
        
        if packet_length > MAX_PACKET_SIZE - PACKET_LENGTH_SIZE:
            raise ProtocolException(f"Packet too large: {packet_length}")
        
        # Read rest of packet
        packet_data = await self._reader.readexactly(packet_length)
        
        # Return complete packet
        return length_data + packet_data
    
    async def _request_userauth_service_async(self) -> None:
        """Request ssh-userauth service asynchronously."""
        if self._userauth_service_requested:
            return
        
        service_request = ServiceRequestMessage(SERVICE_USERAUTH)
        await self._send_message_async(service_request)
        
        # Wait for service accept
        msg = await self._recv_message_async()
        if not isinstance(msg, ServiceAcceptMessage):
            raise AuthenticationException(f"Expected SERVICE_ACCEPT, got {type(msg).__name__}")
        
        if msg.service_name != SERVICE_USERAUTH:
            raise AuthenticationException(f"Service not accepted: {msg.service_name}")
        
        self._userauth_service_requested = True
    
    async def _handle_auth_response_async(self) -> bool:
        """Handle authentication response message asynchronously."""
        msg = await self._recv_message_async()
        
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
    
    async def _try_publickey_query_async(self, username: str, key: Any) -> bool:
        """Try public key authentication without signature asynchronously."""
        auth_request = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PUBLICKEY,
            method_data=self._build_publickey_query_data(key)
        )
        
        await self._send_message_async(auth_request)
        
        # Wait for response
        msg = await self._recv_message_async()
        
        if isinstance(msg, UserAuthFailureMessage):
            return False
        elif msg.msg_type == MSG_USERAUTH_PK_OK:
            return True
        else:
            raise AuthenticationException(f"Unexpected response to public key query: {type(msg).__name__}")
    
    async def _auth_publickey_with_signature_async(self, username: str, key: Any) -> bool:
        """Authenticate with public key signature asynchronously."""
        auth_request = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PUBLICKEY,
            method_data=self._build_publickey_auth_data(username, key)
        )
        
        await self._send_message_async(auth_request)
        
        return await self._handle_auth_response_async()
    
    async def _send_channel_data_async(self, channel_id: int, data: bytes) -> None:
        """Send data through channel asynchronously."""
        async with self._lock:
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
            await self._send_message_async(data_msg)
            
            # Update remote window size
            channel._remote_window_size -= len(data)
    
    async def _send_channel_window_adjust_async(self, channel_id: int, bytes_to_add: int) -> None:
        """Send channel window adjust message asynchronously."""
        async with self._lock:
            if channel_id not in self._channels:
                return
            
            channel = self._channels[channel_id]
            
            # Build window adjust message
            msg = Message(MSG_CHANNEL_WINDOW_ADJUST)
            msg.add_uint32(channel._remote_channel_id)
            msg.add_uint32(bytes_to_add)
            
            await self._send_message_async(msg)
            
            # Update local window size
            channel._local_window_size += bytes_to_add
    
    async def _send_channel_request_async(self, channel_id: int, request_type: str, want_reply: bool, data: bytes) -> None:
        """Send channel request message asynchronously."""
        async with self._lock:
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
            
            await self._send_message_async(msg)
    
    async def _send_channel_eof_async(self, channel_id: int) -> None:
        """Send channel EOF message asynchronously."""
        async with self._lock:
            if channel_id not in self._channels:
                return
            
            channel = self._channels[channel_id]
            
            # Build EOF message
            msg = Message(MSG_CHANNEL_EOF)
            msg.add_uint32(channel._remote_channel_id)
            
            await self._send_message_async(msg)
    
    async def _send_channel_close_async(self, channel_id: int) -> None:
        """Send channel close message asynchronously."""
        async with self._lock:
            if channel_id not in self._channels:
                return
            
            channel = self._channels[channel_id]
            
            # Build close message
            msg = Message(MSG_CHANNEL_CLOSE)
            msg.add_uint32(channel._remote_channel_id)
            
            await self._send_message_async(msg)