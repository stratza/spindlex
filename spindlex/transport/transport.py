"""
SSH Transport Layer Implementation

Core SSH transport functionality including protocol handshake, key exchange,
authentication, and secure packet transmission.
"""

import logging
import socket
import struct
import threading
import time
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .forwarding import PortForwardingManager

from ..crypto.backend import default_crypto_backend
from ..exceptions import AuthenticationException, ProtocolException, TransportException
from ..protocol.constants import *
from ..protocol.constants import create_version_string
from ..protocol.messages import *
from ..protocol.utils import *
from .channel import Channel
from .kex import KeyExchange


class Transport:
    """
    SSH transport layer implementation.

    Manages SSH protocol handshake, key exchange, authentication,
    and secure packet transmission according to RFC 4251-4254.
    """

    def __init__(
        self,
        sock: socket.socket,
        rekey_bytes_limit: Optional[int] = None,
        rekey_time_limit: Optional[int] = None,
    ) -> None:
        """
        Initialize transport with socket connection.

        Args:
            sock: Connected socket for SSH communication
            rekey_bytes_limit: Number of bytes before rekeying (default: 1GB)
            rekey_time_limit: Seconds before rekeying (default: 1 hour)
        """
        self._socket = sock
        self._active = False
        self._server_mode = False
        self._channels: dict[int, Channel] = {}
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
        self._iv_c2s: Optional[bytes] = None
        self._iv_s2c: Optional[bytes] = None
        self._cipher_c2s: Optional[str] = None
        self._cipher_s2c: Optional[str] = None
        self._mac_c2s: Optional[str] = None
        self._mac_s2c: Optional[str] = None

        # Active crypto state (updated only on NEWKEYS)
        self._mac_key_in_active: Optional[bytes] = None
        self._mac_key_out_active: Optional[bytes] = None
        self._mac_in_active: Optional[str] = None
        self._mac_out_active: Optional[str] = None

        # Rekeying policy (configurable)
        self._rekey_bytes_limit = rekey_bytes_limit or (
            1024 * 1024 * 1024
        )  # 1GB default
        self._rekey_time_limit = rekey_time_limit or 3600  # 1 hour default

        # Cipher instances
        self._encryptor: Optional[Any] = None
        self._decryptor: Optional[Any] = None
        self._encryptor_instance: Optional[Any] = None
        self._decryptor_instance: Optional[Any] = None

        # Packet handling
        self._sequence_number_in = 0
        self._sequence_number_out = 0
        self._packet_buffer = b""
        self._lock = threading.RLock()
        self._read_lock = threading.RLock()
        self._server_host_key_blob = None

        self._kex_in_progress = False
        self._kex = KeyExchange(self)
        self._bytes_since_rekey = 0
        self._last_rekey_time = time.time()

        # Timeouts
        self._connect_timeout: float = float(DEFAULT_CONNECT_TIMEOUT)
        self._auth_timeout: float = float(DEFAULT_AUTH_TIMEOUT)

        # Authentication state
        self._userauth_service_requested = False

        # Server interface for authentication callbacks
        self._server_interface: Optional[Any] = None

        # Port forwarding
        self._port_forwarding_manager: Optional[PortForwardingManager] = None

        # Message dispatching
        self._message_queue: list[Message] = []
        self._timeout = 10.0

        self._logger = logging.getLogger(__name__)

    def get_timeout(self) -> Optional[float]:
        """
        Get transport timeout.

        Returns:
            Current timeout in seconds, or None if no timeout
        """
        return self._socket.gettimeout()

    def set_timeout(self, timeout: float) -> None:
        """Set default timeout for transport operations."""
        self._timeout = timeout
        if self._socket:
            self._socket.settimeout(timeout)

    def set_rekey_policy(
        self, bytes_limit: Optional[int] = None, time_limit: Optional[int] = None
    ) -> None:
        """
        Configure rekeying thresholds.

        Args:
            bytes_limit: Number of bytes before rekeying (default: 1GB)
            time_limit: Seconds before rekeying (default: 1 hour)
        """
        if bytes_limit is not None:
            self._rekey_bytes_limit = bytes_limit
        if time_limit is not None:
            self._rekey_time_limit = time_limit

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
                self._client_version = create_version_string()

                # Set socket timeout for handshake
                old_timeout = self._socket.gettimeout()
                self._socket.settimeout(self._connect_timeout)

                try:
                    # Perform SSH handshake
                    self._logger.debug("Starting handshake...")
                    self._do_handshake()
                    self._logger.debug("Handshake complete.")

                    # Start key exchange
                    self._logger.debug("Starting KEX...")
                    self._start_kex()
                    self._logger.debug("KEX complete.")

                    self._active = True

                finally:
                    # Restore original socket timeout
                    try:
                        if self._socket and self._socket.fileno() != -1:
                            self._socket.settimeout(old_timeout)
                    except (OSError, AttributeError):
                        pass

        except Exception as e:
            self.close()
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Client start failed: {e}") from e

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
                self._server_version = create_version_string()

                # Set socket timeout for handshake
                old_timeout = self._socket.gettimeout()
                self._socket.settimeout(self._connect_timeout)

                try:
                    # Perform SSH handshake
                    self._logger.debug("Starting handshake...")
                    self._do_handshake()
                    self._logger.debug("Handshake complete.")

                    # Start key exchange
                    self._logger.debug("Starting KEX...")
                    self._start_kex()
                    self._logger.debug("KEX complete.")

                    self._active = True

                finally:
                    # Restore original socket timeout
                    try:
                        if self._socket and self._socket.fileno() != -1:
                            self._socket.settimeout(old_timeout)
                    except (OSError, AttributeError):
                        pass

        except Exception as e:
            self.close()
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Server start failed: {e}") from e

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
                method_data=self._build_password_auth_data(password),
            )

            # Send authentication request
            self._send_message(auth_request)

            # Wait for authentication response
            return self._handle_auth_response()

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(f"Password authentication failed: {e}") from e

    def _build_password_auth_data(self, password: str) -> bytes:
        """Build password authentication method data."""
        data = bytearray()
        data.extend(write_boolean(False))  # password change request
        data.extend(write_string(password))
        return bytes(data)

    def auth_publickey(self, username: str, key: Any) -> bool:
        """
        Authenticate using public key.
        """
        if not self._active:
            raise AuthenticationException("Transport not active")

        if self._authenticated:
            return True

        try:
            # Request ssh-userauth service if not already done
            if not self._userauth_service_requested:
                self._request_userauth_service()

            # For maximum compatibility and performance, we proceed directly to signature-based auth
            return self._auth_publickey_with_signature(username, key)

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(
                f"Public key authentication failed: {e}"
            ) from e

    def _auth_publickey_with_signature(self, username: str, key: Any) -> bool:
        """Authenticate with public key signature."""
        auth_request = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PUBLICKEY,
            method_data=self._build_publickey_auth_data(username, key),
        )

        self._send_message(auth_request)

        return self._handle_auth_response()

    def _try_publickey_query(self, username: str, key: Any) -> bool:
        """Try public key authentication without signature (query)."""
        auth_request = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PUBLICKEY,
            method_data=self._build_publickey_query_data(key),
        )

        self._send_message(auth_request)

        msg = self._expect_message(MSG_USERAUTH_FAILURE, MSG_USERAUTH_PK_OK)

        if isinstance(msg, UserAuthFailureMessage):
            return False
        elif getattr(msg, "msg_type", 0) == MSG_USERAUTH_PK_OK:
            return True
        else:
            return False

    def _build_publickey_query_data(self, key: Any) -> bytes:
        """Build public key query method data."""
        data = bytearray()
        data.extend(write_boolean(False))  # no signature
        data.extend(write_string(key.get_ssh_type()))  # algorithm name
        data.extend(write_string(key.get_public_key_bytes()))  # public key blob
        return bytes(data)

    def _build_publickey_auth_data(self, username: str, key: Any) -> bytes:
        """Build public key authentication method data with signature."""
        data = bytearray()
        data.extend(write_boolean(True))  # has signature
        data.extend(write_string(key.get_ssh_type()))
        data.extend(write_string(key.get_public_key_bytes()))

        # Build signature data
        signature_data = self._build_signature_data(username, key)
        signature = key.sign(signature_data)

        if signature is None:
            raise TransportException("Failed to sign authentication data")

        # The signature includes its own length when wrapped by write_string
        data.extend(write_string(signature))
        return bytes(data)

    def _build_signature_data(self, username: str, key: Any) -> bytes:
        """Build signature data for public key authentication."""
        if self._session_id is None:
            raise TransportException("Session ID not set")

        data = bytearray()
        data.extend(write_string(self._session_id))

        data.extend(write_byte(MSG_USERAUTH_REQUEST))
        data.extend(write_string(username))
        data.extend(write_string(SERVICE_CONNECTION))
        data.extend(write_string(AUTH_PUBLICKEY))
        data.extend(write_boolean(True))  # has signature
        data.extend(write_string(key.get_ssh_type()))
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

            from ..auth.keyboard_interactive import KeyboardInteractiveAuth

            # Send initial keyboard-interactive request
            auth_request = UserAuthRequestMessage(
                username=username,
                service=SERVICE_CONNECTION,
                method=AUTH_KEYBOARD_INTERACTIVE,
                method_data=self._build_keyboard_interactive_data(),
            )

            self._send_message(auth_request)

            # Perform interactive authentication
            ki_auth = KeyboardInteractiveAuth(self)
            result = ki_auth.authenticate(username, handler)

            if result:
                self._authenticated = True

            return result

        except Exception as e:
            if isinstance(e, AuthenticationException):
                raise
            raise AuthenticationException(
                f"Keyboard-interactive authentication failed: {e}"
            )

    def _build_keyboard_interactive_data(self) -> bytes:
        """Build keyboard-interactive authentication method data."""
        data = bytearray()
        data.extend(write_string(""))  # language tag
        data.extend(write_string(""))  # submethods
        return bytes(data)

    def auth_gssapi(
        self,
        username: str,
        gss_host: Optional[str] = None,
        gss_deleg_creds: bool = False,
    ) -> bool:
        """
        Authenticate using GSSAPI method.

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
            raise AuthenticationException(f"GSSAPI authentication failed: {e}") from e

    def _request_userauth_service(self) -> None:
        """Request ssh-userauth service."""
        if self._userauth_service_requested:
            return

        service_request = ServiceRequestMessage(SERVICE_USERAUTH)
        self._send_message(service_request)

        # Wait for service accept
        msg = self._expect_message(MSG_SERVICE_ACCEPT)
        if not isinstance(msg, ServiceAcceptMessage):
            raise AuthenticationException(
                f"Expected SERVICE_ACCEPT, got {type(msg).__name__}"
            )

        if msg.service_name != SERVICE_USERAUTH:
            raise AuthenticationException(f"Service not accepted: {msg.service_name}")

        self._userauth_service_requested = True

    def _handle_auth_response(self) -> bool:
        """Handle authentication response message."""
        msg = self._expect_message(MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE)

        if isinstance(msg, UserAuthSuccessMessage):
            self._authenticated = True
            return True
        elif isinstance(msg, UserAuthFailureMessage):
            # Check if partial success
            if msg.partial_success:
                # Partial success - more auth methods required
                raise AuthenticationException(
                    f"Partial success - additional methods required: {', '.join(msg.authentications)}"
                )
            else:
                return False
        else:
            raise AuthenticationException(
                f"Unexpected authentication response: {type(msg).__name__}"
            )

    def open_channel(
        self, kind: str, dest_addr: Optional[tuple[str, int]] = None
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

            # Create channel instance
            channel = Channel(self, channel_id)

        try:
            # Build channel open message
            type_specific_data = b""
            if kind == CHANNEL_DIRECT_TCPIP and dest_addr:
                type_specific_data = self._build_direct_tcpip_data(dest_addr)

            open_msg = ChannelOpenMessage(
                channel_type=kind,
                sender_channel=channel_id,
                initial_window_size=DEFAULT_WINDOW_SIZE,
                maximum_packet_size=DEFAULT_MAX_PACKET_SIZE,
                type_specific_data=type_specific_data,
            )

            # Send channel open request
            self._send_message(open_msg)

            # Wait for response (CRITICAL: release lock before calling _expect_message)
            response = self._expect_message(
                MSG_CHANNEL_OPEN_CONFIRMATION, MSG_CHANNEL_OPEN_FAILURE
            )

            if isinstance(response, ChannelOpenConfirmationMessage):
                # Channel opened successfully
                with self._lock:
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
                raise TransportException(
                    f"Channel open failed: {response.description} (code: {response.reason_code})"
                )

            else:
                raise TransportException(
                    f"Unexpected response to channel open: {type(response).__name__}"
                )

        except Exception as e:
            if isinstance(e, TransportException):
                raise
            raise TransportException(f"Failed to open channel: {e}") from e

    def _build_direct_tcpip_data(self, dest_addr: tuple[str, int]) -> bytes:
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
                if not channel.closed and channel._remote_channel_id is not None:
                    try:
                        close_msg = ChannelCloseMessage(channel._remote_channel_id)
                        self._send_message(close_msg)
                    except Exception:
                        pass  # Ignore errors during close

                # Remove from channels dict
                del self._channels[channel_id]

    def _handle_channel_message(self, msg: Message) -> None:
        """
        Handle channel-related messages.

        Args:
            msg: Channel message to handle
        """
        # All channel messages (80-100) have recipient_channel as first uint32
        recipient_channel = None
        if len(msg._data) >= 4:
            recipient_channel, _ = read_uint32(msg._data, 0)

        if recipient_channel is not None:
            with self._lock:
                channel = self._channels.get(recipient_channel)
                if channel:
                    if msg.msg_type == MSG_CHANNEL_DATA:
                        self._handle_channel_data(msg)
                    elif msg.msg_type == MSG_CHANNEL_EXTENDED_DATA:
                        self._handle_channel_extended_data(msg)
                    elif msg.msg_type == MSG_CHANNEL_EOF:
                        channel._handle_eof()
                    elif msg.msg_type == MSG_CHANNEL_CLOSE:
                        channel._handle_close()
                        # Remove from channels dict
                        del self._channels[recipient_channel]
                    elif msg.msg_type == MSG_CHANNEL_WINDOW_ADJUST:
                        self._handle_channel_window_adjust(msg)
                    elif msg.msg_type == MSG_CHANNEL_SUCCESS:
                        channel._handle_request_success()
                    elif msg.msg_type == MSG_CHANNEL_FAILURE:
                        channel._handle_request_failure()
                    elif msg.msg_type == MSG_CHANNEL_REQUEST:
                        self._handle_channel_request(msg)

                # Handle channel open even if channel doesn't exist yet (logical!)
                if msg.msg_type == MSG_CHANNEL_OPEN:
                    self._handle_channel_open(msg)
                else:
                    pass
                    # print(f"DEBUG: Channel {recipient_channel} not found in {list(self._channels.keys())}")

        # If it's a global request, handle it separately
        if msg.msg_type == MSG_GLOBAL_REQUEST:
            self._handle_global_request(msg)

    def _handle_channel_open(self, msg: Message) -> None:
        """
        Handle incoming channel open request.

        Args:
            msg: Channel open message
        """
        try:
            if not isinstance(msg, ChannelOpenMessage):
                msg = ChannelOpenMessage.unpack(msg.pack())

            channel_type = msg.channel_type  # type: ignore[attr-defined]
            sender_channel = msg.sender_channel  # type: ignore[attr-defined]
            initial_window_size = msg.initial_window_size  # type: ignore[attr-defined]
            maximum_packet_size = msg.maximum_packet_size  # type: ignore[attr-defined]
            type_specific_data = msg.type_specific_data  # type: ignore[attr-defined]

            if channel_type == CHANNEL_SESSION:
                self._handle_session_open(
                    sender_channel, initial_window_size, maximum_packet_size
                )
            elif channel_type == CHANNEL_FORWARDED_TCPIP:
                self._handle_forwarded_tcpip_open(
                    sender_channel,
                    initial_window_size,
                    maximum_packet_size,
                    type_specific_data,
                )
            else:
                # Unknown channel type - send failure
                failure_msg = ChannelOpenFailureMessage(
                    recipient_channel=sender_channel,
                    reason_code=SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
                    description=f"Unknown channel type: {channel_type}",
                    language="",
                )
                self._send_message(failure_msg)

        except Exception as e:
            # Send failure response
            try:
                failure_msg = ChannelOpenFailureMessage(
                    recipient_channel=sender_channel,
                    reason_code=SSH_OPEN_CONNECT_FAILED,
                    description=f"Channel open failed: {e}",
                    language="",
                )
                self._send_message(failure_msg)
            except Exception:
                pass

    def _handle_session_open(
        self, sender_channel: int, initial_window_size: int, maximum_packet_size: int
    ) -> None:
        """Handle session channel open request."""
        # 1. Check with server interface
        if self._server_interface:
            result = self._server_interface.check_channel_request(
                CHANNEL_SESSION, sender_channel
            )
            if result != 0:
                failure_msg = ChannelOpenFailureMessage(
                    sender_channel, result, "Administratively prohibited", ""
                )
                self._send_message(failure_msg)
                return

        # 2. Create channel
        with self._lock:
            channel_id = self._next_channel_id
            self._next_channel_id += 1
            channel = Channel(self, channel_id)
            channel._remote_channel_id = sender_channel
            channel._remote_window_size = initial_window_size
            channel._remote_max_packet_size = maximum_packet_size
            channel._local_window_size = DEFAULT_WINDOW_SIZE
            channel._local_max_packet_size = MAX_PACKET_SIZE
            self._channels[channel_id] = channel

        # 3. Send confirmation
        confirm_msg = ChannelOpenConfirmationMessage(
            recipient_channel=sender_channel,
            sender_channel=channel_id,
            initial_window_size=channel._local_window_size,
            maximum_packet_size=channel._local_max_packet_size,
        )
        self._send_message(confirm_msg)

        # 4. Notify server interface
        if self._server_interface:
            self._server_interface.on_channel_opened(channel)

    def _handle_forwarded_tcpip_open(
        self,
        sender_channel: int,
        initial_window_size: int,
        maximum_packet_size: int,
        type_specific_data: bytes,
    ) -> None:
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
                type_specific_data=b"",
            )
            self._send_message(confirm_msg)

            # Handle the forwarded connection
            if self._port_forwarding_manager:
                origin_addr = (originator_address, originator_port)
                dest_addr = (connected_address, connected_port)
                self._port_forwarding_manager.handle_forwarded_connection(
                    channel, origin_addr, dest_addr
                )

        except Exception as e:
            # Send failure response
            failure_msg = ChannelOpenFailureMessage(
                recipient_channel=sender_channel,
                reason_code=SSH_OPEN_CONNECT_FAILED,
                description=f"Forwarded connection failed: {e}",
                language="",
            )
            self._send_message(failure_msg)

    def _handle_channel_data(self, msg: Message) -> None:
        """Handle channel data message."""
        if isinstance(msg, ChannelDataMessage):
            # print(f"DEBUG: Data for channel {msg.recipient_channel}: {len(msg.data)} bytes")
            with self._lock:
                if msg.recipient_channel in self._channels:
                    channel = self._channels[msg.recipient_channel]
                    channel._handle_data(msg.data)
                else:
                    print(f"DEBUG: Data for UNKNOWN channel {msg.recipient_channel}")

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

                # Handle channel request
                success = channel._handle_request(request_type, request_data)

                # Send reply if requested
                if want_reply:
                    if success:
                        reply_msg = Message(MSG_CHANNEL_SUCCESS)
                    else:
                        reply_msg = Message(MSG_CHANNEL_FAILURE)

                    if channel._remote_channel_id is not None:
                        reply_msg.add_uint32(channel._remote_channel_id)
                        self._send_message(reply_msg)

    def _handle_exit_signal_request(self, channel: Channel, data: bytes) -> None:
        """Handle exit signal request data."""
        try:
            offset = 0
            signal_name_bytes, offset = read_string(data, offset)
            core_dumped, offset = read_boolean(data, offset)
            error_message_bytes, offset = read_string(data, offset)
            language_tag_bytes, offset = read_string(data, offset)

            signal_name = signal_name_bytes.decode(SSH_STRING_ENCODING)
            error_message = error_message_bytes.decode(
                SSH_STRING_ENCODING, errors="replace"
            )
            language_tag = language_tag_bytes.decode(
                SSH_STRING_ENCODING, errors="replace"
            )

            channel._handle_exit_signal(
                signal_name, core_dumped, error_message, language_tag
            )
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
            if channel._remote_channel_id is not None:
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
            if channel._remote_channel_id is not None:
                msg = Message(MSG_CHANNEL_WINDOW_ADJUST)
                msg.add_uint32(channel._remote_channel_id)
                msg.add_uint32(bytes_to_add)

                self._send_message(msg)

            # Update local window size
            channel._local_window_size += bytes_to_add

    def _send_channel_request(
        self, channel_id: int, request_type: str, want_reply: bool, data: bytes
    ) -> None:
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
            if channel._remote_channel_id is not None:
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
            if channel._remote_channel_id is not None:
                msg = Message(MSG_CHANNEL_EOF)
                msg.add_uint32(channel._remote_channel_id)

                self._send_message(msg)

    def _send_global_request(
        self, request_name: str, want_reply: bool, data: bytes = b""
    ) -> bool:
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
                response = self._expect_message(
                    MSG_REQUEST_SUCCESS, MSG_REQUEST_FAILURE
                )

                if response.msg_type == MSG_REQUEST_SUCCESS:
                    return True
                elif response.msg_type == MSG_REQUEST_FAILURE:
                    return False
                else:
                    raise TransportException(
                        f"Unexpected response to global request: {type(response).__name__}"
                    )

            return True  # No reply requested

        except Exception as e:
            if isinstance(e, TransportException):
                raise
            raise TransportException(f"Failed to send global request: {e}") from e

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

        except Exception:
            # Send failure reply if requested
            if want_reply:
                try:
                    reply_msg = Message(MSG_REQUEST_FAILURE)
                    self._send_message(reply_msg)
                except Exception:
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

            # Delegate to server interface for validation
            if self._server_mode and self._server_interface:
                return bool(
                    self._server_interface.check_port_forward_request(
                        bind_address, bind_port
                    )
                )

            # Default to reject if no server interface
            return False

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

            # Delegate to server interface for validation
            if self._server_mode and self._server_interface:
                return bool(
                    self._server_interface.check_port_forward_cancel_request(
                        bind_address, bind_port
                    )
                )

            # Default to reject if no server interface
            return False

        except Exception:
            return False

    def close(self) -> None:
        """Close transport and cleanup resources."""
        with self._lock:
            self._active = False
            if self._socket:
                try:
                    self._socket.close()
                except Exception:
                    pass

            # Close all channels
            for channel in list(self._channels.values()):
                try:
                    channel.close()
                except Exception:
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
            # RFC 4253, Section 4.2: Both sides MUST send an identification string.
            # It is recommended to send it before receiving the peer's string to avoid deadlock.
            self._send_version()
            self._recv_version()

        except Exception as e:
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Error during version exchange: {e}") from e

    def _send_version(self) -> None:
        """Send SSH version string."""
        version_string = create_version_string()
        self._client_version = version_string

        version_line = version_string + "\r\n"
        self._socket.sendall(version_line.encode(SSH_STRING_ENCODING))

    def _recv_version(self) -> None:
        """Receive and validate SSH version string with retries."""
        import time

        max_retries = 15
        retry_delay = 2.0
        version_line = b""

        for attempt in range(max_retries):
            try:
                # Read lines until we find the one starting with SSH-
                while True:
                    current_line = b""
                    # Read character by character until line ending
                    while True:
                        char = self._recv_bytes(1)
                        if not char:
                            self._logger.debug("Received EOF during banner read")
                            raise TransportException("Connection closed")

                        self._logger.debug(f"Banner read char: {repr(char)}")
                        current_line += char

                        # Check for line ending
                        if current_line.endswith(b"\r\n"):
                            current_line = current_line[:-2]
                            self._logger.debug(
                                f"Banner line completed (CRLF): {repr(current_line)}"
                            )
                            break
                        elif current_line.endswith(b"\n"):
                            current_line = current_line[:-1]
                            self._logger.debug(
                                f"Banner line completed (LF): {repr(current_line)}"
                            )
                            break

                        # Prevent excessive version line length
                        if len(current_line) > 255:
                            raise ProtocolException("Version line too long")

                    # RFC 4253: The server MAY send other lines of data before
                    # sending the version string. ... The identification string
                    # MUST start with 'SSH-'.
                    if current_line.startswith(b"SSH-"):
                        version_line = current_line
                        self._logger.debug(f"Found version line: {repr(version_line)}")
                        break

                    self._logger.debug(f"Ignoring non-SSH line: {repr(current_line)}")

                if version_line:
                    break

            except (TransportException, socket.timeout, ConnectionResetError) as e:
                # If connection closed unexpectedly, no point in retrying
                # BROADEN CLOSED CHECK: Include common socket error messages and types
                error_str = str(e).lower()
                is_closed = any(
                    term in error_str
                    for term in ["closed", "10053", "10054", "aborted", "reset"]
                )
                if (
                    isinstance(e, (ConnectionResetError, ConnectionAbortedError))
                    or is_closed
                ):
                    self._logger.debug(
                        f"Connection closed/reset during banner read: {e}"
                    )
                    if isinstance(e, TransportException):
                        raise
                    raise TransportException(
                        f"Connection closed during handshake: {e}"
                    ) from e

                if attempt < max_retries - 1:
                    self._logger.debug(
                        f"Banner read attempt {attempt + 1} failed, retrying..."
                    )
                    time.sleep(retry_delay)
                    version_line = b""  # Reset for next attempt
                    continue
                raise TransportException(
                    f"Failed to receive SSH banner after {max_retries} attempts: Timeout"
                )

        self._remote_version = version_line.decode().strip()
        self._logger.debug(f"Remote version: {self._remote_version}")

        try:
            version_string = version_line.decode(SSH_STRING_ENCODING)
        except UnicodeDecodeError:
            raise ProtocolException("Invalid version string encoding")

        # Parse and validate version
        try:
            protocol_version, software_version = parse_version_string(version_string)
        except ValueError as e:
            raise ProtocolException(f"Invalid version string: {e}") from e

        if not is_supported_version(protocol_version):
            raise ProtocolException(f"Unsupported protocol version: {protocol_version}")

        if self._server_mode:
            self._client_version = version_string
        else:
            self._server_version = version_string

    def _start_kex(self) -> None:
        """
        Start key exchange process in the background.
        Includes a 30-second watchdog to prevent hanging on stalled connections.
        """
        self._kex_in_progress = True
        self._kex_thread = threading.current_thread()
        timeout = 30.0

        # Set a temporary timeout for key exchange
        old_timeout = self._socket.gettimeout()
        self._socket.settimeout(timeout)

        try:
            # Send KEXINIT message with our supported algorithms
            self._send_kexinit()

            # Receive server's KEXINIT message
            self._recv_kexinit()

            # Now perform key exchange using KeyExchange class
            self._logger.debug("Starting DH exchange phase...")
            self._kex.start_kex()
            self._logger.debug("Rekeying handshake complete.")

        except Exception as e:
            self._kex_in_progress = False
            self._active = False
            try:
                self.close()
            except Exception:
                pass
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Rekeying failed or timed out: {e}") from e
        finally:
            self._kex_in_progress = False
            self._kex_thread = None  # type: ignore[assignment]
            # Reset byte count after successful rekey
            with self._lock:
                self._bytes_since_rekey = 0

            try:
                if self._socket and self._socket.fileno() != -1:
                    self._socket.settimeout(old_timeout)
            except (OSError, AttributeError):
                pass

    def _send_kexinit(self) -> None:
        """Send KEXINIT message with supported algorithms."""
        cookie = self._crypto_backend.generate_random(KEX_COOKIE_SIZE)

        # Define supported algorithms (modern preferences)
        kex_algorithms = [
            KEX_CURVE25519_SHA256,
            "curve25519-sha256@libssh.org",
            KEX_ECDH_SHA2_NISTP256,
            KEX_DH_GROUP14_SHA256,
        ]

        host_key_algorithms = [
            HOSTKEY_ED25519,
            HOSTKEY_ECDSA_SHA2_NISTP256,
            HOSTKEY_RSA_SHA2_256,
        ]

        encryption_algorithms = [
            CIPHER_AES256_CTR,
            CIPHER_AES192_CTR,
            CIPHER_AES128_CTR,
            CIPHER_CHACHA20_POLY1305,
            CIPHER_AES256_GCM,
            CIPHER_AES128_GCM,
        ]

        mac_algorithms = [
            MAC_HMAC_SHA2_256,
            MAC_HMAC_SHA2_512,
        ]

        compression_algorithms = [COMPRESS_NONE, "zlib@openssh.com"]

        kexinit_msg = KexInitMessage(
            cookie=cookie,
            kex_algorithms=kex_algorithms,
            server_host_key_algorithms=host_key_algorithms,
            encryption_algorithms_client_to_server=encryption_algorithms,
            encryption_algorithms_server_to_client=encryption_algorithms,
            mac_algorithms_client_to_server=mac_algorithms,
            mac_algorithms_server_to_client=mac_algorithms,
            compression_algorithms_client_to_server=compression_algorithms,
            compression_algorithms_server_to_client=compression_algorithms,
        )

        self._client_kexinit_blob = kexinit_msg.pack()
        self._send_message(kexinit_msg)

    def _recv_kexinit(self) -> None:
        """Receive and process KEXINIT message."""
        msg = self._expect_message(MSG_KEXINIT)

        if not isinstance(msg, KexInitMessage):
            raise ProtocolException(f"Expected KEXINIT, got {type(msg).__name__}")

        # Store peer's KEXINIT for algorithm negotiation
        self._peer_kexinit = msg

    def _check_rekey(self) -> None:
        """Check if rekeying is needed and start it if so."""
        if self._kex_in_progress or not self._active:
            return

        with self._lock:
            # Check byte limit, time limit, or sequence number (rekey every 2^31 packets)
            if (
                self._bytes_since_rekey >= self._rekey_bytes_limit
                or (time.time() - self._last_rekey_time) >= self._rekey_time_limit
                or self._sequence_number_out >= 0x80000000
                or self._sequence_number_in >= 0x80000000
            ):
                self._logger.debug(
                    f"Triggering rekeying: bytes={self._bytes_since_rekey}, limit={self._rekey_bytes_limit}"
                )
                # Trigger rekeying in a separate thread to avoid blocking current I/O
                # Set flag BEFORE starting thread to avoid race conditions
                self._kex_in_progress = True
                kex_thread = threading.Thread(
                    target=self._start_kex, name="RekeyingThread", daemon=True
                )
                self._kex_thread = kex_thread
                kex_thread.start()
                self._bytes_since_rekey = 0
                self._last_rekey_time = time.time()

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

            with self._lock:
                packet = self._build_packet(payload)

                if self._encryptor:
                    packet = self._encrypt_packet(packet)

                self._socket.sendall(packet)

                # Track bytes sent for rekeying
                if message.msg_type not in [
                    MSG_KEXINIT,
                    MSG_NEWKEYS,
                ] and not (MSG_KEXDH_INIT <= message.msg_type <= MSG_KEXDH_REPLY):
                    self._bytes_since_rekey += len(packet)
                    self._check_rekey()

                # If this was a NEWKEYS message, activate encryption AFTER sending it
                if message.msg_type == MSG_NEWKEYS:
                    self._activate_outbound_encryption()

                self._sequence_number_out = (self._sequence_number_out + 1) & 0xFFFFFFFF

        except Exception as e:
            raise TransportException(f"Failed to send message: {e}") from e

    def _read_message(self) -> Message:
        """
        Read next message from socket and dispatch if needed.
        Does NOT check the message queue.
        """
        while True:
            # If rekeying is in progress, only the rekeying thread is allowed to read from the socket.
            # Other threads must wait and check the queue (handled in _recv_message and _expect_message).
            if self._kex_in_progress and threading.current_thread() != getattr(
                self, "_kex_thread", None
            ):
                # We should not be here if called from _recv_message or _expect_message
                # as they have their own yielding loops, but for safety:
                return None  # type: ignore[return-value]

            try:
                # We need to hold the read_lock while reading from the socket to ensure
                # only one thread reads a complete packet at a time.
                with self._read_lock:
                    packet = self._recv_packet()
                    payload = extract_message_from_packet(packet)

                    with self._lock:
                        msg = Message.unpack(payload)
                        self._logger.debug(f"Received message type {msg.msg_type}")

                        # Track bytes received for rekeying (unless it's KEX)
                        if msg.msg_type not in [
                            MSG_KEXINIT,
                            MSG_NEWKEYS,
                        ] and not (MSG_KEXDH_INIT <= msg.msg_type <= MSG_KEXDH_REPLY):
                            self._bytes_since_rekey += len(packet)
                            self._check_rekey()

                        # ALWAYS increment sequence number for EVERY packet received
                        self._sequence_number_in = (
                            self._sequence_number_in + 1
                        ) & 0xFFFFFFFF

                        # Handle internal messages and extensions
                        # 7 = MSG_EXT_INFO (RFC 8308)
                        if msg.msg_type in [MSG_IGNORE, MSG_DEBUG, 7]:
                            continue

                        if msg.msg_type == MSG_DISCONNECT:
                            # Parse disconnect reason if possible
                            try:
                                d_msg = DisconnectMessage.unpack(payload)
                                # Type ignore because we know d_msg is a DisconnectMessage here
                                reason = getattr(d_msg, "description", "Unknown")
                                code = getattr(d_msg, "reason_code", 0)
                                raise TransportException(
                                    f"Disconnected: {reason} (code: {code})"
                                )
                            except Exception as e:
                                if isinstance(e, TransportException):
                                    raise
                                raise TransportException("Disconnected by peer")

                        if msg.msg_type == MSG_NEWKEYS:
                            self._activate_inbound_encryption()

                        if msg.msg_type == MSG_KEXINIT and not self._kex_in_progress:
                            # Peer initiated rekeying. Set flag immediately to prevent
                            # multiple threads, then queue message and start KEX thread.
                            self._kex_in_progress = True
                            with self._lock:
                                self._message_queue.append(msg)
                            threading.Thread(
                                target=self._start_kex, daemon=True
                            ).start()
                            continue

                        # Dispatch messages that need background handling (80, 90, 93-98)
                        # Return response messages (81, 82, 91, 92, 99, 100) to callers
                        if (
                            msg.msg_type == MSG_GLOBAL_REQUEST  # 80
                            or msg.msg_type == MSG_CHANNEL_OPEN  # 90
                            or (msg.msg_type >= 93 and msg.msg_type <= 98)
                        ):
                            self._handle_channel_message(msg)
                            continue

                        # Server-side specific messages
                        if self._server_mode:
                            if msg.msg_type == MSG_SERVICE_REQUEST:
                                self._handle_service_request(msg)
                                continue
                            if msg.msg_type == MSG_USERAUTH_REQUEST:
                                self._handle_userauth_request(msg)
                                continue

                        return msg

            except Exception as e:
                if isinstance(e, (TransportException, ProtocolException)):
                    raise
                raise TransportException(f"Failed to receive message: {e}") from e

    def _pump(self) -> None:
        """
        Read next message and either handle it or queue it.
        This is used for background message processing to ensure no
        messages are lost when multiple threads are waiting for messages.
        """
        msg = self._read_message()
        if msg:
            with self._lock:
                self._message_queue.append(msg)

    def _recv_message(self) -> Message:
        """
        Receive SSH message, checking the queue first.
        """
        while True:
            with self._lock:
                if self._message_queue:
                    return self._message_queue.pop(0)

                # If no rekeying or we are the rekeying thread, proceed to read
                if not self._kex_in_progress or threading.current_thread() == getattr(
                    self, "_kex_thread", None
                ):
                    break

            # Yield and wait for rekeying thread to process packets
            time.sleep(0.01)

        msg = self._read_message()
        if msg is None:
            # Should only happen if we yielded and then read_message returned None
            # because rekeying is still in progress (unlikely given the break above)
            return self._recv_message()  # type: ignore[unreachable]
        return msg

    def _expect_message(self, *allowed_types: int) -> Message:
        """
        Receive next message and ensure it's one of the allowed types.
        Messages of other types are queued for later processing.
        """
        while True:
            # 1. Check queue for allowed message
            while True:
                with self._lock:
                    for i, msg in enumerate(self._message_queue):
                        if msg.msg_type in allowed_types:
                            return self._message_queue.pop(i)

                    # If no rekeying or we are the rekeying thread, proceed to read
                    if (
                        not self._kex_in_progress
                        or threading.current_thread()
                        == getattr(self, "_kex_thread", None)
                    ):
                        break

                # Yield and wait for rekeying thread to process packets
                time.sleep(0.01)

            # 2. Not in queue, read from socket
            msg = self._read_message()
            if msg is None:
                continue  # type: ignore[unreachable]

            if msg.msg_type in allowed_types:
                return msg

            # 3. Not what we wanted, queue it for others
            with self._lock:
                self._message_queue.append(msg)

    def get_server_host_key(self) -> Optional[Any]:
        """
        Get server's public host key.

        Returns:
            PKey object or None if not available
        """
        if not hasattr(self, "_server_host_key_blob") or not self._server_host_key_blob:
            return None

        from ..crypto.pkey import PKey  # type: ignore[unreachable]

        try:
            return PKey.from_string(self._server_host_key_blob)
        except Exception:
            return None

    def _activate_outbound_encryption(self) -> None:
        """Activate outbound encryption using negotiated parameters."""
        if self._server_mode:
            cipher_name = self._cipher_s2c
            key = self._encryption_key_s2c
            iv = self._iv_s2c
            mac_name = self._mac_s2c
            mac_key = self._mac_key_s2c
        else:
            cipher_name = self._cipher_c2s
            key = self._encryption_key_c2s
            iv = self._iv_c2s
            mac_name = self._mac_c2s
            mac_key = self._mac_key_c2s

        if not cipher_name or not key:
            return

        if iv is None:
            raise TransportException("Encryption parameters not fully negotiated")

        self._encryptor = self._crypto_backend.create_cipher(cipher_name, key, iv)
        if not cipher_name.endswith("@openssh.com") and not cipher_name.endswith(
            "-gcm"
        ):
            # It's a standard cipher, needs separate encryptor instance for state
            self._encryptor_instance = self._encryptor.encryptor()
        else:
            self._encryptor_instance = None

        self._mac_out_active = mac_name
        self._mac_key_out_active = mac_key

    def _activate_inbound_encryption(self) -> None:
        """Activate inbound encryption using negotiated parameters."""
        if self._server_mode:
            cipher_name = self._cipher_c2s
            key = self._encryption_key_c2s
            iv = self._iv_c2s
            mac_name = self._mac_c2s
            mac_key = self._mac_key_c2s
        else:
            cipher_name = self._cipher_s2c
            key = self._encryption_key_s2c
            iv = self._iv_s2c
            mac_name = self._mac_s2c
            mac_key = self._mac_key_s2c

        if not cipher_name or not key:
            return

        if iv is None:
            raise TransportException("Encryption parameters not fully negotiated")

        self._decryptor = self._crypto_backend.create_cipher(cipher_name, key, iv)
        if not cipher_name.endswith("@openssh.com") and not cipher_name.endswith(
            "-gcm"
        ):
            # It's a standard cipher, needs separate decryptor instance for state
            self._decryptor_instance = self._decryptor.decryptor()
        else:
            self._decryptor_instance = None

        self._mac_in_active = mac_name
        self._mac_key_in_active = mac_key

    def _encrypt_packet(self, packet: bytes) -> bytes:
        """Encrypt SSH packet and add MAC if needed."""
        if self._encryptor_instance:
            # AES-CTR or similar
            encrypted = self._encryptor_instance.update(packet)

            # Add MAC
            if self._mac_out_active and self._mac_key_out_active:
                mac_data = struct.pack(">I", self._sequence_number_out) + packet
                mac = self._crypto_backend.compute_mac(
                    self._mac_out_active, self._mac_key_out_active, mac_data
                )
                return bytes(encrypted + mac)
            return bytes(encrypted)

        return packet  # Fallback for AEAD which should be handled above

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
        if self._cipher_c2s:
            # Get block size from cipher
            if "aes" in self._cipher_c2s:
                block_size = 16

        padding_length = block_size - (
            (len(payload) + PADDING_LENGTH_SIZE + PACKET_LENGTH_SIZE) % block_size
        )
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
        if self._decryptor_instance:
            # AES-CTR: length is encrypted
            encrypted_length = self._recv_bytes(PACKET_LENGTH_SIZE)
            length_data = self._decryptor_instance.update(encrypted_length)
            packet_length = struct.unpack(">I", length_data)[0]

            # Validate length
            if (
                packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE
                or packet_length > MAX_PACKET_SIZE
            ):
                raise ProtocolException(f"Invalid packet length: {packet_length}")

            # Read rest of packet (encrypted)
            encrypted_payload = self._recv_bytes(packet_length)
            packet_payload = self._decryptor_instance.update(encrypted_payload)

            # Verify MAC
            if self._mac_in_active and self._mac_key_in_active:
                # Get mac length from CipherSuite
                mac_info = self._kex._cipher_suite.get_mac_info(self._mac_in_active)
                mac_len = mac_info["digest_len"]

                received_mac = self._recv_bytes(mac_len)
                mac_data = (
                    struct.pack(">I", self._sequence_number_in)
                    + length_data
                    + packet_payload
                )
                expected_mac = self._crypto_backend.compute_mac(
                    self._mac_in_active, self._mac_key_in_active, mac_data
                )

                if received_mac != expected_mac:
                    raise TransportException("MAC verification failed")

            return bytes(length_data + packet_payload)
        else:
            # Unencrypted or AEAD (simplified unencrypted here for now to get connection working)
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
        # Check if we have enough in buffer
        with self._lock:
            if len(self._packet_buffer) >= length:
                data = self._packet_buffer[:length]
                self._packet_buffer = self._packet_buffer[length:]
                return data

            # Need more data, start with what we have
            data = self._packet_buffer
            self._packet_buffer = b""

        while len(data) < length:
            try:
                # If we need to read from socket, try to read more than requested to buffer it
                # Read up to 32KB at a time to reduce syscalls and round-trips
                to_read = max(32768, length - len(data))
                chunk = self._socket.recv(to_read)
                if not chunk:
                    self._logger.debug("Socket closed while receiving")
                    raise TransportException("Connection closed unexpectedly")

                self._logger.debug(f"Received {len(chunk)} bytes: {chunk!r}")
                data += chunk
            except socket.timeout:
                # If we have some data, but not enough, keep it in buffer
                with self._lock:
                    self._packet_buffer = data
                raise TransportException("Timeout receiving data")
            except OSError as e:
                raise TransportException(f"Socket error: {e}") from e

        # If we read more than requested, store the rest in buffer
        with self._lock:
            if len(data) > length:
                self._packet_buffer = data[length:]
                return data[:length]

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

    def set_server_interface(self, server_interface: Any) -> None:
        """
        Set server interface for authentication callbacks.

        Args:
            server_interface: Server interface implementing authentication methods
        """
        self._server_interface = server_interface

    def get_server_interface(self) -> Optional[Any]:
        """
        Get server interface.

        Returns:
            Server interface or None if not set
        """
        return self._server_interface

    def _handle_service_request(self, msg: Message) -> None:
        """Handle service request message (server mode)."""
        try:
            service_name_bytes, _ = read_string(msg._data, 0)
            service_name = service_name_bytes.decode(SSH_STRING_ENCODING)

            if service_name == SERVICE_USERAUTH:
                accept_msg = ServiceAcceptMessage(SERVICE_USERAUTH)
                self._send_message(accept_msg)
            else:
                self._logger.warning(f"Rejecting unsupported service: {service_name}")
        except Exception as e:
            self._logger.error(f"Error handling service request: {e}")

    def _handle_userauth_request(self, msg: Message) -> None:
        """Handle user authentication request message (server mode)."""
        if not self._server_interface:
            return

        try:
            # Unpack request
            auth_req = UserAuthRequestMessage._unpack_data(msg._data)
            username = auth_req.username
            method = auth_req.method

            result = AUTH_FAILED
            if method == AUTH_PASSWORD:
                offset = 0
                # Read boolean (False) before password
                change_requested, offset = read_boolean(auth_req.method_data, offset)
                password_bytes, offset = read_string(auth_req.method_data, offset)
                password = password_bytes.decode(SSH_STRING_ENCODING)
                result = self._server_interface.check_auth_password(username, password)
            elif method == AUTH_PUBLICKEY:
                # Basic publickey check if implemented
                result = self._server_interface.check_auth_publickey(username, None)

            # Send response
            if result == AUTH_SUCCESSFUL:
                self._authenticated = True
                self._server_interface.on_authentication_successful(username, method)
                self._send_message(UserAuthSuccessMessage())
            else:
                self._server_interface.on_authentication_failed(username, method)
                allowed_methods = self._server_interface.get_allowed_auths(username)
                self._send_message(UserAuthFailureMessage(allowed_methods, False))

        except Exception as e:
            self._logger.error(f"Error handling userauth request: {e}")
            self._send_message(UserAuthFailureMessage(["password"], False))

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
