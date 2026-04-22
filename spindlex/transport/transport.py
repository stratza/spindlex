"""
SSH Transport Layer Implementation

Core SSH transport functionality including protocol handshake, key exchange,
authentication, and secure packet transmission.
"""

import hmac
import logging
import socket
import struct
import threading
import time
from collections import deque
from typing import TYPE_CHECKING, Any, Optional, Union

if TYPE_CHECKING:
    from .forwarding import PortForwardingManager

from ..crypto.backend import default_crypto_backend
from ..exceptions import (
    AuthenticationException,
    ProtocolException,
    SSHException,
    TransportException,
)
from ..protocol.constants import (
    AUTH_FAILED,
    AUTH_KEYBOARD_INTERACTIVE,
    AUTH_PASSWORD,
    AUTH_PUBLICKEY,
    AUTH_SUCCESSFUL,
    CHANNEL_DIRECT_TCPIP,
    CHANNEL_FORWARDED_TCPIP,
    CHANNEL_SESSION,
    COMPRESS_NONE,
    DEFAULT_AUTH_TIMEOUT,
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_WINDOW_SIZE,
    KEX_COOKIE_SIZE,
    MAX_CHANNELS,
    MAX_PACKET_SIZE,
    MAX_VERSION_LINE_LENGTH,
    MIN_PACKET_SIZE,
    MIN_PADDING_SIZE,
    MSG_CHANNEL_CLOSE,
    MSG_CHANNEL_DATA,
    MSG_CHANNEL_EOF,
    MSG_CHANNEL_EXTENDED_DATA,
    MSG_CHANNEL_FAILURE,
    MSG_CHANNEL_OPEN,
    MSG_CHANNEL_OPEN_CONFIRMATION,
    MSG_CHANNEL_OPEN_FAILURE,
    MSG_CHANNEL_REQUEST,
    MSG_CHANNEL_SUCCESS,
    MSG_CHANNEL_WINDOW_ADJUST,
    MSG_DEBUG,
    MSG_DISCONNECT,
    MSG_GLOBAL_REQUEST,
    MSG_IGNORE,
    MSG_KEXDH_INIT,
    MSG_KEXDH_REPLY,
    MSG_KEXINIT,
    MSG_NEWKEYS,
    MSG_REQUEST_FAILURE,
    MSG_REQUEST_SUCCESS,
    MSG_SERVICE_ACCEPT,
    MSG_SERVICE_REQUEST,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_PK_OK,
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_SUCCESS,
    PACKET_LENGTH_SIZE,
    PADDING_LENGTH_SIZE,
    REKEY_SEQUENCE_THRESHOLD,
    SERVICE_CONNECTION,
    SERVICE_USERAUTH,
    SSH_OPEN_CONNECT_FAILED,
    SSH_OPEN_RESOURCE_SHORTAGE,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
    SSH_STRING_ENCODING,
    create_version_string,
    is_supported_version,
    parse_version_string,
)
from ..protocol.messages import (
    ChannelCloseMessage,
    ChannelDataMessage,
    ChannelOpenConfirmationMessage,
    ChannelOpenFailureMessage,
    ChannelOpenMessage,
    DisconnectMessage,
    KexInitMessage,
    Message,
    ServiceAcceptMessage,
    ServiceRequestMessage,
    UserAuthFailureMessage,
    UserAuthRequestMessage,
    UserAuthSuccessMessage,
)
from ..protocol.utils import (
    extract_message_from_packet,
    read_boolean,
    read_string,
    read_uint32,
    write_boolean,
    write_byte,
    write_string,
    write_uint32,
)
from .channel import Channel
from .kex import KeyExchange

# Bug #9 Fixed: Move dictionary to module-level constant to avoid recreating it on every call.
_CIPHER_BLOCK_SIZES = {
    "aes128-ctr": 16,
    "aes192-ctr": 16,
    "aes256-ctr": 16,
    "aes128-gcm@openssh.com": 16,
    "aes256-gcm@openssh.com": 16,
    "chacha20-poly1305@openssh.com": 8,
}


class HandledMessage:
    """Sentinel for messages handled internally by the transport."""

    msg_type = 0
    _data = b""


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
        rekey_time_limit: Optional[float] = None,
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
        self._encryptor_instance: Optional[Any] = None
        self._decryptor_instance: Optional[Any] = None

        self._sequence_number_in = 0
        self._sequence_number_out = 0
        self._packet_buffer = b""
        self._lock = threading.RLock()
        self._read_lock = threading.RLock()
        self._kex_condition = threading.Condition(self._lock)
        self._server_host_key_blob: Optional[bytes] = None

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
        self._message_queue: deque[Message] = deque()
        self._timeout = 10.0

        self._logger = logging.getLogger(__name__)
        self._strict_kex = False

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
        self, bytes_limit: Optional[int] = None, time_limit: Optional[float] = None
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
            with self._read_lock:
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

                    finally:
                        # Restore original socket timeout
                        try:
                            if self._socket and self._socket.fileno() != -1:
                                self._socket.settimeout(old_timeout)
                        except (OSError, AttributeError):
                            pass

                # Start key exchange (WITHOUT holding _lock)
                self._logger.debug("Starting KEX...")
                self._start_kex()
                self._logger.debug("KEX complete.")

                with self._lock:
                    self._active = True

        except (OSError, struct.error, SSHException) as e:
            self.close()
            if isinstance(e, SSHException):
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
            with self._read_lock:
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

                    finally:
                        # Restore original socket timeout
                        try:
                            if self._socket and self._socket.fileno() != -1:
                                self._socket.settimeout(old_timeout)
                        except (OSError, AttributeError):
                            pass

                # Start key exchange (WITHOUT holding _lock)
                self._logger.debug("Starting KEX...")
                self._start_kex()
                self._logger.debug("KEX complete.")

                with self._lock:
                    self._active = True

        except (OSError, struct.error, SSHException) as e:
            self.close()
            if isinstance(e, SSHException):
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

        except (OSError, struct.error, SSHException) as e:
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

        except (OSError, struct.error, SSHException) as e:
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
        elif msg.msg_type == MSG_USERAUTH_PK_OK:
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

        except (OSError, struct.error, SSHException) as e:
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
        except (OSError, struct.error, SSHException) as e:
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

            # Find next available channel ID (recycling IDs)
            channel_id = self._next_channel_id
            while channel_id in self._channels:
                channel_id = (channel_id + 1) % MAX_CHANNELS

            self._next_channel_id = (channel_id + 1) % MAX_CHANNELS

            # Create channel instance
            channel = Channel(self, channel_id)

            # Register channel BEFORE sending open request to avoid race
            self._channels[channel_id] = channel

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

                return channel

            elif isinstance(response, ChannelOpenFailureMessage):
                # Channel open failed - remove from channels
                with self._lock:
                    if channel_id in self._channels:
                        del self._channels[channel_id]
                raise TransportException(
                    f"Channel open failed: {response.description} (code: {response.reason_code})"
                )

            else:
                # Unexpected response - remove from channels
                with self._lock:
                    if channel_id in self._channels:
                        del self._channels[channel_id]
                raise TransportException(
                    f"Unexpected response to channel open: {type(response).__name__}"
                )

        except (OSError, struct.error, SSHException) as e:
            # Cleanup on error
            with self._lock:
                if channel_id in self._channels:
                    del self._channels[channel_id]
            if isinstance(e, SSHException):
                raise
            raise TransportException(f"Failed to open channel: {e}") from e

    def _build_direct_tcpip_data(self, dest_addr: tuple[str, int]) -> bytes:
        """Build type-specific data for direct-tcpip channel."""
        try:
            originator_ip = self._socket.getsockname()[0]
        except OSError:
            originator_ip = "127.0.0.1"
        data = bytearray()
        data.extend(write_string(dest_addr[0]))  # destination host
        data.extend(write_uint32(dest_addr[1]))  # destination port
        data.extend(write_string(originator_ip))  # originator IP
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
                    except (OSError, TransportException):
                        pass  # Ignore errors during close

                # Remove from channels dict
                del self._channels[channel_id]

    def _handle_channel_message(self, msg: Message) -> None:
        """
        Handle channel-related messages.

        Args:
            msg: Channel message to handle
        """
        # Handle messages that don't have a recipient_channel field first
        if msg.msg_type == MSG_CHANNEL_OPEN:
            self._handle_channel_open(msg)
            return

        if msg.msg_type == MSG_GLOBAL_REQUEST:
            self._handle_global_request(msg)
            return

        # Other channel messages (91-100) have recipient_channel as first uint32
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
                    else:
                        self._logger.debug(
                            f"Unhandled channel message type {msg.msg_type} for channel {recipient_channel}"
                        )
                else:
                    self._logger.debug(
                        f"Message type {msg.msg_type} for unknown channel {recipient_channel}"
                    )

    def _handle_channel_open(self, msg: Message) -> None:
        """
        Handle incoming channel open request.

        Args:
            msg: Channel open message
        """
        # Parse the remote sender_channel up-front so we always have a valid
        # id to reference in a failure response, even if later fields are
        # malformed. If even this fails we cannot reply safely — the peer
        # will time out, which is the expected behaviour for a garbage frame.
        sender_channel: Optional[int] = None
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

        except (
            OSError,
            struct.error,
            ValueError,
            UnicodeDecodeError,
            SSHException,
        ) as e:
            # Do not leak internal exception details to the remote peer.
            self._logger.error("Channel open failed: %s", e)
            if sender_channel is None:
                # No valid sender id parsed — can't send a targeted failure.
                return
            try:
                failure_msg = ChannelOpenFailureMessage(
                    recipient_channel=sender_channel,
                    reason_code=SSH_OPEN_CONNECT_FAILED,
                    description="Channel open failed",
                    language="",
                )
                self._send_message(failure_msg)
            except (TransportException, OSError) as send_err:
                self._logger.debug(
                    "Could not send channel open failure response: %s", send_err
                )

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
            # Bug #2 Fixed: Enforce MAX_CHANNELS limit on server-side opens
            if len(self._channels) >= MAX_CHANNELS:
                failure_msg = ChannelOpenFailureMessage(
                    sender_channel,
                    SSH_OPEN_RESOURCE_SHORTAGE,
                    "Too many open channels",
                    "",
                )
                self._send_message(failure_msg)
                return

            channel_id = self._next_channel_id
            self._next_channel_id = (self._next_channel_id + 1) % MAX_CHANNELS

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
                # Bug #2 Fixed: Enforce MAX_CHANNELS limit on server-side opens
                if len(self._channels) >= MAX_CHANNELS:
                    failure_msg = ChannelOpenFailureMessage(
                        sender_channel,
                        SSH_OPEN_RESOURCE_SHORTAGE,
                        "Too many open channels",
                        "",
                    )
                    self._send_message(failure_msg)
                    return

                channel_id = self._next_channel_id
                self._next_channel_id = (self._next_channel_id + 1) % MAX_CHANNELS

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

        except (
            OSError,
            struct.error,
            ValueError,
            UnicodeDecodeError,
            SSHException,
        ) as e:
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
            with self._lock:
                if msg.recipient_channel in self._channels:
                    channel = self._channels[msg.recipient_channel]
                    channel._handle_data(msg.data)
                else:
                    self._logger.debug(
                        f"Data for UNKNOWN channel {msg.recipient_channel}"
                    )

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
        except (struct.error, ValueError, UnicodeDecodeError, IndexError):
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

            # Defensive check only — the channel layer owns _remote_window_size
            # and is the single decrement point (mirrors the async path in
            # AsyncChannel.send). Transport must not decrement here, otherwise
            # the window would be debited twice per send.
            self._logger.debug(
                f"Channel {channel_id} window: remote={channel._remote_window_size}, max_packet={channel._remote_max_packet_size}, data={len(data)}"
            )
            if len(data) > channel._remote_window_size:
                raise TransportException("Remote window size exceeded")

            if len(data) > channel._remote_max_packet_size:
                raise TransportException("Remote max packet size exceeded")

            if channel._remote_channel_id is not None:
                data_msg = ChannelDataMessage(channel._remote_channel_id, data)
                self._send_message(data_msg)

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

        except (OSError, struct.error, SSHException) as e:
            if isinstance(e, SSHException):
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

        except (OSError, struct.error, ValueError, UnicodeDecodeError, SSHException):
            # Send failure reply if requested
            if want_reply:
                try:
                    reply_msg = Message(MSG_REQUEST_FAILURE)
                    self._send_message(reply_msg)
                except (OSError, TransportException):
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

        except (struct.error, ValueError, UnicodeDecodeError, IndexError):
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

        except (struct.error, ValueError, UnicodeDecodeError, IndexError):
            return False

    def __enter__(self) -> "Transport":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def close(self) -> None:
        """Close transport and cleanup resources."""
        kex_thread: Optional[threading.Thread] = None
        # Snapshot the channel list under the transport lock, then release it
        # before calling Channel.close(). Channel.close() takes the channel
        # lock and then re-enters _close_channel which takes the transport
        # lock — holding the transport lock here while calling channel.close()
        # would invert the order taken by any concurrent caller of
        # Channel.close() and deadlock the two threads.
        with self._lock:
            self._active = False
            kex_thread = getattr(self, "_kex_thread", None)
            channels_snapshot = list(self._channels.values())
            sock = self._socket

        for channel in channels_snapshot:
            try:
                channel.close()
            except (OSError, SSHException):
                pass

        with self._lock:
            self._channels.clear()

        if sock is not None:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass

        # Join kex thread outside lock to avoid deadlock.
        # Socket closure above ensures the thread unblocks promptly.
        if kex_thread is not None and kex_thread.is_alive():
            kex_thread.join(timeout=5.0)

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

        except (OSError, struct.error, SSHException) as e:
            if isinstance(e, SSHException):
                raise
            raise TransportException(f"Error during version exchange: {e}") from e

    def _send_version(self) -> None:
        """Send SSH version string."""
        version_string = create_version_string()
        if self._server_mode:
            self._server_version = version_string
        else:
            self._client_version = version_string

        version_line = version_string + "\r\n"
        self._socket.sendall(version_line.encode(SSH_STRING_ENCODING))

    def _recv_version(self) -> None:
        """Receive and validate SSH version string."""
        version_line = b""
        _MAX_BANNER_LINES = 20

        # RFC 4253: The server MAY send other lines of data before
        # sending the version string. ... The identification string
        # MUST start with 'SSH-'.
        banner_lines = 0
        while True:
            if banner_lines > _MAX_BANNER_LINES:
                raise ProtocolException(
                    "Too many banner lines before SSH version string"
                )
            banner_lines += 1

            # Bug #13 Fixed: Optimized reading of version/banner lines to avoid byte-by-byte recv() calls
            # We read up to MAX_VERSION_LINE_LENGTH + a bit more, then split by lines.
            # This is safe because _recv_bytes already uses a 32KB internal buffer.
            # The byte-by-byte loop here was redundant and slow.

            current_line = b""
            while True:
                # Still read one byte at a time conceptually via _recv_bytes,
                # but _recv_bytes is now buffered, so it's much faster.
                # However, to be even more efficient, we could peek at the buffer.
                # For now, just ensuring _recv_bytes buffering is leveraged.
                char = self._recv_bytes(1)
                if not char:
                    raise TransportException("Connection closed during banner read")

                current_line += char
                if char == b"\n":
                    # Remove trailing CRLF or LF
                    if current_line.endswith(b"\r\n"):
                        current_line = current_line[:-2]
                    else:
                        current_line = current_line[:-1]
                    break

                if len(current_line) > MAX_VERSION_LINE_LENGTH:
                    raise ProtocolException("Version line too long")

            if current_line.startswith(b"SSH-"):
                version_line = current_line
                break

            self._logger.debug(f"Ignoring non-SSH line: {repr(current_line)}")

        try:
            version_string = version_line.decode(SSH_STRING_ENCODING)
        except UnicodeDecodeError:
            raise ProtocolException("Invalid version string encoding")

        self._remote_version = version_string.strip()
        self._logger.debug(f"Remote version: {self._remote_version}")

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
        with self._lock:
            self._kex_in_progress = True
            self._kex_thread = threading.current_thread()
            self._kex_condition.notify_all()

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

        except (OSError, struct.error, SSHException) as e:
            # _kex_in_progress / _active are reset under the lock in finally
            with self._lock:
                self._active = False
            try:
                self.close()
            except (OSError, SSHException):
                pass
            if isinstance(e, SSHException):
                raise
            raise TransportException(f"Rekeying failed or timed out: {e}") from e
        finally:
            # Clear flags and reset byte counter atomically under the lock so
            # _check_rekey / _send_packet observers see a consistent snapshot.
            with self._lock:
                self._kex_in_progress = False
                self._kex_thread = None  # type: ignore[assignment]
                self._bytes_since_rekey = 0
                self._last_rekey_time = time.time()
                self._kex_condition.notify_all()

            try:
                if self._socket and self._socket.fileno() != -1:
                    self._socket.settimeout(old_timeout)
            except (OSError, AttributeError):
                pass

    def _send_kexinit(self) -> None:
        """Send KEXINIT message with supported algorithms."""
        cookie = self._crypto_backend.generate_random(KEX_COOKIE_SIZE)

        # Use algorithms from CipherSuite to ensure consistency
        cipher_suite = self._kex._cipher_suite

        # Strict KEX (Terrapin defense)
        kex_algorithms = list(cipher_suite.KEX_ALGORITHMS)
        if self._server_mode:
            # Server sends kex-strict-s
            kex_algorithms = [
                a for a in kex_algorithms if a != "kex-strict-c-v01@openssh.com"
            ]
            if "kex-strict-s-v01@openssh.com" not in kex_algorithms:
                kex_algorithms.append("kex-strict-s-v01@openssh.com")
            # Servers don't send ext-info-c
            kex_algorithms = [a for a in kex_algorithms if a != "ext-info-c"]
        else:
            # Client sends kex-strict-c (already in list likely, but ensure s is out)
            kex_algorithms = [
                a for a in kex_algorithms if a != "kex-strict-s-v01@openssh.com"
            ]

        kexinit_msg = KexInitMessage(
            cookie=cookie,
            kex_algorithms=kex_algorithms,
            server_host_key_algorithms=cipher_suite.HOST_KEY_ALGORITHMS,
            encryption_algorithms_client_to_server=cipher_suite.ENCRYPTION_ALGORITHMS,
            encryption_algorithms_server_to_client=cipher_suite.ENCRYPTION_ALGORITHMS,
            mac_algorithms_client_to_server=cipher_suite.MAC_ALGORITHMS,
            mac_algorithms_server_to_client=cipher_suite.MAC_ALGORITHMS,
            compression_algorithms_client_to_server=[COMPRESS_NONE],
            compression_algorithms_server_to_client=[COMPRESS_NONE],
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

        # Check for strict KEX marker from peer
        peer_strict_marker = (
            "kex-strict-c-v01@openssh.com"
            if self._server_mode
            else "kex-strict-s-v01@openssh.com"
        )
        if peer_strict_marker in msg.kex_algorithms:
            self._strict_kex = True
            self._logger.debug("Strict KEX mode enabled (Terrapin defense)")

    def _check_rekey(self) -> None:
        """Check if rekeying is needed and start it if so."""
        if not self._active:
            return

        with self._lock:
            if self._kex_in_progress:
                return

            # Check byte limit, time limit, or sequence number (rekey every 2^31 packets)
            if (
                self._bytes_since_rekey >= self._rekey_bytes_limit
                or (time.time() - self._last_rekey_time) >= self._rekey_time_limit
                or self._sequence_number_out >= REKEY_SEQUENCE_THRESHOLD
                or self._sequence_number_in >= REKEY_SEQUENCE_THRESHOLD
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

                # Encrypt if we have an active cipher (standard or AEAD)
                if self._encryptor_instance or getattr(
                    self, "_cipher_out_active", None
                ):
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

                # Strict-KEX (kex-strict-*@openssh.com): after NEWKEYS, the next
                # outbound packet must use sequence number 0. Reset happens AFTER
                # the unconditional increment above so seq 0 is used for the next
                # _send_message call; doing it in _activate_outbound_encryption
                # would be clobbered by the increment and produce seq=1.
                if message.msg_type == MSG_NEWKEYS and self._strict_kex:
                    self._sequence_number_out = 0
                    self._logger.debug("Sequence number (out) reset for strict KEX")

        except (OSError, struct.error) as e:
            raise TransportException(f"Failed to send message: {e}") from e

    def _read_message(self, single_pump: bool = False) -> Optional[Message]:
        """
        Read next message from socket and dispatch if needed.
        Does NOT check the message queue.
        """
        while True:
            # If rekeying is in progress, only the rekeying thread is allowed to read from the socket.
            # Other threads must wait and check the queue (handled in _recv_message and _expect_message).
            if (
                self._kex_in_progress
                and not getattr(self, "_is_async", False)
                and threading.current_thread() != getattr(self, "_kex_thread", None)
            ):
                # We should not be here if called from _recv_message or _expect_message
                # as they have their own yielding loops, but for safety:
                return None

            try:
                # We need to hold the read_lock while reading from the socket to ensure
                # only one thread reads a complete packet at a time.
                with self._read_lock:
                    packet = self._recv_packet()
                    payload = extract_message_from_packet(packet)

                    with self._lock:
                        msg = Message.unpack(payload)

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
                            if single_pump:
                                return HandledMessage()  # type: ignore[return-value]
                            continue

                        if msg.msg_type == MSG_DISCONNECT:
                            # Parse disconnect reason if possible
                            try:
                                d_msg = DisconnectMessage.unpack(payload)
                                # Type ignore because we know d_msg is a DisconnectMessage here
                                reason = getattr(d_msg, "description", "Unknown")
                                code = getattr(d_msg, "reason_code", 0)
                            except (
                                struct.error,
                                ValueError,
                                UnicodeDecodeError,
                                IndexError,
                            ):
                                raise TransportException("Disconnected by peer")
                            raise TransportException(
                                f"Disconnected: {reason} (code: {code})"
                            )

                        if msg.msg_type == MSG_NEWKEYS:
                            self._activate_inbound_encryption()

                        if msg.msg_type == MSG_KEXINIT and not self._kex_in_progress:
                            # Peer initiated rekeying. Set flag immediately to prevent
                            # multiple threads, then queue message and start KEX thread.
                            self._kex_in_progress = True
                            self._message_queue.append(msg)
                            threading.Thread(
                                target=self._start_kex, daemon=True
                            ).start()
                            if single_pump:
                                return HandledMessage()  # type: ignore[return-value]
                            continue

                        if (
                            msg.msg_type == MSG_GLOBAL_REQUEST  # 80
                            or msg.msg_type == MSG_CHANNEL_OPEN  # 90
                            or (msg.msg_type >= 93 and msg.msg_type <= 100)
                        ):
                            self._handle_channel_message(msg)
                            if single_pump:
                                return HandledMessage()  # type: ignore[return-value]
                            continue

                        # Server-side specific messages
                        if self._server_mode:
                            if msg.msg_type == MSG_SERVICE_REQUEST:
                                self._handle_service_request(msg)
                                if single_pump:
                                    return HandledMessage()  # type: ignore[return-value]
                                continue
                            if msg.msg_type == MSG_USERAUTH_REQUEST:
                                self._handle_userauth_request(msg)
                                if single_pump:
                                    return HandledMessage()  # type: ignore[return-value]
                                continue

                        return msg

            except (OSError, struct.error, SSHException) as e:
                if isinstance(e, SSHException):
                    raise
                raise TransportException(f"Failed to receive message: {e}") from e

    def _pump(self) -> Optional[Union[Message, type[HandledMessage]]]:
        """
        Read next message and either handle it or queue it.
        This is used for background message processing to ensure no
        messages are lost when multiple threads are waiting for messages.

        Returns:
            The message read, or HandledMessage if it was handled internally.
        """
        # First check if we already have messages in the queue
        with self._lock:
            if self._message_queue:
                return self._message_queue[0]

        msg = self._read_message(single_pump=True)
        if msg:
            if isinstance(msg, Message):
                with self._lock:
                    self._message_queue.append(msg)
            return msg
        return None

    def _recv_message(self) -> Message:
        """
        Receive SSH message, checking the queue first.
        """
        while True:
            while True:
                with self._lock:
                    if self._message_queue:
                        return self._message_queue.popleft()

                    # If no rekeying or we are the rekeying thread, proceed to read
                    if (
                        not self._kex_in_progress
                        or threading.current_thread()
                        == getattr(self, "_kex_thread", None)
                    ):
                        break

                    # Wait for rekeying thread to process packets or finish KEX
                    self._kex_condition.wait(0.1)

            # Inner loop exited via break — safe to read from socket now
            msg = self._read_message()
            if msg is not None:
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
                    for i, queued in enumerate(self._message_queue):
                        if queued.msg_type in allowed_types:
                            del self._message_queue[i]
                            return queued

                    # If no rekeying or we are the rekeying thread, proceed to read
                    if (
                        not self._kex_in_progress
                        or threading.current_thread()
                        == getattr(self, "_kex_thread", None)
                    ):
                        break

                    # Wait for rekeying thread to process packets or finish KEX
                    self._kex_condition.wait(0.1)

            # 2. Not in queue, read from socket
            read_msg = self._read_message()
            if read_msg is None:
                continue

            if read_msg.msg_type in allowed_types:
                return read_msg

            # 3. Not what we wanted, queue it for others
            with self._lock:
                self._message_queue.append(read_msg)

    def get_server_host_key(self) -> Optional[Any]:
        """
        Get server's public host key.

        Returns:
            PKey object or None if not available
        """
        if not self._server_host_key_blob:
            return None

        from ..crypto.pkey import PKey

        try:
            return PKey.from_string(self._server_host_key_blob)
        except (ValueError, struct.error, SSHException):
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

        self._cipher_out_active = cipher_name
        self._encryption_key_out_active = key
        self._iv_out_active = iv

        self._logger.info(f"Activating outbound encryption: {cipher_name}")

        encryptor = self._crypto_backend.create_cipher(cipher_name, key, iv)
        self._logger.debug(
            f"Activating {cipher_name}: key_len={len(key)}, iv_len={len(iv)}"
        )
        if not cipher_name.endswith("@openssh.com") and not cipher_name.endswith(
            "-gcm"
        ):
            # It's a standard cipher, needs separate encryptor instance for state
            self._encryptor_instance = encryptor.encryptor()
        else:
            self._encryptor_instance = None

        self._mac_out_active = mac_name
        self._mac_key_out_active = mac_key

        # NOTE: strict-KEX outbound sequence reset happens in _send_message
        # AFTER the unconditional ``seq_out += 1`` that follows this call,
        # so the next packet after NEWKEYS goes out with sequence 0 as
        # required by the kex-strict-*@openssh.com extension. Resetting
        # here would be overwritten by the +1 and produce seq=1.

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

        self._cipher_in_active = cipher_name
        self._encryption_key_in_active = key
        self._iv_in_active = iv

        self._logger.info(f"Activating inbound encryption: {cipher_name}")

        decryptor = self._crypto_backend.create_cipher(cipher_name, key, iv)
        if not cipher_name.endswith("@openssh.com") and not cipher_name.endswith(
            "-gcm"
        ):
            # It's a standard cipher, needs separate decryptor instance for state
            self._decryptor_instance = decryptor.decryptor()
        else:
            self._decryptor_instance = None

        self._mac_in_active = mac_name
        self._mac_key_in_active = mac_key

        if self._strict_kex:
            self._sequence_number_in = 0
            self._logger.debug("Sequence number (in) reset for strict KEX")

    def _encrypt_packet(self, packet: bytes) -> bytes:
        """Encrypt SSH packet and add MAC if needed."""
        if self._encryptor_instance:
            # AES-CTR or similar
            encrypted = self._encryptor_instance.update(packet)

            # Add MAC
            if self._mac_out_active and self._mac_key_out_active:
                mac_data = (
                    struct.pack(">I", self._sequence_number_out & 0xFFFFFFFF) + packet
                )
                mac = self._crypto_backend.compute_mac(
                    self._mac_out_active, self._mac_key_out_active, mac_data
                )
                return bytes(encrypted + mac)
            return bytes(encrypted)

        # Handle AEAD ciphers
        if hasattr(self, "_cipher_out_active") and self._cipher_out_active:
            cipher_name = self._cipher_out_active
            if cipher_name == "chacha20-poly1305@openssh.com":
                nonce = struct.pack(">Q", self._sequence_number_out)
                return self._crypto_backend.encrypt(
                    cipher_name, self._encryption_key_out_active, nonce, packet
                )
            elif cipher_name in ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com"]:
                nonce = self._iv_out_active + struct.pack(
                    ">Q", self._sequence_number_out
                )
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.debug(
                        "AEAD encrypt cipher=%s data_len=%d",
                        cipher_name,
                        len(packet),
                    )
                encrypted = self._crypto_backend.encrypt(
                    cipher_name, self._encryption_key_out_active, nonce, packet
                )
                return encrypted

        return packet

    def _build_packet(self, payload: bytes) -> bytes:
        """
        Build SSH packet from payload.

        Args:
            payload: Message payload

        Returns:
            Complete SSH packet
        """
        # Bug #9 Fixed: Moved _CIPHER_BLOCK_SIZES to class level or module level
        # (Using a local cache variable here for efficiency is fine if it were static,
        # but the review specifically complained about recreating the dict on every call)

        cipher_name = getattr(self, "_cipher_out_active", None) or getattr(
            self, "_cipher_c2s", None
        )
        block_size = _CIPHER_BLOCK_SIZES.get(cipher_name, 8) if cipher_name else 8

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
                    struct.pack(">I", self._sequence_number_in & 0xFFFFFFFF)
                    + length_data
                    + packet_payload
                )
                expected_mac = self._crypto_backend.compute_mac(
                    self._mac_in_active, self._mac_key_in_active, mac_data
                )

                if not hmac.compare_digest(received_mac, expected_mac):
                    raise TransportException("MAC verification failed")

            return bytes(length_data + packet_payload)

        # Handle AEAD ciphers
        if hasattr(self, "_cipher_in_active") and self._cipher_in_active:
            cipher_name = self._cipher_in_active
            if cipher_name == "chacha20-poly1305@openssh.com":
                nonce = struct.pack(">Q", self._sequence_number_in)

                # 1. Receive and decrypt length
                enc_len = self._recv_bytes(PACKET_LENGTH_SIZE)
                dec_len_bytes = self._crypto_backend.decrypt_length(
                    cipher_name, self._encryption_key_in_active, nonce, enc_len
                )
                packet_length = struct.unpack(">I", dec_len_bytes)[0]

                # Validate length
                if packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE:
                    raise ProtocolException(f"Invalid packet length: {packet_length}")

                # 2. Receive rest of packet + MAC (16 bytes)
                remaining_len = packet_length + 16
                rest_of_packet = self._recv_bytes(remaining_len)

                # 3. Decrypt and verify
                full_encrypted = enc_len + rest_of_packet
                return self._crypto_backend.decrypt(
                    cipher_name, self._encryption_key_in_active, nonce, full_encrypted
                )

            elif cipher_name in ["aes128-gcm@openssh.com", "aes256-gcm@openssh.com"]:
                nonce = self._iv_in_active + struct.pack(">Q", self._sequence_number_in)

                # 1. Receive length (unencrypted)
                len_data = self._recv_bytes(PACKET_LENGTH_SIZE)
                packet_length = struct.unpack(">I", len_data)[0]

                # Validate length
                if packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE:
                    raise ProtocolException(f"Invalid packet length: {packet_length}")

                # 2. Receive rest of packet + Tag (16 bytes)
                # RFC 5647: packet_length excludes the length field itself and the MAC (tag).
                remaining_len = packet_length + 16
                rest_of_packet = self._recv_bytes(remaining_len)

                # 3. Decrypt and verify
                full_packet = len_data + rest_of_packet
                if self._logger.isEnabledFor(logging.DEBUG):
                    self._logger.debug(
                        "AEAD decrypt cipher=%s data_len=%d",
                        cipher_name,
                        len(full_packet),
                    )
                decrypted = self._crypto_backend.decrypt(
                    cipher_name, self._encryption_key_in_active, nonce, full_packet
                )
                return decrypted

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

        # Verify MAC if present (even if unencrypted)
        if self._mac_in_active and self._mac_key_in_active:
            mac_info = self._kex._cipher_suite.get_mac_info(self._mac_in_active)
            mac_len = mac_info["digest_len"]
            received_mac = self._recv_bytes(mac_len)

            mac_data = (
                struct.pack(">I", self._sequence_number_in & 0xFFFFFFFF)
                + length_data
                + packet_data
            )
            expected_mac = self._crypto_backend.compute_mac(
                self._mac_in_active, self._mac_key_in_active, mac_data
            )

            if not hmac.compare_digest(received_mac, expected_mac):
                raise TransportException("MAC verification failed")

        # Return complete packet
        return length_data + packet_data

    def _recv_bytes(self, length: int) -> bytes:
        """
        Receive exact number of bytes from socket using internal buffering.

        Args:
            length: Number of bytes to receive

        Returns:
            Received bytes

        Raises:
            TransportException: If receive fails
        """
        # Locking model:
        # * ``self._lock`` guards ``self._packet_buffer`` and is held only for
        #   short, non-blocking buffer slices.
        # * ``self._read_lock`` serializes the actual blocking ``socket.recv``
        #   call so two threads cannot race the kernel for the same socket.
        # We do NOT hold ``self._read_lock`` while consuming from the buffer:
        # any thread that already has buffered bytes available can return
        # without contending with a peer that is blocked in ``recv``.
        while True:
            with self._lock:
                if len(self._packet_buffer) >= length:
                    data = self._packet_buffer[:length]
                    self._packet_buffer = self._packet_buffer[length:]
                    return data

            with self._read_lock:
                # Re-check buffer after acquiring _read_lock: another reader
                # may have refilled it while we waited.
                with self._lock:
                    if len(self._packet_buffer) >= length:
                        data = self._packet_buffer[:length]
                        self._packet_buffer = self._packet_buffer[length:]
                        return data
                    short_by = length - len(self._packet_buffer)

                # Read at least 32KB to leverage buffering. The blocking
                # ``recv`` happens with ``_read_lock`` held but ``self._lock``
                # released, so other threads can both send messages and serve
                # themselves from the existing buffer.
                try:
                    to_read = max(32768, short_by)
                    chunk = self._socket.recv(to_read)
                except socket.timeout:
                    raise TransportException("Timeout receiving data")
                except OSError as e:
                    raise TransportException(f"Socket error: {e}") from e

                if not chunk:
                    self._logger.debug("Socket closed while receiving")
                    self.close()
                    raise TransportException("Connection closed unexpectedly")

                with self._lock:
                    self._packet_buffer += chunk

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
        except (
            OSError,
            struct.error,
            ValueError,
            UnicodeDecodeError,
            SSHException,
        ) as e:
            self._logger.error(f"Error handling service request: {e}")

    def _handle_userauth_request(self, msg: Message) -> None:
        """Handle user authentication request message (server mode)."""
        if not self._server_interface:
            # Bug #5 Fixed: Send failure instead of silently dropping
            self._send_message(UserAuthFailureMessage(["password", "publickey"], False))
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
                # Bug #1 Fixed: Verify signature for publickey auth
                offset = 0
                has_signature, offset = read_boolean(auth_req.method_data, offset)
                algo_name_bytes, offset = read_string(auth_req.method_data, offset)
                algo_name = algo_name_bytes.decode(SSH_STRING_ENCODING)
                key_blob, offset = read_string(auth_req.method_data, offset)

                from ..crypto.pkey import PKey

                try:
                    key = PKey.from_string(key_blob)
                except (ValueError, struct.error, SSHException):
                    # Invalid key blob
                    self._send_message(UserAuthFailureMessage(["publickey"], False))
                    return

                if not has_signature:
                    # Client is just querying if the key is acceptable
                    if self._server_interface.check_auth_publickey(username, key):
                        # Send PK_OK to indicate key is acceptable
                        # MSG_USERAUTH_PK_OK = 60
                        pk_ok = Message(60)
                        pk_ok._data.extend(write_string(algo_name))
                        pk_ok._data.extend(write_string(key_blob))
                        self._send_message(pk_ok)
                        return
                    else:
                        result = AUTH_FAILED
                else:
                    # Full authentication request with signature
                    signature, offset = read_string(auth_req.method_data, offset)

                    # Build data that was signed:
                    # string session_id, byte MSG_USERAUTH_REQUEST, string username,
                    # string service, string "publickey", boolean TRUE,
                    # string algo_name, string key_blob
                    signed_data = write_string(self._session_id or b"")
                    signed_data += write_byte(MSG_USERAUTH_REQUEST)
                    signed_data += write_string(username)
                    signed_data += write_string(auth_req.service)
                    signed_data += write_string(AUTH_PUBLICKEY)
                    signed_data += write_boolean(True)
                    signed_data += write_string(algo_name)
                    signed_data += write_string(key_blob)

                    if key.verify(signature, signed_data):
                        result = self._server_interface.check_auth_publickey(
                            username, key
                        )
                    else:
                        self._logger.warning(
                            f"Public key signature verification failed for user {username}"
                        )
                        result = AUTH_FAILED

            # Send response
            if result == AUTH_SUCCESSFUL:
                self._authenticated = True
                self._server_interface.on_authentication_successful(username, method)
                self._send_message(UserAuthSuccessMessage())
            else:
                self._server_interface.on_authentication_failed(username, method)
                allowed_methods = self._server_interface.get_allowed_auths(username)
                self._send_message(UserAuthFailureMessage(allowed_methods, False))

        except (
            OSError,
            struct.error,
            ValueError,
            UnicodeDecodeError,
            SSHException,
        ) as e:
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
