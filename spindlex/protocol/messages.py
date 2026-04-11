"""
SSH Protocol Message Implementation

Implements SSH protocol message parsing, serialization, and validation
according to RFC 4251-4254 specifications.
"""

from typing import Optional, Union

from ..exceptions import ProtocolException
from .constants import *
from .utils import (
    read_boolean,
    read_byte,
    read_mpint,
    read_string,
    read_uint32,
    write_boolean,
    write_byte,
    write_mpint,
    write_string,
    write_uint32,
    write_uint64,
)


class Message:
    """
    Base SSH protocol message class.

    Provides message serialization, deserialization, and validation
    functionality for SSH protocol messages.
    """

    def __init__(self, msg_type: int) -> None:
        """
        Initialize message with type.

        Args:
            msg_type: SSH message type code

        Raises:
            ProtocolException: If message type is invalid
        """
        if not validate_message_type(msg_type):
            raise ProtocolException(f"Invalid message type: {msg_type}")

        self.msg_type = msg_type
        self._data = bytearray()

    def pack(self) -> bytes:
        """
        Serialize message to bytes.

        Returns:
            Serialized message data including message type

        Raises:
            ProtocolException: If serialization fails
        """
        try:
            # Start with message type
            result = write_byte(self.msg_type)

            # Add message-specific data
            result += bytes(self._data)

            return result
        except Exception as e:
            raise ProtocolException(f"Failed to pack message: {e}") from e

    @classmethod
    def unpack(cls, data: bytes) -> "Message":
        """
        Deserialize message from bytes.

        Args:
            data: Serialized message data

        Returns:
            Deserialized message instance

        Raises:
            ProtocolException: If deserialization fails
        """
        if len(data) < 1:
            raise ProtocolException("Message data too short")

        msg_type, offset = read_byte(data, 0)

        # If called on a specific subclass, unpack that subclass directly
        if cls != Message:
            return cls._unpack_data(data[offset:])

        # Create appropriate message class based on type
        message_classes = {
            MSG_DISCONNECT: DisconnectMessage,
            MSG_IGNORE: IgnoreMessage,
            MSG_UNIMPLEMENTED: UnimplementedMessage,
            MSG_DEBUG: DebugMessage,
            MSG_SERVICE_REQUEST: ServiceRequestMessage,
            MSG_SERVICE_ACCEPT: ServiceAcceptMessage,
            MSG_KEXINIT: KexInitMessage,
            MSG_NEWKEYS: NewKeysMessage,
            MSG_KEXDH_INIT: KexDHInitMessage,
            MSG_KEXDH_REPLY: KexDHReplyMessage,
            MSG_USERAUTH_REQUEST: UserAuthRequestMessage,
            MSG_USERAUTH_FAILURE: UserAuthFailureMessage,
            MSG_USERAUTH_SUCCESS: UserAuthSuccessMessage,
            MSG_USERAUTH_BANNER: UserAuthBannerMessage,
            MSG_USERAUTH_PK_OK: UserAuthPKOKMessage,
            MSG_USERAUTH_INFO_REQUEST: UserAuthInfoRequestMessage,
            MSG_USERAUTH_INFO_RESPONSE: UserAuthInfoResponseMessage,
            MSG_GLOBAL_REQUEST: GlobalRequestMessage,
            MSG_REQUEST_SUCCESS: RequestSuccessMessage,
            MSG_REQUEST_FAILURE: RequestFailureMessage,
            MSG_CHANNEL_OPEN: ChannelOpenMessage,
            MSG_CHANNEL_OPEN_CONFIRMATION: ChannelOpenConfirmationMessage,
            MSG_CHANNEL_OPEN_FAILURE: ChannelOpenFailureMessage,
            MSG_CHANNEL_WINDOW_ADJUST: ChannelWindowAdjustMessage,
            MSG_CHANNEL_DATA: ChannelDataMessage,
            MSG_CHANNEL_EXTENDED_DATA: ChannelExtendedDataMessage,
            MSG_CHANNEL_EOF: ChannelEOFMessage,
            MSG_CHANNEL_CLOSE: ChannelCloseMessage,
            MSG_CHANNEL_REQUEST: ChannelRequestMessage,
            MSG_CHANNEL_SUCCESS: ChannelSuccessMessage,
            MSG_CHANNEL_FAILURE: ChannelFailureMessage,
        }

        message_class = message_classes.get(msg_type, Message)

        if message_class == Message:
            # Generic message
            msg = Message(msg_type)
            msg._data = bytearray(data[offset:])
            return msg
        else:
            # Specific message class
            return message_class._unpack_data(data[offset:])

    @classmethod
    def _unpack_data(cls, data: bytes) -> "Message":
        """
        Unpack message-specific data. Override in subclasses.

        Args:
            data: Message data without type byte

        Returns:
            Message instance
        """
        raise NotImplementedError("Subclasses must implement _unpack_data")

    def add_byte(self, value: int) -> None:
        """Add single byte to message."""
        self._data.extend(write_byte(value))

    def add_boolean(self, value: bool) -> None:
        """Add boolean to message."""
        self._data.extend(write_boolean(value))

    def add_uint32(self, value: int) -> None:
        """Add 32-bit unsigned integer to message."""
        self._data.extend(write_uint32(value))

    def add_uint64(self, value: int) -> None:
        """Add 64-bit unsigned integer to message."""
        self._data.extend(write_uint64(value))

    def add_string(self, value: Union[str, bytes]) -> None:
        """Add string to message."""
        self._data.extend(write_string(value))

    def add_mpint(self, value: int) -> None:
        """Add multiple precision integer to message."""
        self._data.extend(write_mpint(value))

    def validate(self) -> bool:
        """
        Validate message content.

        Returns:
            True if message is valid

        Raises:
            ProtocolException: If message is invalid
        """
        # Base validation - subclasses can override
        if not validate_message_type(self.msg_type):
            raise ProtocolException(f"Invalid message type: {self.msg_type}")

        # Validate message size
        if len(self._data) > MAX_MESSAGE_SIZE:
            raise ProtocolException(f"Message too large: {len(self._data)} bytes")

        return True

    def __str__(self) -> str:
        """String representation of message."""
        return (
            f"{self.__class__.__name__}(type={self.msg_type}, size={len(self._data)})"
        )

    def __repr__(self) -> str:
        """Detailed string representation of message."""
        return f"{self.__class__.__name__}(msg_type={self.msg_type}, data_size={len(self._data)})"


class DisconnectMessage(Message):
    """SSH disconnect message (MSG_DISCONNECT)."""

    def __init__(
        self, reason_code: int, description: str = "", language: str = ""
    ) -> None:
        """
        Initialize disconnect message.

        Args:
            reason_code: Disconnect reason code
            description: Human-readable description
            language: Language tag (RFC 3066)
        """
        super().__init__(MSG_DISCONNECT)
        self.reason_code = reason_code
        self.description = description
        self.language = language

        # Build message data
        self.add_uint32(reason_code)
        self.add_string(description)
        self.add_string(language)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "DisconnectMessage":
        """Unpack disconnect message data."""
        offset = 0
        reason_code, offset = read_uint32(data, offset)
        description_bytes, offset = read_string(data, offset)
        language_bytes, offset = read_string(data, offset)

        description = description_bytes.decode(SSH_STRING_ENCODING, errors="replace")
        language = language_bytes.decode(SSH_STRING_ENCODING, errors="replace")

        return cls(reason_code, description, language)


class ServiceRequestMessage(Message):
    """SSH service request message (MSG_SERVICE_REQUEST)."""

    def __init__(self, service_name: str) -> None:
        """
        Initialize service request message.

        Args:
            service_name: Name of requested service
        """
        super().__init__(MSG_SERVICE_REQUEST)
        self.service_name = service_name

        # Build message data
        self.add_string(service_name)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ServiceRequestMessage":
        """Unpack service request message data."""
        service_name_bytes, _ = read_string(data, 0)
        service_name = service_name_bytes.decode(SSH_STRING_ENCODING)
        return cls(service_name)


class ServiceAcceptMessage(Message):
    """SSH service accept message (MSG_SERVICE_ACCEPT)."""

    def __init__(self, service_name: str) -> None:
        """
        Initialize service accept message.

        Args:
            service_name: Name of accepted service
        """
        super().__init__(MSG_SERVICE_ACCEPT)
        self.service_name = service_name

        # Build message data
        self.add_string(service_name)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ServiceAcceptMessage":
        """Unpack service accept message data."""
        service_name_bytes, _ = read_string(data, 0)
        service_name = service_name_bytes.decode(SSH_STRING_ENCODING)
        return cls(service_name)


class KexInitMessage(Message):
    """SSH key exchange init message (MSG_KEXINIT)."""

    def __init__(
        self,
        cookie: bytes,
        kex_algorithms: list[str],
        server_host_key_algorithms: list[str],
        encryption_algorithms_client_to_server: list[str],
        encryption_algorithms_server_to_client: list[str],
        mac_algorithms_client_to_server: list[str],
        mac_algorithms_server_to_client: list[str],
        compression_algorithms_client_to_server: list[str],
        compression_algorithms_server_to_client: list[str],
        languages_client_to_server: Optional[list[str]] = None,
        languages_server_to_client: Optional[list[str]] = None,
        first_kex_packet_follows: bool = False,
    ) -> None:
        """
        Initialize KEX init message.

        Args:
            cookie: Random 16-byte cookie
            kex_algorithms: Key exchange algorithms
            server_host_key_algorithms: Server host key algorithms
            encryption_algorithms_client_to_server: Encryption algorithms (C->S)
            encryption_algorithms_server_to_client: Encryption algorithms (S->C)
            mac_algorithms_client_to_server: MAC algorithms (C->S)
            mac_algorithms_server_to_client: MAC algorithms (S->C)
            compression_algorithms_client_to_server: Compression algorithms (C->S)
            compression_algorithms_server_to_client: Compression algorithms (S->C)
            languages_client_to_server: Language tags (C->S)
            languages_server_to_client: Language tags (S->C)
            first_kex_packet_follows: Whether first KEX packet follows
        """
        super().__init__(MSG_KEXINIT)

        if len(cookie) != KEX_COOKIE_SIZE:
            raise ProtocolException(f"Invalid cookie size: {len(cookie)}")

        self.cookie = cookie
        self.kex_algorithms = kex_algorithms
        self.server_host_key_algorithms = server_host_key_algorithms
        self.encryption_algorithms_client_to_server = (
            encryption_algorithms_client_to_server
        )
        self.encryption_algorithms_server_to_client = (
            encryption_algorithms_server_to_client
        )
        self.mac_algorithms_client_to_server = mac_algorithms_client_to_server
        self.mac_algorithms_server_to_client = mac_algorithms_server_to_client
        self.compression_algorithms_client_to_server = (
            compression_algorithms_client_to_server
        )
        self.compression_algorithms_server_to_client = (
            compression_algorithms_server_to_client
        )
        self.languages_client_to_server = languages_client_to_server or []
        self.languages_server_to_client = languages_server_to_client or []
        self.first_kex_packet_follows = first_kex_packet_follows

        # Build message data
        self._data.extend(cookie)
        self.add_string(",".join(kex_algorithms))
        self.add_string(",".join(server_host_key_algorithms))
        self.add_string(",".join(encryption_algorithms_client_to_server))
        self.add_string(",".join(encryption_algorithms_server_to_client))
        self.add_string(",".join(mac_algorithms_client_to_server))
        self.add_string(",".join(mac_algorithms_server_to_client))
        self.add_string(",".join(compression_algorithms_client_to_server))
        self.add_string(",".join(compression_algorithms_server_to_client))
        self.add_string(",".join(self.languages_client_to_server))
        self.add_string(",".join(self.languages_server_to_client))
        self.add_boolean(first_kex_packet_follows)
        self.add_uint32(0)  # Reserved for future extension

    @classmethod
    def _unpack_data(cls, data: bytes) -> "KexInitMessage":
        """Unpack KEX init message data."""
        offset = 0

        # Read cookie
        if len(data) < KEX_COOKIE_SIZE:
            raise ProtocolException("Invalid KEXINIT message: missing cookie")
        cookie = data[offset : offset + KEX_COOKIE_SIZE]
        offset += KEX_COOKIE_SIZE

        # Read algorithm lists
        kex_algs_bytes, offset = read_string(data, offset)
        host_key_algs_bytes, offset = read_string(data, offset)
        enc_c2s_bytes, offset = read_string(data, offset)
        enc_s2c_bytes, offset = read_string(data, offset)
        mac_c2s_bytes, offset = read_string(data, offset)
        mac_s2c_bytes, offset = read_string(data, offset)
        comp_c2s_bytes, offset = read_string(data, offset)
        comp_s2c_bytes, offset = read_string(data, offset)
        lang_c2s_bytes, offset = read_string(data, offset)
        lang_s2c_bytes, offset = read_string(data, offset)

        first_kex_follows, offset = read_boolean(data, offset)
        reserved, offset = read_uint32(data, offset)

        # Parse algorithm lists
        def parse_list(data: bytes) -> list[str]:
            s = data.decode(SSH_STRING_ENCODING)
            return [alg.strip() for alg in s.split(",") if alg.strip()]

        return cls(
            cookie=cookie,
            kex_algorithms=parse_list(kex_algs_bytes),
            server_host_key_algorithms=parse_list(host_key_algs_bytes),
            encryption_algorithms_client_to_server=parse_list(enc_c2s_bytes),
            encryption_algorithms_server_to_client=parse_list(enc_s2c_bytes),
            mac_algorithms_client_to_server=parse_list(mac_c2s_bytes),
            mac_algorithms_server_to_client=parse_list(mac_s2c_bytes),
            compression_algorithms_client_to_server=parse_list(comp_c2s_bytes),
            compression_algorithms_server_to_client=parse_list(comp_s2c_bytes),
            languages_client_to_server=parse_list(lang_c2s_bytes),
            languages_server_to_client=parse_list(lang_s2c_bytes),
            first_kex_packet_follows=first_kex_follows,
        )

    def validate(self) -> bool:
        """
        Validate KEX init message content.

        Returns:
            True if message is valid

        Raises:
            ProtocolException: If message is invalid
        """
        super().validate()

        # Validate required algorithm lists are not empty
        if not self.kex_algorithms:
            raise ProtocolException("KEX algorithms list cannot be empty")
        if not self.server_host_key_algorithms:
            raise ProtocolException("Server host key algorithms list cannot be empty")
        if not self.encryption_algorithms_client_to_server:
            raise ProtocolException(
                "Client-to-server encryption algorithms list cannot be empty"
            )
        if not self.encryption_algorithms_server_to_client:
            raise ProtocolException(
                "Server-to-client encryption algorithms list cannot be empty"
            )

        return True


class UserAuthRequestMessage(Message):
    """SSH user authentication request message (MSG_USERAUTH_REQUEST)."""

    def __init__(
        self, username: str, service: str, method: str, method_data: bytes = b""
    ) -> None:
        """
        Initialize user auth request message.

        Args:
            username: Username for authentication
            service: Service name
            method: Authentication method
            method_data: Method-specific data
        """
        super().__init__(MSG_USERAUTH_REQUEST)
        self.username = username
        self.service = service
        self.method = method
        self.method_data = method_data

        # Build message data
        self.add_string(username)
        self.add_string(service)
        self.add_string(method)
        if method_data:
            self._data.extend(method_data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "UserAuthRequestMessage":
        """Unpack user auth request message data."""
        offset = 0
        username_bytes, offset = read_string(data, offset)
        service_bytes, offset = read_string(data, offset)
        method_bytes, offset = read_string(data, offset)

        username = username_bytes.decode(SSH_STRING_ENCODING)
        service = service_bytes.decode(SSH_STRING_ENCODING)
        method = method_bytes.decode(SSH_STRING_ENCODING)
        method_data = data[offset:] if offset < len(data) else b""

        return cls(username, service, method, method_data)

    def validate(self) -> bool:
        """
        Validate user auth request message content.

        Returns:
            True if message is valid

        Raises:
            ProtocolException: If message is invalid
        """
        super().validate()

        # Validate required fields
        if not self.username:
            raise ProtocolException("Username cannot be empty")
        if not self.service:
            raise ProtocolException("Service name cannot be empty")
        if not self.method:
            raise ProtocolException("Authentication method cannot be empty")

        # Validate service name
        if self.service not in [SERVICE_USERAUTH, SERVICE_CONNECTION]:
            raise ProtocolException(f"Invalid service name: {self.service}")

        # Validate authentication method
        valid_methods = [
            AUTH_PASSWORD,
            AUTH_PUBLICKEY,
            AUTH_HOSTBASED,
            AUTH_KEYBOARD_INTERACTIVE,
        ]
        if self.method not in valid_methods:
            raise ProtocolException(f"Invalid authentication method: {self.method}")

        return True


class UserAuthFailureMessage(Message):
    """SSH user authentication failure message (MSG_USERAUTH_FAILURE)."""

    def __init__(
        self, authentications: list[str], partial_success: bool = False
    ) -> None:
        """
        Initialize user auth failure message.

        Args:
            authentications: List of authentication methods that can continue
            partial_success: Whether partial success occurred
        """
        super().__init__(MSG_USERAUTH_FAILURE)
        self.authentications = authentications
        self.partial_success = partial_success

        # Build message data
        self.add_string(",".join(authentications))
        self.add_boolean(partial_success)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "UserAuthFailureMessage":
        """Unpack user auth failure message data."""
        offset = 0
        auth_bytes, offset = read_string(data, offset)
        partial_success, offset = read_boolean(data, offset)

        auth_list = auth_bytes.decode(SSH_STRING_ENCODING)
        authentications = [
            auth.strip() for auth in auth_list.split(",") if auth.strip()
        ]

        return cls(authentications, partial_success)


class UserAuthSuccessMessage(Message):
    """SSH user authentication success message (MSG_USERAUTH_SUCCESS)."""

    def __init__(self) -> None:
        """Initialize user auth success message."""
        super().__init__(MSG_USERAUTH_SUCCESS)
        # No additional data for success message

    @classmethod
    def _unpack_data(cls, data: bytes) -> "UserAuthSuccessMessage":
        """Unpack user auth success message data."""
        return cls()


class ChannelOpenMessage(Message):
    """SSH channel open message (MSG_CHANNEL_OPEN)."""

    def __init__(
        self,
        channel_type: str,
        sender_channel: int,
        initial_window_size: int,
        maximum_packet_size: int,
        type_specific_data: bytes = b"",
    ) -> None:
        """
        Initialize channel open message.

        Args:
            channel_type: Type of channel to open
            sender_channel: Sender's channel number
            initial_window_size: Initial window size
            maximum_packet_size: Maximum packet size
            type_specific_data: Channel type specific data
        """
        super().__init__(MSG_CHANNEL_OPEN)
        self.channel_type = channel_type
        self.sender_channel = sender_channel
        self.initial_window_size = initial_window_size
        self.maximum_packet_size = maximum_packet_size
        self.type_specific_data = type_specific_data

        # Build message data
        self.add_string(channel_type)
        self.add_uint32(sender_channel)
        self.add_uint32(initial_window_size)
        self.add_uint32(maximum_packet_size)
        if type_specific_data:
            self._data.extend(type_specific_data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelOpenMessage":
        """Unpack channel open message data."""
        offset = 0
        channel_type_bytes, offset = read_string(data, offset)
        sender_channel, offset = read_uint32(data, offset)
        initial_window_size, offset = read_uint32(data, offset)
        maximum_packet_size, offset = read_uint32(data, offset)

        channel_type = channel_type_bytes.decode(SSH_STRING_ENCODING)
        type_specific_data = data[offset:] if offset < len(data) else b""

        return cls(
            channel_type,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            type_specific_data,
        )

    def validate(self) -> bool:
        """
        Validate channel open message content.

        Returns:
            True if message is valid

        Raises:
            ProtocolException: If message is invalid
        """
        super().validate()

        # Validate channel type
        if not self.channel_type:
            raise ProtocolException("Channel type cannot be empty")

        # Validate window and packet sizes
        if self.initial_window_size <= 0:
            raise ProtocolException("Initial window size must be positive")
        if self.maximum_packet_size <= 0:
            raise ProtocolException("Maximum packet size must be positive")
        if self.maximum_packet_size > MAX_PACKET_SIZE:
            raise ProtocolException(
                f"Maximum packet size too large: {self.maximum_packet_size}"
            )

        return True


class ChannelOpenConfirmationMessage(Message):
    """SSH channel open confirmation message (MSG_CHANNEL_OPEN_CONFIRMATION)."""

    def __init__(
        self,
        recipient_channel: int,
        sender_channel: int,
        initial_window_size: int,
        maximum_packet_size: int,
        type_specific_data: bytes = b"",
    ) -> None:
        """
        Initialize channel open confirmation message.

        Args:
            recipient_channel: Recipient's channel number
            sender_channel: Sender's channel number
            initial_window_size: Initial window size
            maximum_packet_size: Maximum packet size
            type_specific_data: Channel type specific data
        """
        super().__init__(MSG_CHANNEL_OPEN_CONFIRMATION)
        self.recipient_channel = recipient_channel
        self.sender_channel = sender_channel
        self.initial_window_size = initial_window_size
        self.maximum_packet_size = maximum_packet_size
        self.type_specific_data = type_specific_data

        # Build message data
        self.add_uint32(recipient_channel)
        self.add_uint32(sender_channel)
        self.add_uint32(initial_window_size)
        self.add_uint32(maximum_packet_size)
        if type_specific_data:
            self._data.extend(type_specific_data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelOpenConfirmationMessage":
        """Unpack channel open confirmation message data."""
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        sender_channel, offset = read_uint32(data, offset)
        initial_window_size, offset = read_uint32(data, offset)
        maximum_packet_size, offset = read_uint32(data, offset)

        type_specific_data = data[offset:] if offset < len(data) else b""

        return cls(
            recipient_channel,
            sender_channel,
            initial_window_size,
            maximum_packet_size,
            type_specific_data,
        )


class ChannelOpenFailureMessage(Message):
    """SSH channel open failure message (MSG_CHANNEL_OPEN_FAILURE)."""

    def __init__(
        self,
        recipient_channel: int,
        reason_code: int,
        description: str = "",
        language: str = "",
    ) -> None:
        """
        Initialize channel open failure message.

        Args:
            recipient_channel: Recipient's channel number
            reason_code: Failure reason code
            description: Human-readable description
            language: Language tag (RFC 3066)
        """
        super().__init__(MSG_CHANNEL_OPEN_FAILURE)
        self.recipient_channel = recipient_channel
        self.reason_code = reason_code
        self.description = description
        self.language = language

        # Build message data
        self.add_uint32(recipient_channel)
        self.add_uint32(reason_code)
        self.add_string(description)
        self.add_string(language)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelOpenFailureMessage":
        """Unpack channel open failure message data."""
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        reason_code, offset = read_uint32(data, offset)
        description_bytes, offset = read_string(data, offset)
        language_bytes, offset = read_string(data, offset)

        description = description_bytes.decode(SSH_STRING_ENCODING, errors="replace")
        language = language_bytes.decode(SSH_STRING_ENCODING, errors="replace")

        return cls(recipient_channel, reason_code, description, language)


class ChannelDataMessage(Message):
    """SSH channel data message (MSG_CHANNEL_DATA)."""

    def __init__(self, recipient_channel: int, data: bytes) -> None:
        """
        Initialize channel data message.

        Args:
            recipient_channel: Recipient's channel number
            data: Data to send
        """
        super().__init__(MSG_CHANNEL_DATA)
        self.recipient_channel = recipient_channel
        self.data = data

        # Build message data
        self.add_uint32(recipient_channel)
        self.add_string(data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelDataMessage":
        """Unpack channel data message data."""
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        message_data, offset = read_string(data, offset)

        return cls(recipient_channel, message_data)


class ChannelCloseMessage(Message):
    """SSH channel close message (MSG_CHANNEL_CLOSE)."""

    def __init__(self, recipient_channel: int) -> None:
        """
        Initialize channel close message.

        Args:
            recipient_channel: Recipient's channel number
        """
        super().__init__(MSG_CHANNEL_CLOSE)
        self.recipient_channel = recipient_channel

        # Build message data
        self.add_uint32(recipient_channel)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelCloseMessage":
        """Unpack channel close message data."""
        recipient_channel, _ = read_uint32(data, 0)
        return cls(recipient_channel)


class IgnoreMessage(Message):
    """SSH ignore message (MSG_IGNORE)."""

    def __init__(self, data: bytes = b"") -> None:
        """
        Initialize ignore message.

        Args:
            data: Arbitrary data to ignore
        """
        super().__init__(MSG_IGNORE)
        self.data = data

        # Build message data
        self.add_string(data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "IgnoreMessage":
        """Unpack ignore message data."""
        ignore_data, _ = read_string(data, 0)
        return cls(ignore_data)


class UnimplementedMessage(Message):
    """SSH unimplemented message (MSG_UNIMPLEMENTED)."""

    def __init__(self, sequence_number: int) -> None:
        """
        Initialize unimplemented message.

        Args:
            sequence_number: Sequence number of unimplemented message
        """
        super().__init__(MSG_UNIMPLEMENTED)
        self.sequence_number = sequence_number

        # Build message data
        self.add_uint32(sequence_number)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "UnimplementedMessage":
        """Unpack unimplemented message data."""
        sequence_number, _ = read_uint32(data, 0)
        return cls(sequence_number)


class DebugMessage(Message):
    """SSH debug message (MSG_DEBUG)."""

    def __init__(self, always_display: bool, message: str, language: str = "") -> None:
        """
        Initialize debug message.

        Args:
            always_display: Whether message should always be displayed
            message: Debug message text
            language: Language tag (RFC 3066)
        """
        super().__init__(MSG_DEBUG)
        self.always_display = always_display
        self.message = message
        self.language = language

        # Build message data
        self.add_boolean(always_display)
        self.add_string(message)
        self.add_string(language)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "DebugMessage":
        """Unpack debug message data."""
        offset = 0
        always_display, offset = read_boolean(data, offset)
        message_bytes, offset = read_string(data, offset)
        language_bytes, offset = read_string(data, offset)

        message = message_bytes.decode(SSH_STRING_ENCODING, errors="replace")
        language = language_bytes.decode(SSH_STRING_ENCODING, errors="replace")

        return cls(always_display, message, language)


class NewKeysMessage(Message):
    """SSH new keys message (MSG_NEWKEYS)."""

    def __init__(self) -> None:
        """Initialize new keys message."""
        super().__init__(MSG_NEWKEYS)
        # No additional data for new keys message

    @classmethod
    def _unpack_data(cls, data: bytes) -> "NewKeysMessage":
        """Unpack new keys message data."""
        return cls()


class KexDHInitMessage(Message):
    """SSH Diffie-Hellman key exchange init message (MSG_KEXDH_INIT)."""

    def __init__(self, e: int) -> None:
        """
        Initialize DH init message.

        Args:
            e: Client's DH public key
        """
        super().__init__(MSG_KEXDH_INIT)
        self.e = e

        # Build message data
        self.add_mpint(e)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "KexDHInitMessage":
        """Unpack DH init message data."""
        e, _ = read_mpint(data, 0)
        return cls(e)


class KexDHReplyMessage(Message):
    """SSH Diffie-Hellman key exchange reply message (MSG_KEXDH_REPLY)."""

    def __init__(self, host_key: bytes, f: int, signature: bytes) -> None:
        """
        Initialize DH reply message.

        Args:
            host_key: Server's host key
            f: Server's DH public key
            signature: Signature of exchange hash
        """
        super().__init__(MSG_KEXDH_REPLY)
        self.host_key = host_key
        self.f = f
        self.signature = signature

        # Build message data
        self.add_string(host_key)
        self.add_mpint(f)
        self.add_string(signature)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "KexDHReplyMessage":
        """Unpack DH reply message data."""
        offset = 0
        host_key, offset = read_string(data, offset)
        f, offset = read_mpint(data, offset)
        signature, offset = read_string(data, offset)

        return cls(host_key, f, signature)


class UserAuthBannerMessage(Message):
    """SSH user authentication banner message (MSG_USERAUTH_BANNER)."""

    def __init__(self, message: str, language: str = "") -> None:
        """
        Initialize user auth banner message.

        Args:
            message: Banner message text
            language: Language tag (RFC 3066)
        """
        super().__init__(MSG_USERAUTH_BANNER)
        self.message = message
        self.language = language

        # Build message data
        self.add_string(message)
        self.add_string(language)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "UserAuthBannerMessage":
        """Unpack user auth banner message data."""
        offset = 0
        message_bytes, offset = read_string(data, offset)
        language_bytes, offset = read_string(data, offset)

        message = message_bytes.decode(SSH_STRING_ENCODING, errors="replace")
        language = language_bytes.decode(SSH_STRING_ENCODING, errors="replace")

        return cls(message, language)


class UserAuthInfoRequestMessage(Message):
    """SSH user authentication info request message (MSG_USERAUTH_INFO_REQUEST)."""

    def __init__(self, name: str, instruction: str, language: str, prompts: list) -> None:
        """
        Initialize user auth info request message.

        Args:
            name: Name of the authentication method
            instruction: Instructions for the user
            language: Language tag
            prompts: List of (prompt, echo) tuples
        """
        super().__init__(MSG_USERAUTH_INFO_REQUEST)
        self.name = name
        self.instruction = instruction
        self.language = language
        self.prompts = prompts

        # Build message data
        self.add_string(name)
        self.add_string(instruction)
        self.add_string(language)
        self.add_uint32(len(prompts))
        for prompt, echo in prompts:
            self.add_string(prompt)
            self.add_boolean(echo)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "UserAuthInfoRequestMessage":
        """Unpack user auth info request message data."""
        offset = 0
        name_bytes, offset = read_string(data, offset)
        instruction_bytes, offset = read_string(data, offset)
        language_bytes, offset = read_string(data, offset)
        num_prompts, offset = read_uint32(data, offset)

        name = name_bytes.decode(SSH_STRING_ENCODING, errors="replace")
        instruction = instruction_bytes.decode(SSH_STRING_ENCODING, errors="replace")
        language = language_bytes.decode(SSH_STRING_ENCODING, errors="replace")

        prompts = []
        for _ in range(num_prompts):
            prompt_bytes, offset = read_string(data, offset)
            echo, offset = read_boolean(data, offset)
            prompt_text = prompt_bytes.decode(SSH_STRING_ENCODING, errors="replace")
            prompts.append((prompt_text, echo))

        return cls(name, instruction, language, prompts)


class UserAuthInfoResponseMessage(Message):
    """SSH user authentication info response message (MSG_USERAUTH_INFO_RESPONSE)."""

    def __init__(self, responses: list[str]) -> None:
        """
        Initialize user auth info response message.

        Args:
            responses: List of responses to prompts
        """
        super().__init__(MSG_USERAUTH_INFO_RESPONSE)
        self.responses = responses

        # Build message data
        self.add_uint32(len(responses))
        for response in responses:
            self.add_string(response)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "UserAuthInfoResponseMessage":
        """Unpack user auth info response message data."""
        offset = 0
        num_responses, offset = read_uint32(data, offset)

        responses = []
        for _ in range(num_responses):
            response_bytes, offset = read_string(data, offset)
            response = response_bytes.decode(SSH_STRING_ENCODING, errors="replace")
            responses.append(response)

        return cls(responses)


class UserAuthPKOKMessage(Message):
    """SSH user authentication public key OK message (MSG_USERAUTH_PK_OK)."""

    def __init__(self, algorithm: str, public_key: bytes) -> None:
        """
        Initialize user auth PK OK message.

        Args:
            algorithm: Public key algorithm name
            public_key: Public key blob
        """
        super().__init__(MSG_USERAUTH_PK_OK)
        self.algorithm = algorithm
        self.public_key = public_key

        # Build message data
        self.add_string(algorithm)
        self.add_string(public_key)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "UserAuthPKOKMessage":
        """Unpack user auth PK OK message data."""
        offset = 0
        algorithm_bytes, offset = read_string(data, offset)
        public_key, offset = read_string(data, offset)

        algorithm = algorithm_bytes.decode(SSH_STRING_ENCODING)
        return cls(algorithm, public_key)


class GlobalRequestMessage(Message):
    """SSH global request message (MSG_GLOBAL_REQUEST)."""

    def __init__(
        self, request_name: str, want_reply: bool, request_data: bytes = b""
    ) -> None:
        """
        Initialize global request message.

        Args:
            request_name: Name of the request
            want_reply: Whether a reply is wanted
            request_data: Request-specific data
        """
        super().__init__(MSG_GLOBAL_REQUEST)
        self.request_name = request_name
        self.want_reply = want_reply
        self.request_data = request_data

        # Build message data
        self.add_string(request_name)
        self.add_boolean(want_reply)
        if request_data:
            self._data.extend(request_data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "GlobalRequestMessage":
        """Unpack global request message data."""
        offset = 0
        request_name_bytes, offset = read_string(data, offset)
        want_reply, offset = read_boolean(data, offset)

        request_name = request_name_bytes.decode(SSH_STRING_ENCODING)
        request_data = data[offset:] if offset < len(data) else b""

        return cls(request_name, want_reply, request_data)


class RequestSuccessMessage(Message):
    """SSH request success message (MSG_REQUEST_SUCCESS)."""

    def __init__(self, response_data: bytes = b"") -> None:
        """
        Initialize request success message.

        Args:
            response_data: Response-specific data
        """
        super().__init__(MSG_REQUEST_SUCCESS)
        self.response_data = response_data

        # Build message data
        if response_data:
            self._data.extend(response_data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "RequestSuccessMessage":
        """Unpack request success message data."""
        return cls(data)


class RequestFailureMessage(Message):
    """SSH request failure message (MSG_REQUEST_FAILURE)."""

    def __init__(self) -> None:
        """Initialize request failure message."""
        super().__init__(MSG_REQUEST_FAILURE)
        # No additional data for request failure message

    @classmethod
    def _unpack_data(cls, data: bytes) -> "RequestFailureMessage":
        """Unpack request failure message data."""
        return cls()


class ChannelWindowAdjustMessage(Message):
    """SSH channel window adjust message (MSG_CHANNEL_WINDOW_ADJUST)."""

    def __init__(self, recipient_channel: int, bytes_to_add: int) -> None:
        """
        Initialize channel window adjust message.

        Args:
            recipient_channel: Recipient's channel number
            bytes_to_add: Number of bytes to add to window
        """
        super().__init__(MSG_CHANNEL_WINDOW_ADJUST)
        self.recipient_channel = recipient_channel
        self.bytes_to_add = bytes_to_add

        # Build message data
        self.add_uint32(recipient_channel)
        self.add_uint32(bytes_to_add)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelWindowAdjustMessage":
        """Unpack channel window adjust message data."""
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        bytes_to_add, offset = read_uint32(data, offset)

        return cls(recipient_channel, bytes_to_add)


class ChannelExtendedDataMessage(Message):
    """SSH channel extended data message (MSG_CHANNEL_EXTENDED_DATA)."""

    def __init__(self, recipient_channel: int, data_type: int, data: bytes) -> None:
        """
        Initialize channel extended data message.

        Args:
            recipient_channel: Recipient's channel number
            data_type: Extended data type code
            data: Extended data
        """
        super().__init__(MSG_CHANNEL_EXTENDED_DATA)
        self.recipient_channel = recipient_channel
        self.data_type = data_type
        self.data = data

        # Build message data
        self.add_uint32(recipient_channel)
        self.add_uint32(data_type)
        self.add_string(data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelExtendedDataMessage":
        """Unpack channel extended data message data."""
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        data_type, offset = read_uint32(data, offset)
        extended_data, offset = read_string(data, offset)

        return cls(recipient_channel, data_type, extended_data)


class ChannelEOFMessage(Message):
    """SSH channel EOF message (MSG_CHANNEL_EOF)."""

    def __init__(self, recipient_channel: int) -> None:
        """
        Initialize channel EOF message.

        Args:
            recipient_channel: Recipient's channel number
        """
        super().__init__(MSG_CHANNEL_EOF)
        self.recipient_channel = recipient_channel

        # Build message data
        self.add_uint32(recipient_channel)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelEOFMessage":
        """Unpack channel EOF message data."""
        recipient_channel, _ = read_uint32(data, 0)
        return cls(recipient_channel)


class ChannelRequestMessage(Message):
    """SSH channel request message (MSG_CHANNEL_REQUEST)."""

    def __init__(
        self,
        recipient_channel: int,
        request_type: str,
        want_reply: bool,
        request_data: bytes = b"",
    ) -> None:
        """
        Initialize channel request message.

        Args:
            recipient_channel: Recipient's channel number
            request_type: Type of request
            want_reply: Whether a reply is wanted
            request_data: Request-specific data
        """
        super().__init__(MSG_CHANNEL_REQUEST)
        self.recipient_channel = recipient_channel
        self.request_type = request_type
        self.want_reply = want_reply
        self.request_data = request_data

        # Build message data
        self.add_uint32(recipient_channel)
        self.add_string(request_type)
        self.add_boolean(want_reply)
        if request_data:
            self._data.extend(request_data)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelRequestMessage":
        """Unpack channel request message data."""
        offset = 0
        recipient_channel, offset = read_uint32(data, offset)
        request_type_bytes, offset = read_string(data, offset)
        want_reply, offset = read_boolean(data, offset)

        request_type = request_type_bytes.decode(SSH_STRING_ENCODING)
        request_data = data[offset:] if offset < len(data) else b""

        return cls(recipient_channel, request_type, want_reply, request_data)


class ChannelSuccessMessage(Message):
    """SSH channel success message (MSG_CHANNEL_SUCCESS)."""

    def __init__(self, recipient_channel: int) -> None:
        """
        Initialize channel success message.

        Args:
            recipient_channel: Recipient's channel number
        """
        super().__init__(MSG_CHANNEL_SUCCESS)
        self.recipient_channel = recipient_channel

        # Build message data
        self.add_uint32(recipient_channel)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelSuccessMessage":
        """Unpack channel success message data."""
        recipient_channel, _ = read_uint32(data, 0)
        return cls(recipient_channel)


class ChannelFailureMessage(Message):
    """SSH channel failure message (MSG_CHANNEL_FAILURE)."""

    def __init__(self, recipient_channel: int) -> None:
        """
        Initialize channel failure message.

        Args:
            recipient_channel: Recipient's channel number
        """
        super().__init__(MSG_CHANNEL_FAILURE)
        self.recipient_channel = recipient_channel

        # Build message data
        self.add_uint32(recipient_channel)

    @classmethod
    def _unpack_data(cls, data: bytes) -> "ChannelFailureMessage":
        """Unpack channel failure message data."""
        recipient_channel, _ = read_uint32(data, 0)
        return cls(recipient_channel)
