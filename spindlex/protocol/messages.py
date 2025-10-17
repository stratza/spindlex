"""
SSH Protocol Message Implementation

Implements SSH protocol message parsing, serialization, and validation
according to RFC 4251-4254 specifications.
"""

from typing import Any, Dict, List, Optional, Union
import struct
from ..exceptions import ProtocolException
from .constants import *
from .utils import (
    read_byte, read_boolean, read_uint32, read_uint64, read_string, read_mpint,
    write_byte, write_boolean, write_uint32, write_uint64, write_string, write_mpint,
    validate_message_type
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
            raise ProtocolException(f"Failed to pack message: {e}")
    
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
        
        # Create appropriate message class based on type
        message_classes = {
            MSG_DISCONNECT: DisconnectMessage,
            MSG_SERVICE_REQUEST: ServiceRequestMessage,
            MSG_SERVICE_ACCEPT: ServiceAcceptMessage,
            MSG_KEXINIT: KexInitMessage,
            MSG_USERAUTH_REQUEST: UserAuthRequestMessage,
            MSG_USERAUTH_FAILURE: UserAuthFailureMessage,
            MSG_USERAUTH_SUCCESS: UserAuthSuccessMessage,
            MSG_CHANNEL_OPEN: ChannelOpenMessage,
            MSG_CHANNEL_OPEN_CONFIRMATION: ChannelOpenConfirmationMessage,
            MSG_CHANNEL_OPEN_FAILURE: ChannelOpenFailureMessage,
            MSG_CHANNEL_DATA: ChannelDataMessage,
            MSG_CHANNEL_CLOSE: ChannelCloseMessage,
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
        return validate_message_type(self.msg_type)
    
    def __str__(self) -> str:
        """String representation of message."""
        return f"{self.__class__.__name__}(type={self.msg_type}, size={len(self._data)})"
    
    def __repr__(self) -> str:
        """Detailed string representation of message."""
        return f"{self.__class__.__name__}(msg_type={self.msg_type}, data_size={len(self._data)})"


class DisconnectMessage(Message):
    """SSH disconnect message (MSG_DISCONNECT)."""
    
    def __init__(self, reason_code: int, description: str = "", language: str = "") -> None:
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
        
        description = description_bytes.decode(SSH_STRING_ENCODING, errors='replace')
        language = language_bytes.decode(SSH_STRING_ENCODING, errors='replace')
        
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
        kex_algorithms: List[str],
        server_host_key_algorithms: List[str],
        encryption_algorithms_client_to_server: List[str],
        encryption_algorithms_server_to_client: List[str],
        mac_algorithms_client_to_server: List[str],
        mac_algorithms_server_to_client: List[str],
        compression_algorithms_client_to_server: List[str],
        compression_algorithms_server_to_client: List[str],
        languages_client_to_server: List[str] = None,
        languages_server_to_client: List[str] = None,
        first_kex_packet_follows: bool = False
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
        self.encryption_algorithms_client_to_server = encryption_algorithms_client_to_server
        self.encryption_algorithms_server_to_client = encryption_algorithms_server_to_client
        self.mac_algorithms_client_to_server = mac_algorithms_client_to_server
        self.mac_algorithms_server_to_client = mac_algorithms_server_to_client
        self.compression_algorithms_client_to_server = compression_algorithms_client_to_server
        self.compression_algorithms_server_to_client = compression_algorithms_server_to_client
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
        cookie = data[offset:offset + KEX_COOKIE_SIZE]
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
        def parse_list(data: bytes) -> List[str]:
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
            first_kex_packet_follows=first_kex_follows
        )


class UserAuthRequestMessage(Message):
    """SSH user authentication request message (MSG_USERAUTH_REQUEST)."""
    
    def __init__(
        self, 
        username: str, 
        service: str, 
        method: str, 
        method_data: bytes = b""
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


class UserAuthFailureMessage(Message):
    """SSH user authentication failure message (MSG_USERAUTH_FAILURE)."""
    
    def __init__(self, authentications: List[str], partial_success: bool = False) -> None:
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
        authentications = [auth.strip() for auth in auth_list.split(",") if auth.strip()]
        
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
        type_specific_data: bytes = b""
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
        
        return cls(channel_type, sender_channel, initial_window_size, 
                  maximum_packet_size, type_specific_data)


class ChannelOpenConfirmationMessage(Message):
    """SSH channel open confirmation message (MSG_CHANNEL_OPEN_CONFIRMATION)."""
    
    def __init__(
        self,
        recipient_channel: int,
        sender_channel: int,
        initial_window_size: int,
        maximum_packet_size: int,
        type_specific_data: bytes = b""
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
        
        return cls(recipient_channel, sender_channel, initial_window_size,
                  maximum_packet_size, type_specific_data)


class ChannelOpenFailureMessage(Message):
    """SSH channel open failure message (MSG_CHANNEL_OPEN_FAILURE)."""
    
    def __init__(
        self,
        recipient_channel: int,
        reason_code: int,
        description: str = "",
        language: str = ""
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
        
        description = description_bytes.decode(SSH_STRING_ENCODING, errors='replace')
        language = language_bytes.decode(SSH_STRING_ENCODING, errors='replace')
        
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