"""
SFTP Protocol Message Implementation

Implements SFTP protocol message parsing, serialization, and validation
according to RFC 4254 and draft-ietf-secsh-filexfer specifications.
"""

from typing import Any, Dict, List, Optional, Union
import struct
import stat
from ..exceptions import SFTPError, ProtocolException
from .sftp_constants import *
from .utils import (
    read_byte, read_uint32, read_uint64, read_string,
    write_byte, write_uint32, write_uint64, write_string
)


class SFTPMessage:
    """
    Base SFTP protocol message class.
    
    Provides message serialization, deserialization, and validation
    functionality for SFTP protocol messages.
    """
    
    def __init__(self, msg_type: int, request_id: Optional[int] = None) -> None:
        """
        Initialize SFTP message with type.
        
        Args:
            msg_type: SFTP message type code
            request_id: Request ID for request/response correlation
            
        Raises:
            ProtocolException: If message type is invalid
        """
        if not validate_sftp_message_type(msg_type):
            raise ProtocolException(f"Invalid SFTP message type: {msg_type}")
        
        self.msg_type = msg_type
        self.request_id = request_id
        self._data = bytearray()
    
    def pack(self) -> bytes:
        """
        Serialize SFTP message to bytes.
        
        Returns:
            Serialized message data with length prefix
            
        Raises:
            ProtocolException: If serialization fails
        """
        try:
            # Build message content
            content = write_byte(self.msg_type)
            
            # Add request ID for request messages
            if self.request_id is not None:
                content += write_uint32(self.request_id)
            
            # Add message-specific data
            content += bytes(self._data)
            
            # Prepend length
            return write_uint32(len(content)) + content
        except Exception as e:
            raise ProtocolException(f"Failed to pack SFTP message: {e}")
    
    @classmethod
    def unpack(cls, data: bytes) -> "SFTPMessage":
        """
        Deserialize SFTP message from bytes.
        
        Args:
            data: Serialized message data with length prefix
            
        Returns:
            Deserialized SFTP message instance
            
        Raises:
            ProtocolException: If deserialization fails
        """
        if len(data) < 5:  # Minimum: length(4) + type(1)
            raise ProtocolException("SFTP message data too short")
        
        # Read message length
        msg_length, offset = read_uint32(data, 0)
        
        if len(data) < 4 + msg_length:
            raise ProtocolException("Incomplete SFTP message")
        
        # Read message type
        msg_type, offset = read_byte(data, offset)
        
        # Create appropriate message class based on type
        message_classes = {
            SSH_FXP_INIT: SFTPInitMessage,
            SSH_FXP_VERSION: SFTPVersionMessage,
            SSH_FXP_OPEN: SFTPOpenMessage,
            SSH_FXP_CLOSE: SFTPCloseMessage,
            SSH_FXP_READ: SFTPReadMessage,
            SSH_FXP_WRITE: SFTPWriteMessage,
            SSH_FXP_STAT: SFTPStatMessage,
            SSH_FXP_LSTAT: SFTPLStatMessage,
            SSH_FXP_FSTAT: SFTPFStatMessage,
            SSH_FXP_SETSTAT: SFTPSetStatMessage,
            SSH_FXP_OPENDIR: SFTPOpenDirMessage,
            SSH_FXP_READDIR: SFTPReadDirMessage,
            SSH_FXP_REMOVE: SFTPRemoveMessage,
            SSH_FXP_MKDIR: SFTPMkdirMessage,
            SSH_FXP_RMDIR: SFTPRmdirMessage,
            SSH_FXP_REALPATH: SFTPRealPathMessage,
            SSH_FXP_RENAME: SFTPRenameMessage,
            SSH_FXP_LINK: SFTPLinkMessage,
            SSH_FXP_STATUS: SFTPStatusMessage,
            SSH_FXP_HANDLE: SFTPHandleMessage,
            SSH_FXP_DATA: SFTPDataMessage,
            SSH_FXP_NAME: SFTPNameMessage,
            SSH_FXP_ATTRS: SFTPAttrsMessage,
            SSH_FXP_EXTENDED: SFTPExtendedMessage,
            SSH_FXP_EXTENDED_REPLY: SFTPExtendedReplyMessage,
        }
        
        message_class = message_classes.get(msg_type, SFTPMessage)
        
        if message_class == SFTPMessage:
            # Generic message
            msg = SFTPMessage(msg_type)
            msg._data = bytearray(data[offset:4 + msg_length])
            return msg
        else:
            # Specific message class
            return message_class._unpack_data(data[offset:4 + msg_length])
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPMessage":
        """
        Unpack message-specific data. Override in subclasses.
        
        Args:
            data: Message data without length prefix and type byte
            
        Returns:
            Message instance
        """
        raise NotImplementedError("Subclasses must implement _unpack_data")
    
    def add_uint32(self, value: int) -> None:
        """Add 32-bit unsigned integer to message."""
        self._data.extend(write_uint32(value))
    
    def add_uint64(self, value: int) -> None:
        """Add 64-bit unsigned integer to message."""
        self._data.extend(write_uint64(value))
    
    def add_string(self, value: Union[str, bytes]) -> None:
        """Add string to message."""
        self._data.extend(write_string(value))
    
    def add_byte(self, value: int) -> None:
        """Add single byte to message."""
        self._data.extend(write_byte(value))
    
    def validate(self) -> bool:
        """
        Validate SFTP message content.
        
        Returns:
            True if message is valid
            
        Raises:
            ProtocolException: If message is invalid
        """
        if not validate_sftp_message_type(self.msg_type):
            raise ProtocolException(f"Invalid SFTP message type: {self.msg_type}")
        
        # Validate message size
        if len(self._data) > SFTP_MAX_PACKET_SIZE:
            raise ProtocolException(f"SFTP message too large: {len(self._data)} bytes")
        
        return True


class SFTPAttributes:
    """
    SFTP file attributes.
    
    Represents file/directory attributes in SFTP protocol.
    """
    
    def __init__(self) -> None:
        """Initialize empty attributes."""
        self.flags = 0
        self.size: Optional[int] = None
        self.uid: Optional[int] = None
        self.gid: Optional[int] = None
        self.permissions: Optional[int] = None
        self.atime: Optional[int] = None
        self.mtime: Optional[int] = None
        self.extended: Dict[str, str] = {}
    
    def pack(self) -> bytes:
        """
        Serialize attributes to bytes.
        
        Returns:
            Serialized attributes
        """
        data = write_uint32(self.flags)
        
        if self.flags & SSH_FILEXFER_ATTR_SIZE:
            data += write_uint64(self.size or 0)
        
        if self.flags & SSH_FILEXFER_ATTR_UIDGID:
            data += write_uint32(self.uid or 0)
            data += write_uint32(self.gid or 0)
        
        if self.flags & SSH_FILEXFER_ATTR_PERMISSIONS:
            data += write_uint32(self.permissions or 0)
        
        if self.flags & SSH_FILEXFER_ATTR_ACMODTIME:
            data += write_uint32(self.atime or 0)
            data += write_uint32(self.mtime or 0)
        
        if self.flags & SSH_FILEXFER_ATTR_EXTENDED:
            data += write_uint32(len(self.extended))
            for key, value in self.extended.items():
                data += write_string(key)
                data += write_string(value)
        
        return data
    
    @classmethod
    def unpack(cls, data: bytes, offset: int = 0) -> tuple["SFTPAttributes", int]:
        """
        Deserialize attributes from bytes.
        
        Args:
            data: Serialized attributes data
            offset: Starting offset in data
            
        Returns:
            Tuple of (attributes, new_offset)
        """
        attrs = cls()
        
        attrs.flags, offset = read_uint32(data, offset)
        
        if attrs.flags & SSH_FILEXFER_ATTR_SIZE:
            attrs.size, offset = read_uint64(data, offset)
        
        if attrs.flags & SSH_FILEXFER_ATTR_UIDGID:
            attrs.uid, offset = read_uint32(data, offset)
            attrs.gid, offset = read_uint32(data, offset)
        
        if attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS:
            attrs.permissions, offset = read_uint32(data, offset)
        
        if attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME:
            attrs.atime, offset = read_uint32(data, offset)
            attrs.mtime, offset = read_uint32(data, offset)
        
        if attrs.flags & SSH_FILEXFER_ATTR_EXTENDED:
            count, offset = read_uint32(data, offset)
            for _ in range(count):
                key_bytes, offset = read_string(data, offset)
                value_bytes, offset = read_string(data, offset)
                key = key_bytes.decode('utf-8')
                value = value_bytes.decode('utf-8')
                attrs.extended[key] = value
        
        return attrs, offset
    
    def is_dir(self) -> bool:
        """Check if attributes represent a directory."""
        if self.permissions is None:
            return False
        return stat.S_ISDIR(self.permissions)
    
    def is_file(self) -> bool:
        """Check if attributes represent a regular file."""
        if self.permissions is None:
            return False
        return stat.S_ISREG(self.permissions)
    
    def is_symlink(self) -> bool:
        """Check if attributes represent a symbolic link."""
        if self.permissions is None:
            return False
        return stat.S_ISLNK(self.permissions)


class SFTPInitMessage(SFTPMessage):
    """SFTP initialization message (SSH_FXP_INIT)."""
    
    def __init__(self, version: int = SFTP_VERSION) -> None:
        """
        Initialize SFTP init message.
        
        Args:
            version: SFTP protocol version
        """
        super().__init__(SSH_FXP_INIT)
        self.version = version
        
        # Build message data
        self.add_uint32(version)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPInitMessage":
        """Unpack SFTP init message data."""
        version, _ = read_uint32(data, 0)
        return cls(version)


class SFTPVersionMessage(SFTPMessage):
    """SFTP version message (SSH_FXP_VERSION)."""
    
    def __init__(self, version: int = SFTP_VERSION, extensions: Optional[Dict[str, str]] = None) -> None:
        """
        Initialize SFTP version message.
        
        Args:
            version: SFTP protocol version
            extensions: Optional extensions dictionary
        """
        super().__init__(SSH_FXP_VERSION)
        self.version = version
        self.extensions = extensions or {}
        
        # Build message data
        self.add_uint32(version)
        for name, data in self.extensions.items():
            self.add_string(name)
            self.add_string(data)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPVersionMessage":
        """Unpack SFTP version message data."""
        offset = 0
        version, offset = read_uint32(data, offset)
        
        extensions = {}
        while offset < len(data):
            name_bytes, offset = read_string(data, offset)
            data_bytes, offset = read_string(data, offset)
            name = name_bytes.decode('utf-8')
            ext_data = data_bytes.decode('utf-8')
            extensions[name] = ext_data
        
        return cls(version, extensions)


class SFTPStatusMessage(SFTPMessage):
    """SFTP status message (SSH_FXP_STATUS)."""
    
    def __init__(self, request_id: int, status_code: int, message: str = "", language: str = "") -> None:
        """
        Initialize SFTP status message.
        
        Args:
            request_id: Request ID this status responds to
            status_code: SFTP status code
            message: Human-readable error message
            language: Language tag
        """
        super().__init__(SSH_FXP_STATUS, request_id)
        self.status_code = status_code
        self.message = message
        self.language = language
        
        # Build message data
        self.add_uint32(status_code)
        self.add_string(message)
        self.add_string(language)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPStatusMessage":
        """Unpack SFTP status message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        status_code, offset = read_uint32(data, offset)
        message_bytes, offset = read_string(data, offset)
        language_bytes, offset = read_string(data, offset)
        
        message = message_bytes.decode('utf-8', errors='replace')
        language = language_bytes.decode('utf-8', errors='replace')
        
        return cls(request_id, status_code, message, language)


class SFTPOpenMessage(SFTPMessage):
    """SFTP open file message (SSH_FXP_OPEN)."""
    
    def __init__(self, request_id: int, filename: str, pflags: int, attrs: SFTPAttributes) -> None:
        """
        Initialize SFTP open message.
        
        Args:
            request_id: Request ID
            filename: Path to file to open
            pflags: Open flags
            attrs: File attributes
        """
        super().__init__(SSH_FXP_OPEN, request_id)
        self.filename = filename
        self.pflags = pflags
        self.attrs = attrs
        
        # Build message data
        self.add_string(filename)
        self.add_uint32(pflags)
        self._data.extend(attrs.pack())
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPOpenMessage":
        """Unpack SFTP open message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        filename_bytes, offset = read_string(data, offset)
        pflags, offset = read_uint32(data, offset)
        attrs, offset = SFTPAttributes.unpack(data, offset)
        
        filename = filename_bytes.decode('utf-8')
        return cls(request_id, filename, pflags, attrs)
    
    def validate(self) -> bool:
        """
        Validate SFTP open message content.
        
        Returns:
            True if message is valid
            
        Raises:
            ProtocolException: If message is invalid
        """
        super().validate()
        
        # Validate filename
        if not self.filename:
            raise ProtocolException("Filename cannot be empty")
        
        # Validate flags
        valid_flags = (SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_APPEND | 
                      SSH_FXF_CREAT | SSH_FXF_TRUNC | SSH_FXF_EXCL)
        if self.pflags & ~valid_flags:
            raise ProtocolException(f"Invalid open flags: {self.pflags}")
        
        # Must have at least read or write flag
        if not (self.pflags & (SSH_FXF_READ | SSH_FXF_WRITE)):
            raise ProtocolException("Must specify read or write flag")
        
        return True


class SFTPHandleMessage(SFTPMessage):
    """SFTP handle message (SSH_FXP_HANDLE)."""
    
    def __init__(self, request_id: int, handle: bytes) -> None:
        """
        Initialize SFTP handle message.
        
        Args:
            request_id: Request ID this handle responds to
            handle: File handle
        """
        super().__init__(SSH_FXP_HANDLE, request_id)
        self.handle = handle
        
        # Build message data
        self.add_string(handle)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPHandleMessage":
        """Unpack SFTP handle message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        handle, offset = read_string(data, offset)
        
        return cls(request_id, handle)


class SFTPCloseMessage(SFTPMessage):
    """SFTP close file message (SSH_FXP_CLOSE)."""
    
    def __init__(self, request_id: int, handle: bytes) -> None:
        """
        Initialize SFTP close message.
        
        Args:
            request_id: Request ID
            handle: File handle to close
        """
        super().__init__(SSH_FXP_CLOSE, request_id)
        self.handle = handle
        
        # Build message data
        self.add_string(handle)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPCloseMessage":
        """Unpack SFTP close message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        handle, offset = read_string(data, offset)
        
        return cls(request_id, handle)


class SFTPReadMessage(SFTPMessage):
    """SFTP read file message (SSH_FXP_READ)."""
    
    def __init__(self, request_id: int, handle: bytes, offset: int, length: int) -> None:
        """
        Initialize SFTP read message.
        
        Args:
            request_id: Request ID
            handle: File handle
            offset: Byte offset to read from
            length: Number of bytes to read
        """
        super().__init__(SSH_FXP_READ, request_id)
        self.handle = handle
        self.offset = offset
        self.length = length
        
        # Build message data
        self.add_string(handle)
        self.add_uint64(offset)
        self.add_uint32(length)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPReadMessage":
        """Unpack SFTP read message data."""
        offset_pos = 0
        request_id, offset_pos = read_uint32(data, offset_pos)
        handle, offset_pos = read_string(data, offset_pos)
        file_offset, offset_pos = read_uint64(data, offset_pos)
        length, offset_pos = read_uint32(data, offset_pos)
        
        return cls(request_id, handle, file_offset, length)


class SFTPWriteMessage(SFTPMessage):
    """SFTP write file message (SSH_FXP_WRITE)."""
    
    def __init__(self, request_id: int, handle: bytes, offset: int, data: bytes) -> None:
        """
        Initialize SFTP write message.
        
        Args:
            request_id: Request ID
            handle: File handle
            offset: Byte offset to write to
            data: Data to write
        """
        super().__init__(SSH_FXP_WRITE, request_id)
        self.handle = handle
        self.offset = offset
        self.data = data
        
        # Build message data
        self.add_string(handle)
        self.add_uint64(offset)
        self.add_string(data)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPWriteMessage":
        """Unpack SFTP write message data."""
        offset_pos = 0
        request_id, offset_pos = read_uint32(data, offset_pos)
        handle, offset_pos = read_string(data, offset_pos)
        file_offset, offset_pos = read_uint64(data, offset_pos)
        write_data, offset_pos = read_string(data, offset_pos)
        
        return cls(request_id, handle, file_offset, write_data)


class SFTPDataMessage(SFTPMessage):
    """SFTP data message (SSH_FXP_DATA)."""
    
    def __init__(self, request_id: int, data: bytes) -> None:
        """
        Initialize SFTP data message.
        
        Args:
            request_id: Request ID this data responds to
            data: File data
        """
        super().__init__(SSH_FXP_DATA, request_id)
        self.data = data
        
        # Build message data
        self.add_string(data)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPDataMessage":
        """Unpack SFTP data message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        file_data, offset = read_string(data, offset)
        
        return cls(request_id, file_data)


class SFTPStatMessage(SFTPMessage):
    """SFTP stat message (SSH_FXP_STAT)."""
    
    def __init__(self, request_id: int, path: str) -> None:
        """
        Initialize SFTP stat message.
        
        Args:
            request_id: Request ID
            path: Path to get attributes for
        """
        super().__init__(SSH_FXP_STAT, request_id)
        self.path = path
        
        # Build message data
        self.add_string(path)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPStatMessage":
        """Unpack SFTP stat message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        path_bytes, offset = read_string(data, offset)
        
        path = path_bytes.decode('utf-8')
        return cls(request_id, path)


class SFTPLStatMessage(SFTPMessage):
    """SFTP lstat message (SSH_FXP_LSTAT)."""
    
    def __init__(self, request_id: int, path: str) -> None:
        """
        Initialize SFTP lstat message.
        
        Args:
            request_id: Request ID
            path: Path to get attributes for (don't follow symlinks)
        """
        super().__init__(SSH_FXP_LSTAT, request_id)
        self.path = path
        
        # Build message data
        self.add_string(path)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPLStatMessage":
        """Unpack SFTP lstat message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        path_bytes, offset = read_string(data, offset)
        
        path = path_bytes.decode('utf-8')
        return cls(request_id, path)


class SFTPFStatMessage(SFTPMessage):
    """SFTP fstat message (SSH_FXP_FSTAT)."""
    
    def __init__(self, request_id: int, handle: bytes) -> None:
        """
        Initialize SFTP fstat message.
        
        Args:
            request_id: Request ID
            handle: File handle to get attributes for
        """
        super().__init__(SSH_FXP_FSTAT, request_id)
        self.handle = handle
        
        # Build message data
        self.add_string(handle)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPFStatMessage":
        """Unpack SFTP fstat message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        handle, offset = read_string(data, offset)
        
        return cls(request_id, handle)


class SFTPAttrsMessage(SFTPMessage):
    """SFTP attributes message (SSH_FXP_ATTRS)."""
    
    def __init__(self, request_id: int, attrs: SFTPAttributes) -> None:
        """
        Initialize SFTP attributes message.
        
        Args:
            request_id: Request ID this responds to
            attrs: File attributes
        """
        super().__init__(SSH_FXP_ATTRS, request_id)
        self.attrs = attrs
        
        # Build message data
        self._data.extend(attrs.pack())
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPAttrsMessage":
        """Unpack SFTP attributes message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        attrs, offset = SFTPAttributes.unpack(data, offset)
        
        return cls(request_id, attrs)


class SFTPSetStatMessage(SFTPMessage):
    """SFTP setstat message (SSH_FXP_SETSTAT)."""
    
    def __init__(self, request_id: int, path: str, attrs: SFTPAttributes) -> None:
        """
        Initialize SFTP setstat message.
        
        Args:
            request_id: Request ID
            path: Path to set attributes for
            attrs: New attributes
        """
        super().__init__(SSH_FXP_SETSTAT, request_id)
        self.path = path
        self.attrs = attrs
        
        # Build message data
        self.add_string(path)
        self._data.extend(attrs.pack())
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPSetStatMessage":
        """Unpack SFTP setstat message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        path_bytes, offset = read_string(data, offset)
        attrs, offset = SFTPAttributes.unpack(data, offset)
        
        path = path_bytes.decode('utf-8')
        return cls(request_id, path, attrs)


class SFTPOpenDirMessage(SFTPMessage):
    """SFTP opendir message (SSH_FXP_OPENDIR)."""
    
    def __init__(self, request_id: int, path: str) -> None:
        """
        Initialize SFTP opendir message.
        
        Args:
            request_id: Request ID
            path: Directory path to open
        """
        super().__init__(SSH_FXP_OPENDIR, request_id)
        self.path = path
        
        # Build message data
        self.add_string(path)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPOpenDirMessage":
        """Unpack SFTP opendir message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        path_bytes, offset = read_string(data, offset)
        
        path = path_bytes.decode('utf-8')
        return cls(request_id, path)


class SFTPReadDirMessage(SFTPMessage):
    """SFTP readdir message (SSH_FXP_READDIR)."""
    
    def __init__(self, request_id: int, handle: bytes) -> None:
        """
        Initialize SFTP readdir message.
        
        Args:
            request_id: Request ID
            handle: Directory handle
        """
        super().__init__(SSH_FXP_READDIR, request_id)
        self.handle = handle
        
        # Build message data
        self.add_string(handle)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPReadDirMessage":
        """Unpack SFTP readdir message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        handle, offset = read_string(data, offset)
        
        return cls(request_id, handle)


class SFTPNameMessage(SFTPMessage):
    """SFTP name message (SSH_FXP_NAME)."""
    
    def __init__(self, request_id: int, names: List[tuple[str, str, SFTPAttributes]]) -> None:
        """
        Initialize SFTP name message.
        
        Args:
            request_id: Request ID this responds to
            names: List of (filename, longname, attrs) tuples
        """
        super().__init__(SSH_FXP_NAME, request_id)
        self.names = names
        
        # Build message data
        self.add_uint32(len(names))
        for filename, longname, attrs in names:
            self.add_string(filename)
            self.add_string(longname)
            self._data.extend(attrs.pack())
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPNameMessage":
        """Unpack SFTP name message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        count, offset = read_uint32(data, offset)
        
        names = []
        for _ in range(count):
            filename_bytes, offset = read_string(data, offset)
            longname_bytes, offset = read_string(data, offset)
            attrs, offset = SFTPAttributes.unpack(data, offset)
            
            filename = filename_bytes.decode('utf-8')
            longname = longname_bytes.decode('utf-8')
            names.append((filename, longname, attrs))
        
        return cls(request_id, names)


class SFTPRemoveMessage(SFTPMessage):
    """SFTP remove message (SSH_FXP_REMOVE)."""
    
    def __init__(self, request_id: int, filename: str) -> None:
        """
        Initialize SFTP remove message.
        
        Args:
            request_id: Request ID
            filename: File to remove
        """
        super().__init__(SSH_FXP_REMOVE, request_id)
        self.filename = filename
        
        # Build message data
        self.add_string(filename)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPRemoveMessage":
        """Unpack SFTP remove message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        filename_bytes, offset = read_string(data, offset)
        
        filename = filename_bytes.decode('utf-8')
        return cls(request_id, filename)


class SFTPMkdirMessage(SFTPMessage):
    """SFTP mkdir message (SSH_FXP_MKDIR)."""
    
    def __init__(self, request_id: int, path: str, attrs: SFTPAttributes) -> None:
        """
        Initialize SFTP mkdir message.
        
        Args:
            request_id: Request ID
            path: Directory path to create
            attrs: Directory attributes
        """
        super().__init__(SSH_FXP_MKDIR, request_id)
        self.path = path
        self.attrs = attrs
        
        # Build message data
        self.add_string(path)
        self._data.extend(attrs.pack())
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPMkdirMessage":
        """Unpack SFTP mkdir message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        path_bytes, offset = read_string(data, offset)
        attrs, offset = SFTPAttributes.unpack(data, offset)
        
        path = path_bytes.decode('utf-8')
        return cls(request_id, path, attrs)


class SFTPRmdirMessage(SFTPMessage):
    """SFTP rmdir message (SSH_FXP_RMDIR)."""
    
    def __init__(self, request_id: int, path: str) -> None:
        """
        Initialize SFTP rmdir message.
        
        Args:
            request_id: Request ID
            path: Directory path to remove
        """
        super().__init__(SSH_FXP_RMDIR, request_id)
        self.path = path
        
        # Build message data
        self.add_string(path)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPRmdirMessage":
        """Unpack SFTP rmdir message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        path_bytes, offset = read_string(data, offset)
        
        path = path_bytes.decode('utf-8')
        return cls(request_id, path)


class SFTPRealPathMessage(SFTPMessage):
    """SFTP realpath message (SSH_FXP_REALPATH)."""
    
    def __init__(self, request_id: int, path: str) -> None:
        """
        Initialize SFTP realpath message.
        
        Args:
            request_id: Request ID
            path: Path to resolve
        """
        super().__init__(SSH_FXP_REALPATH, request_id)
        self.path = path
        
        # Build message data
        self.add_string(path)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPRealPathMessage":
        """Unpack SFTP realpath message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        path_bytes, offset = read_string(data, offset)
        
        path = path_bytes.decode('utf-8')
        return cls(request_id, path)


class SFTPRenameMessage(SFTPMessage):
    """SFTP rename message (SSH_FXP_RENAME)."""
    
    def __init__(self, request_id: int, oldpath: str, newpath: str) -> None:
        """
        Initialize SFTP rename message.
        
        Args:
            request_id: Request ID
            oldpath: Current path
            newpath: New path
        """
        super().__init__(SSH_FXP_RENAME, request_id)
        self.oldpath = oldpath
        self.newpath = newpath
        
        # Build message data
        self.add_string(oldpath)
        self.add_string(newpath)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPRenameMessage":
        """Unpack SFTP rename message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        oldpath_bytes, offset = read_string(data, offset)
        newpath_bytes, offset = read_string(data, offset)
        
        oldpath = oldpath_bytes.decode('utf-8')
        newpath = newpath_bytes.decode('utf-8')
        return cls(request_id, oldpath, newpath)


class SFTPLinkMessage(SFTPMessage):
    """SFTP link message (SSH_FXP_LINK)."""
    
    def __init__(self, request_id: int, linkpath: str, targetpath: str) -> None:
        """
        Initialize SFTP link message.
        
        Args:
            request_id: Request ID
            linkpath: Path where link should be created
            targetpath: Target path for the link
        """
        super().__init__(SSH_FXP_LINK, request_id)
        self.linkpath = linkpath
        self.targetpath = targetpath
        
        # Build message data
        self.add_string(linkpath)
        self.add_string(targetpath)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPLinkMessage":
        """Unpack SFTP link message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        linkpath_bytes, offset = read_string(data, offset)
        targetpath_bytes, offset = read_string(data, offset)
        
        linkpath = linkpath_bytes.decode('utf-8')
        targetpath = targetpath_bytes.decode('utf-8')
        return cls(request_id, linkpath, targetpath)


class SFTPExtendedMessage(SFTPMessage):
    """SFTP extended message (SSH_FXP_EXTENDED)."""
    
    def __init__(self, request_id: int, extended_request: str, extended_data: bytes = b"") -> None:
        """
        Initialize SFTP extended message.
        
        Args:
            request_id: Request ID
            extended_request: Extended request name
            extended_data: Extended request data
        """
        super().__init__(SSH_FXP_EXTENDED, request_id)
        self.extended_request = extended_request
        self.extended_data = extended_data
        
        # Build message data
        self.add_string(extended_request)
        if extended_data:
            self._data.extend(extended_data)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPExtendedMessage":
        """Unpack SFTP extended message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        extended_request_bytes, offset = read_string(data, offset)
        
        extended_request = extended_request_bytes.decode('utf-8')
        extended_data = data[offset:] if offset < len(data) else b""
        
        return cls(request_id, extended_request, extended_data)


class SFTPExtendedReplyMessage(SFTPMessage):
    """SFTP extended reply message (SSH_FXP_EXTENDED_REPLY)."""
    
    def __init__(self, request_id: int, extended_data: bytes = b"") -> None:
        """
        Initialize SFTP extended reply message.
        
        Args:
            request_id: Request ID this reply responds to
            extended_data: Extended reply data
        """
        super().__init__(SSH_FXP_EXTENDED_REPLY, request_id)
        self.extended_data = extended_data
        
        # Build message data
        if extended_data:
            self._data.extend(extended_data)
    
    @classmethod
    def _unpack_data(cls, data: bytes) -> "SFTPExtendedReplyMessage":
        """Unpack SFTP extended reply message data."""
        offset = 0
        request_id, offset = read_uint32(data, offset)
        extended_data = data[offset:] if offset < len(data) else b""
        
        return cls(request_id, extended_data)