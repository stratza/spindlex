"""
SSH Protocol Utility Functions

Provides utility functions for SSH protocol message parsing,
serialization, and validation.
"""

import struct
from typing import Union

from ..exceptions import ProtocolException
from .constants import (
    MAX_PACKET_SIZE,
    MAX_PADDING_SIZE,
    MIN_PACKET_SIZE,
    MIN_PADDING_SIZE,
    PACKET_LENGTH_SIZE,
    PADDING_LENGTH_SIZE,
    SSH_STRING_ENCODING,
)


def read_byte(data: bytes, offset: int) -> tuple[int, int]:
    """
    Read single byte from data.

    Args:
        data: Data buffer
        offset: Current offset

    Returns:
        Tuple of (value, new_offset)

    Raises:
        ProtocolException: If not enough data
    """
    if offset >= len(data):
        raise ProtocolException("Not enough data to read byte")

    return data[offset], offset + 1


def read_boolean(data: bytes, offset: int) -> tuple[bool, int]:
    """
    Read boolean from data.

    Args:
        data: Data buffer
        offset: Current offset

    Returns:
        Tuple of (value, new_offset)

    Raises:
        ProtocolException: If not enough data
    """
    value, new_offset = read_byte(data, offset)
    return bool(value), new_offset


def read_uint32(data: bytes, offset: int) -> tuple[int, int]:
    """
    Read 32-bit unsigned integer from data.

    Args:
        data: Data buffer
        offset: Current offset

    Returns:
        Tuple of (value, new_offset)

    Raises:
        ProtocolException: If not enough data
    """
    if offset + 4 > len(data):
        raise ProtocolException("Not enough data to read uint32")

    value = struct.unpack(">I", data[offset : offset + 4])[0]
    return value, offset + 4


def read_uint64(data: bytes, offset: int) -> tuple[int, int]:
    """
    Read 64-bit unsigned integer from data.

    Args:
        data: Data buffer
        offset: Current offset

    Returns:
        Tuple of (value, new_offset)

    Raises:
        ProtocolException: If not enough data
    """
    if offset + 8 > len(data):
        raise ProtocolException("Not enough data to read uint64")

    value = struct.unpack(">Q", data[offset : offset + 8])[0]
    return value, offset + 8


def read_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """
    Read string from data.

    Args:
        data: Data buffer
        offset: Current offset

    Returns:
        Tuple of (string_bytes, new_offset)

    Raises:
        ProtocolException: If not enough data or invalid string length
    """
    length, new_offset = read_uint32(data, offset)

    if new_offset + length > len(data):
        raise ProtocolException("Not enough data to read string")

    if length > MAX_PACKET_SIZE:
        raise ProtocolException(f"String too long: {length}")

    # Ensure result is bytes, even if data is bytearray
    string_data = bytes(data[new_offset : new_offset + length])
    return string_data, new_offset + length


def read_mpint(data: bytes, offset: int) -> tuple[int, int]:
    """
    Read multiple precision integer from data.

    Args:
        data: Data buffer
        offset: Current offset

    Returns:
        Tuple of (integer_value, new_offset)

    Raises:
        ProtocolException: If not enough data or invalid mpint
    """
    string_data, new_offset = read_string(data, offset)

    if len(string_data) == 0:
        return 0, new_offset

    # Convert bytes to integer (big-endian, two's complement)
    value = int.from_bytes(string_data, byteorder="big", signed=True)
    return value, new_offset


def write_byte(value: int) -> bytes:
    """
    Write single byte to bytes.

    Args:
        value: Byte value (0-255)

    Returns:
        Serialized byte

    Raises:
        ProtocolException: If value is out of range
    """
    if not (0 <= value <= 255):
        raise ProtocolException(f"Byte value out of range: {value}")

    return bytes([value])


def write_boolean(value: bool) -> bytes:
    """
    Write boolean to bytes.

    Args:
        value: Boolean value

    Returns:
        Serialized boolean
    """
    return write_byte(1 if value else 0)


def write_uint32(value: int) -> bytes:
    """
    Write 32-bit unsigned integer to bytes.

    Args:
        value: Integer value

    Returns:
        Serialized integer

    Raises:
        ProtocolException: If value is out of range
    """
    if not (0 <= value <= 0xFFFFFFFF):
        raise ProtocolException(f"uint32 value out of range: {value}")

    return struct.pack(">I", value)


def write_uint64(value: int) -> bytes:
    """
    Write 64-bit unsigned integer to bytes.

    Args:
        value: Integer value

    Returns:
        Serialized integer

    Raises:
        ProtocolException: If value is out of range
    """
    if not (0 <= value <= 0xFFFFFFFFFFFFFFFF):
        raise ProtocolException(f"uint64 value out of range: {value}")

    return struct.pack(">Q", value)


def write_string(value: Union[str, bytes]) -> bytes:
    """
    Write string to bytes.

    Args:
        value: String or bytes to write

    Returns:
        Serialized string with length prefix

    Raises:
        ProtocolException: If string is too long
    """
    if isinstance(value, str):
        value = value.encode(SSH_STRING_ENCODING)

    # Ensure value is bytes (not bytearray)
    value_bytes = bytes(value)

    if len(value_bytes) > MAX_PACKET_SIZE:
        raise ProtocolException(f"String too long: {len(value_bytes)}")

    return write_uint32(len(value_bytes)) + value_bytes


def write_mpint(value: int) -> bytes:
    """
    Write multiple precision integer to bytes.

    Args:
        value: Integer value

    Returns:
        Serialized mpint
    """
    if value == 0:
        return write_string(b"")

    # Convert integer to bytes (big-endian, two's complement)
    # Calculate minimum number of bytes needed
    bit_length = value.bit_length()
    byte_length = (bit_length + 7) // 8
    if byte_length == 0:
        byte_length = 1

    try:
        value_bytes = value.to_bytes(byte_length, byteorder="big", signed=True)
    except OverflowError:
        # Handle edge case where we need one more byte (for sign bit)
        byte_length += 1
        value_bytes = value.to_bytes(byte_length, byteorder="big", signed=True)

    return write_string(value_bytes)


def validate_packet_structure(packet_data: bytes) -> bool:
    """
    Validate SSH packet structure.

    Args:
        packet_data: Raw packet data

    Returns:
        True if packet structure is valid

    Raises:
        ProtocolException: If packet structure is invalid
    """
    if len(packet_data) < MIN_PACKET_SIZE:
        raise ProtocolException(f"Packet too small: {len(packet_data)}")

    if len(packet_data) > MAX_PACKET_SIZE:
        raise ProtocolException(f"Packet too large: {len(packet_data)}")

    # Read packet length
    packet_length = struct.unpack(">I", packet_data[:PACKET_LENGTH_SIZE])[0]

    # Validate packet length
    if packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE:
        raise ProtocolException(f"Invalid packet length: {packet_length}")

    if packet_length > MAX_PACKET_SIZE - PACKET_LENGTH_SIZE:
        raise ProtocolException(f"Packet length too large: {packet_length}")

    # Check if we have the complete packet
    if len(packet_data) < packet_length + PACKET_LENGTH_SIZE:
        raise ProtocolException("Incomplete packet")

    # Read padding length
    padding_length = packet_data[PACKET_LENGTH_SIZE]

    # Validate padding length
    if padding_length < MIN_PADDING_SIZE:
        raise ProtocolException(f"Padding too small: {padding_length}")

    if padding_length > MAX_PADDING_SIZE:
        raise ProtocolException(f"Padding too large: {padding_length}")

    # Calculate payload length
    payload_length = packet_length - PADDING_LENGTH_SIZE - padding_length

    if payload_length < 1:  # At least message type byte
        raise ProtocolException(f"Invalid payload length: {payload_length}")

    return True


def extract_message_from_packet(packet_data: bytes) -> bytes:
    """
    Extract message payload from SSH packet.

    Args:
        packet_data: Complete SSH packet

    Returns:
        Message payload (without packet framing)

    Raises:
        ProtocolException: If packet is invalid
    """
    validate_packet_structure(packet_data)

    # Read packet length and padding length
    packet_length = struct.unpack(">I", packet_data[:PACKET_LENGTH_SIZE])[0]
    padding_length = packet_data[PACKET_LENGTH_SIZE]

    # Extract payload
    payload_start = PACKET_LENGTH_SIZE + PADDING_LENGTH_SIZE
    payload_end = payload_start + packet_length - PADDING_LENGTH_SIZE - padding_length

    return packet_data[payload_start:payload_end]


__all__ = [
    "extract_message_from_packet",
    "read_boolean",
    "read_byte",
    "read_mpint",
    "read_string",
    "read_uint32",
    "read_uint64",
    "validate_packet_structure",
    "write_boolean",
    "write_byte",
    "write_mpint",
    "write_string",
    "write_uint32",
    "write_uint64",
]
