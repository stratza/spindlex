"""
Tests for SSH protocol utility functions.
"""

import struct

import pytest

from spindlex.exceptions import ProtocolException
from spindlex.protocol.utils import (
    extract_message_from_packet,
    read_boolean,
    read_byte,
    read_mpint,
    read_string,
    read_uint32,
    read_uint64,
    validate_packet_structure,
    write_boolean,
    write_byte,
    write_mpint,
    write_string,
    write_uint32,
    write_uint64,
)


class TestReadFunctions:
    """Test protocol data reading functions."""

    def test_read_byte(self):
        """Test reading single byte."""
        data = b"\x42\x00\xff"
        value, offset = read_byte(data, 0)
        assert value == 0x42
        assert offset == 1

        value, offset = read_byte(data, 2)
        assert value == 0xFF
        assert offset == 3

    def test_read_byte_insufficient_data(self):
        """Test reading byte with insufficient data."""
        data = b"\x42"
        with pytest.raises(ProtocolException, match="Not enough data"):
            read_byte(data, 1)

    def test_read_boolean(self):
        """Test reading boolean values."""
        data = b"\x00\x01\x42"

        value, offset = read_boolean(data, 0)
        assert value is False
        assert offset == 1

        value, offset = read_boolean(data, 1)
        assert value is True
        assert offset == 2

        value, offset = read_boolean(data, 2)
        assert value is True  # Non-zero is True
        assert offset == 3

    def test_read_uint32(self):
        """Test reading 32-bit unsigned integers."""
        data = struct.pack(">II", 0x12345678, 0xFFFFFFFF)

        value, offset = read_uint32(data, 0)
        assert value == 0x12345678
        assert offset == 4

        value, offset = read_uint32(data, 4)
        assert value == 0xFFFFFFFF
        assert offset == 8

    def test_read_uint32_insufficient_data(self):
        """Test reading uint32 with insufficient data."""
        data = b"\x12\x34\x56"
        with pytest.raises(ProtocolException, match="Not enough data"):
            read_uint32(data, 0)

    def test_read_uint64(self):
        """Test reading 64-bit unsigned integers."""
        data = struct.pack(">Q", 0x123456789ABCDEF0)

        value, offset = read_uint64(data, 0)
        assert value == 0x123456789ABCDEF0
        assert offset == 8

    def test_read_string(self):
        """Test reading strings."""
        # String "hello"
        data = struct.pack(">I", 5) + b"hello"

        value, offset = read_string(data, 0)
        assert value == b"hello"
        assert offset == 9

    def test_read_string_empty(self):
        """Test reading empty string."""
        data = struct.pack(">I", 0)

        value, offset = read_string(data, 0)
        assert value == b""
        assert offset == 4

    def test_read_string_insufficient_data(self):
        """Test reading string with insufficient data."""
        data = struct.pack(">I", 10) + b"hello"
        with pytest.raises(ProtocolException, match="Not enough data"):
            read_string(data, 0)

    def test_read_mpint_positive(self):
        """Test reading positive multiple precision integers."""
        # Positive number 0x1234
        mpint_data = b"\x12\x34"
        data = struct.pack(">I", len(mpint_data)) + mpint_data

        value, offset = read_mpint(data, 0)
        assert value == 0x1234
        assert offset == 6

    def test_read_mpint_negative(self):
        """Test reading negative multiple precision integers."""
        # Negative number -1 (0xFF in two's complement)
        mpint_data = b"\xff"
        data = struct.pack(">I", len(mpint_data)) + mpint_data

        value, offset = read_mpint(data, 0)
        assert value == -1
        assert offset == 5

    def test_read_mpint_zero(self):
        """Test reading zero mpint."""
        data = struct.pack(">I", 0)

        value, offset = read_mpint(data, 0)
        assert value == 0
        assert offset == 4


class TestWriteFunctions:
    """Test protocol data writing functions."""

    def test_write_byte(self):
        """Test writing single byte."""
        assert write_byte(0x42) == b"\x42"
        assert write_byte(0) == b"\x00"
        assert write_byte(255) == b"\xff"

    def test_write_byte_invalid(self):
        """Test writing invalid byte values."""
        with pytest.raises(ProtocolException, match="Byte value out of range"):
            write_byte(-1)

        with pytest.raises(ProtocolException, match="Byte value out of range"):
            write_byte(256)

    def test_write_boolean(self):
        """Test writing boolean values."""
        assert write_boolean(True) == b"\x01"
        assert write_boolean(False) == b"\x00"

    def test_write_uint32(self):
        """Test writing 32-bit unsigned integers."""
        assert write_uint32(0x12345678) == struct.pack(">I", 0x12345678)
        assert write_uint32(0) == b"\x00\x00\x00\x00"
        assert write_uint32(0xFFFFFFFF) == b"\xff\xff\xff\xff"

    def test_write_uint32_invalid(self):
        """Test writing invalid uint32 values."""
        with pytest.raises(ProtocolException, match="uint32 value out of range"):
            write_uint32(-1)

        with pytest.raises(ProtocolException, match="uint32 value out of range"):
            write_uint32(0x100000000)

    def test_write_uint64(self):
        """Test writing 64-bit unsigned integers."""
        value = 0x123456789ABCDEF0
        assert write_uint64(value) == struct.pack(">Q", value)
        assert write_uint64(0) == b"\x00" * 8

    def test_write_string_bytes(self):
        """Test writing byte strings."""
        result = write_string(b"hello")
        expected = struct.pack(">I", 5) + b"hello"
        assert result == expected

    def test_write_string_text(self):
        """Test writing text strings."""
        result = write_string("hello")
        expected = struct.pack(">I", 5) + b"hello"
        assert result == expected

    def test_write_string_empty(self):
        """Test writing empty strings."""
        result = write_string("")
        expected = struct.pack(">I", 0)
        assert result == expected

    def test_write_mpint_positive(self):
        """Test writing positive multiple precision integers."""
        result = write_mpint(0x1234)
        # Should be length-prefixed bytes
        expected_bytes = (0x1234).to_bytes(2, byteorder="big", signed=True)
        expected = struct.pack(">I", len(expected_bytes)) + expected_bytes
        assert result == expected

    def test_write_mpint_negative(self):
        """Test writing negative multiple precision integers."""
        result = write_mpint(-1)
        expected_bytes = (-1).to_bytes(1, byteorder="big", signed=True)
        expected = struct.pack(">I", len(expected_bytes)) + expected_bytes
        assert result == expected

    def test_write_mpint_zero(self):
        """Test writing zero mpint."""
        result = write_mpint(0)
        expected = struct.pack(">I", 0)
        assert result == expected


class TestRoundTrip:
    """Test round-trip serialization/deserialization."""

    def test_byte_roundtrip(self):
        """Test byte round-trip."""
        original = 0x42
        data = write_byte(original)
        value, _ = read_byte(data, 0)
        assert value == original

    def test_boolean_roundtrip(self):
        """Test boolean round-trip."""
        for original in [True, False]:
            data = write_boolean(original)
            value, _ = read_boolean(data, 0)
            assert value == original

    def test_uint32_roundtrip(self):
        """Test uint32 round-trip."""
        for original in [0, 1, 0x12345678, 0xFFFFFFFF]:
            data = write_uint32(original)
            value, _ = read_uint32(data, 0)
            assert value == original

    def test_uint64_roundtrip(self):
        """Test uint64 round-trip."""
        for original in [0, 1, 0x123456789ABCDEF0, 0xFFFFFFFFFFFFFFFF]:
            data = write_uint64(original)
            value, _ = read_uint64(data, 0)
            assert value == original

    def test_string_roundtrip(self):
        """Test string round-trip."""
        for original in [b"", b"hello", b"test\x00\xff"]:
            data = write_string(original)
            value, _ = read_string(data, 0)
            assert value == original

    def test_mpint_roundtrip(self):
        """Test mpint round-trip."""
        test_values = [0, 1, -1, 0x1234, -0x1234, 0x123456789ABCDEF0]
        for original in test_values:
            data = write_mpint(original)
            value, _ = read_mpint(data, 0)
            assert value == original


class TestPacketValidation:
    """Test SSH packet structure validation."""

    def test_validate_valid_packet(self):
        """Test validation of valid packet structure."""
        # Create a minimal valid packet (16 bytes total)
        # packet_length (4) + padding_length (1) + payload (1) + padding (10) = 16 bytes
        packet_length = 12  # padding_length + payload + padding
        padding_length = 10
        payload = b"\x01"  # MSG_DISCONNECT
        padding = b"\x00" * padding_length

        packet = (
            struct.pack(">I", packet_length)
            + struct.pack("B", padding_length)
            + payload
            + padding
        )

        assert validate_packet_structure(packet) is True

    def test_validate_packet_too_small(self):
        """Test validation of packet that's too small."""
        packet = b"\x00" * 10  # Less than MIN_PACKET_SIZE
        with pytest.raises(ProtocolException, match="Packet too small"):
            validate_packet_structure(packet)

    def test_extract_message_from_packet(self):
        """Test extracting message from valid packet."""
        # Create packet with known payload (16 bytes total)
        packet_length = 12
        padding_length = 9
        payload = b"\x01\x42"  # MSG_DISCONNECT + some data
        padding = b"\x00" * padding_length

        packet = (
            struct.pack(">I", packet_length)
            + struct.pack("B", padding_length)
            + payload
            + padding
        )

        extracted = extract_message_from_packet(packet)
        assert extracted == payload
