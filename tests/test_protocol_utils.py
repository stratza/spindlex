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


def test_read_byte():
    data = b"\x01\x02\x03"
    val, next_off = read_byte(data, 0)
    assert val == 1
    assert next_off == 1

    val, next_off = read_byte(data, 1)
    assert val == 2
    assert next_off == 2


def test_read_byte_insufficient_data():
    data = b"\x01"
    with pytest.raises(ProtocolException, match="Not enough data to read byte"):
        read_byte(data, 1)


def test_read_boolean():
    assert read_boolean(b"\x01", 0) == (True, 1)
    assert read_boolean(b"\x00", 0) == (False, 1)


def test_read_uint32():
    data = struct.pack(">I", 0x12345678) + b"extra"
    val, next_off = read_uint32(data, 0)
    assert val == 0x12345678
    assert next_off == 4


def test_read_uint32_insufficient_data():
    data = b"\x01\x02\x03"
    with pytest.raises(ProtocolException, match="Not enough data to read uint32"):
        read_uint32(data, 0)


def test_read_uint64():
    data = struct.pack(">Q", 0x123456789ABCDEF0)
    val, next_off = read_uint64(data, 0)
    assert val == 0x123456789ABCDEF0
    assert next_off == 8


def test_read_string():
    s = b"hello"
    data = struct.pack(">I", len(s)) + s + b"extra"
    val, next_off = read_string(data, 0)
    assert val == b"hello"
    assert next_off == 4 + len(s)


def test_read_mpint():
    # Example from RFC 4251
    # 0x00000000 -> 0
    assert read_mpint(b"\x00\x00\x00\x00", 0) == (0, 4)

    # 0x00000008 0x09a3d08f db59232d -> 0x09a3d08fdb59232d
    val = 0x09A3D08FDB59232D
    data = b"\x00\x00\x00\x08\x09\xa3\xd0\x8f\xdb\x59\x23\x2d"
    assert read_mpint(data, 0) == (val, 12)

    # Negative value
    data = b"\x00\x00\x00\x01\x80"
    assert read_mpint(data, 0) == (-128, 5)


def test_write_byte():
    assert write_byte(0x42) == b"\x42"
    with pytest.raises(ProtocolException, match="Byte value out of range"):
        write_byte(256)


def test_write_boolean():
    assert write_boolean(True) == b"\x01"
    assert write_boolean(False) == b"\x00"


def test_write_uint32():
    assert write_uint32(0x12345678) == b"\x12\x34\x56\x78"
    with pytest.raises(ProtocolException, match="uint32 value out of range"):
        write_uint32(0x100000000)


def test_write_uint64():
    assert write_uint64(0x123456789ABCDEF0) == b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"


def test_write_string():
    assert write_string("hello") == b"\x00\x00\x00\x05hello"
    assert write_string(b"world") == b"\x00\x00\x00\x05world"


def test_write_mpint():
    assert write_mpint(0) == b"\x00\x00\x00\x00"
    assert write_mpint(0x80) == b"\x00\x00\x00\x02\x00\x80"
    assert write_mpint(-128) == b"\x00\x00\x00\x01\x80"

    # Large positive integer
    val = 0x1234567890ABCDEF
    data = write_mpint(val)
    assert read_mpint(data, 0) == (val, len(data))

    # Large negative integer
    val = -0x1234567890ABCDEF
    data = write_mpint(val)
    assert read_mpint(data, 0) == (val, len(data))

    # Test path that might trigger OverflowError or specific byte_length logic
    # value = 0x80... (needs extra byte for sign if positive)
    val = 0x8000000000000000
    data = write_mpint(val)
    # length should be 4 + 9 = 13
    assert len(data) == 13
    assert data[4] == 0x00
    assert data[5] == 0x80
    assert read_mpint(data, 0) == (val, 13)


def test_read_uint64_insufficient_data():
    data = b"\x01\x02\x03\x04\x05\x06\x07"
    with pytest.raises(ProtocolException, match="Not enough data to read uint64"):
        read_uint64(data, 0)


def test_read_string_too_long():
    from spindlex.protocol.constants import MAX_PACKET_SIZE

    # We need to provide at least enough data to satisfy new_offset + length > len(data) check
    # but length must be > MAX_PACKET_SIZE.
    # Actually, the check 'if new_offset + length > len(data)' comes BEFORE 'if length > MAX_PACKET_SIZE'.
    # To hit "String too long", we need to provide enough data.
    length = MAX_PACKET_SIZE + 1
    data = struct.pack(">I", length) + b"a" * length
    with pytest.raises(ProtocolException, match="String too long"):
        read_string(data, 0)


def test_read_string_insufficient_data():
    data = struct.pack(">I", 10) + b"short"
    with pytest.raises(ProtocolException, match="Not enough data to read string"):
        read_string(data, 0)


def test_write_uint64_out_of_range():
    with pytest.raises(ProtocolException, match="uint64 value out of range"):
        write_uint64(-1)
    with pytest.raises(ProtocolException, match="uint64 value out of range"):
        write_uint64(0x10000000000000000)


def test_write_string_too_long():
    from spindlex.protocol.constants import MAX_PACKET_SIZE

    long_string = "a" * (MAX_PACKET_SIZE + 1)
    with pytest.raises(ProtocolException, match="String too long"):
        write_string(long_string)


def test_validate_packet_structure_errors():
    from spindlex.protocol.constants import MAX_PACKET_SIZE

    # Too small
    with pytest.raises(ProtocolException, match="Packet too small"):
        validate_packet_structure(b"abc")

    # Too large
    with pytest.raises(ProtocolException, match="Packet too large"):
        validate_packet_structure(b"a" * (MAX_PACKET_SIZE + 1))

    # Invalid packet length (too small)
    # MIN_PACKET_SIZE is 16. PACKET_LENGTH_SIZE is 4.
    # packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE => packet_length < 12
    data = struct.pack(">I", 11) + b"a" * 12
    with pytest.raises(ProtocolException, match="Invalid packet length"):
        validate_packet_structure(data)

    # Packet length too large
    data = struct.pack(">I", MAX_PACKET_SIZE + 1) + b"a" * 16
    with pytest.raises(ProtocolException, match="Packet length too large"):
        validate_packet_structure(data)

    # Incomplete packet
    # length=20, but only 16 bytes provided
    data = struct.pack(">I", 20) + b"a" * 12
    with pytest.raises(ProtocolException, match="Incomplete packet"):
        validate_packet_structure(data)

    # Padding too small
    payload = b"msg_content_long_enough"
    padding_len = 3  # Min is 4
    packet_len = 1 + len(payload) + padding_len
    # Ensure packet_len >= 12
    data = (
        struct.pack(">I", packet_len)
        + bytes([padding_len])
        + payload
        + b"\x00" * padding_len
    )
    with pytest.raises(ProtocolException, match="Padding too small"):
        validate_packet_structure(data)

    # Invalid payload length
    # payload_length = packet_length - PADDING_LENGTH_SIZE - padding_length
    # we want payload_length < 1
    padding_len = 15
    payload = b""
    packet_len = 1 + len(payload) + padding_len  # 1 + 0 + 15 = 16
    # payload_length = 16 - 1 - 15 = 0
    data = (
        struct.pack(">I", packet_len)
        + bytes([padding_len])
        + payload
        + b"\x00" * padding_len
    )
    with pytest.raises(ProtocolException, match="Invalid payload length"):
        validate_packet_structure(data)
    # packet_length = 12 (payload_size + 1 + padding_size)
    # padding_length = 10
    # payload = b"m" (1 byte)
    # total size = 4 + 12 = 16
    payload = b"m"
    padding_len = 10
    packet_len = 1 + len(payload) + padding_len
    data = (
        struct.pack(">I", packet_len)
        + bytes([padding_len])
        + payload
        + b"\x00" * padding_len
    )

    assert validate_packet_structure(data) is True


def test_extract_message_from_packet():
    payload = b"message_content"
    padding_len = 10
    packet_len = 1 + len(payload) + padding_len
    data = (
        struct.pack(">I", packet_len)
        + bytes([padding_len])
        + payload
        + b"\x00" * padding_len
    )

    assert extract_message_from_packet(data) == payload


def test_validate_message_type():
    from spindlex.protocol.constants import MSG_KEXINIT, validate_message_type

    assert validate_message_type(MSG_KEXINIT) is True
    assert validate_message_type(256) is False
