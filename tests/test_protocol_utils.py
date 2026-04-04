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


def test_validate_packet_structure():
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
