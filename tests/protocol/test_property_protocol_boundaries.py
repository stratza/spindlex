from __future__ import annotations

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from spindlex.exceptions import ProtocolException
from spindlex.protocol.messages import ChannelDataMessage, IgnoreMessage, Message
from spindlex.protocol.sftp_messages import (
    SFTPDataMessage,
    SFTPReadMessage,
    SFTPStatusMessage,
    SFTPWriteMessage,
)
from spindlex.protocol.utils import (
    read_byte,
    read_mpint,
    read_string,
    read_uint32,
    read_uint64,
    write_byte,
    write_mpint,
    write_string,
    write_uint32,
    write_uint64,
)

BOUNDED = settings(
    max_examples=75,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


@given(st.integers(min_value=0, max_value=0xFFFFFFFF))
@BOUNDED
def test_uint32_round_trip(value: int) -> None:
    encoded = write_uint32(value)

    decoded, offset = read_uint32(encoded, 0)

    assert decoded == value
    assert offset == len(encoded)


@given(st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF))
@BOUNDED
def test_uint64_round_trip(value: int) -> None:
    encoded = write_uint64(value)

    decoded, offset = read_uint64(encoded, 0)

    assert decoded == value
    assert offset == len(encoded)


@given(st.integers(min_value=0, max_value=255))
@BOUNDED
def test_byte_round_trip(value: int) -> None:
    encoded = write_byte(value)

    decoded, offset = read_byte(encoded, 0)

    assert decoded == value
    assert offset == len(encoded)


@given(st.binary(max_size=512))
@BOUNDED
def test_string_round_trip(payload: bytes) -> None:
    encoded = write_string(payload)

    decoded, offset = read_string(encoded, 0)

    assert decoded == payload
    assert offset == len(encoded)


@given(st.integers(min_value=-(2**63), max_value=2**63 - 1))
@BOUNDED
def test_mpint_round_trip(value: int) -> None:
    encoded = write_mpint(value)

    decoded, offset = read_mpint(encoded, 0)

    assert decoded == value
    assert offset == len(encoded)


@given(
    st.integers(min_value=192, max_value=255),
    st.binary(max_size=512),
)
@BOUNDED
def test_generic_ssh_extension_message_round_trip(
    msg_type: int, payload: bytes
) -> None:
    message = Message(msg_type)
    message._data.extend(payload)

    unpacked = Message.unpack(message.pack())

    assert unpacked.msg_type == msg_type
    assert bytes(unpacked._data) == payload


@given(
    st.integers(min_value=0, max_value=0xFFFFFFFF),
    st.binary(max_size=512),
)
@BOUNDED
def test_channel_data_message_round_trip(channel: int, payload: bytes) -> None:
    unpacked = Message.unpack(ChannelDataMessage(channel, payload).pack())

    assert isinstance(unpacked, ChannelDataMessage)
    assert unpacked.recipient_channel == channel
    assert unpacked.data == payload


@given(st.binary(max_size=512))
@BOUNDED
def test_ignore_message_round_trip(payload: bytes) -> None:
    unpacked = Message.unpack(IgnoreMessage(payload).pack())

    assert isinstance(unpacked, IgnoreMessage)
    assert unpacked.data == payload


@given(
    st.integers(min_value=0, max_value=0xFFFFFFFF),
    st.binary(max_size=512),
)
@BOUNDED
def test_sftp_data_message_round_trip(request_id: int, payload: bytes) -> None:
    unpacked = SFTPDataMessage.unpack(SFTPDataMessage(request_id, payload).pack())

    assert isinstance(unpacked, SFTPDataMessage)
    assert unpacked.request_id == request_id
    assert unpacked.data == payload


@given(
    st.integers(min_value=0, max_value=0xFFFFFFFF),
    st.binary(min_size=1, max_size=64),
    st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    st.binary(max_size=512),
)
@BOUNDED
def test_sftp_write_message_round_trip(
    request_id: int, handle: bytes, offset: int, payload: bytes
) -> None:
    unpacked = SFTPWriteMessage.unpack(
        SFTPWriteMessage(request_id, handle, offset, payload).pack()
    )

    assert isinstance(unpacked, SFTPWriteMessage)
    assert unpacked.request_id == request_id
    assert unpacked.handle == handle
    assert unpacked.offset == offset
    assert unpacked.data == payload


@given(
    st.integers(min_value=0, max_value=0xFFFFFFFF),
    st.binary(min_size=1, max_size=64),
    st.integers(min_value=0, max_value=0xFFFFFFFFFFFFFFFF),
    st.integers(min_value=0, max_value=0xFFFFFFFF),
)
@BOUNDED
def test_sftp_read_message_round_trip(
    request_id: int, handle: bytes, offset: int, length: int
) -> None:
    unpacked = SFTPReadMessage.unpack(
        SFTPReadMessage(request_id, handle, offset, length).pack()
    )

    assert isinstance(unpacked, SFTPReadMessage)
    assert unpacked.request_id == request_id
    assert unpacked.handle == handle
    assert unpacked.offset == offset
    assert unpacked.length == length


@given(st.binary(max_size=16))
@BOUNDED
def test_truncated_sftp_status_rejects_without_partial_object(payload: bytes) -> None:
    with pytest.raises(ProtocolException):
        SFTPStatusMessage.unpack(payload)


@given(st.binary(max_size=3))
@BOUNDED
def test_truncated_uint32_rejects_as_protocol_error(payload: bytes) -> None:
    with pytest.raises(ProtocolException):
        read_uint32(payload, 0)
