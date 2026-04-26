"""
Unit tests for spindlex/transport/async_channel.py

All tests are mock-based — no real SSH server connections are made.
pytest-asyncio is configured with asyncio_mode = "auto" in pyproject.toml,
so individual async tests do NOT need @pytest.mark.asyncio.
"""

from __future__ import annotations

import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock

import pytest

from spindlex.exceptions import ChannelException
from spindlex.protocol.constants import (
    DEFAULT_WINDOW_SIZE,
    SSH_EXTENDED_DATA_STDERR,
)
from spindlex.transport.async_channel import AsyncChannel, AsyncChannelFile

# ---------------------------------------------------------------------------
# Helper factory
# ---------------------------------------------------------------------------


def make_async_channel() -> tuple[AsyncChannel, MagicMock]:
    """Return a freshly created (channel, transport) pair with all async mocks."""
    transport = MagicMock()
    transport._pump_async = AsyncMock()
    transport._send_channel_data_async = AsyncMock()
    transport._send_channel_request_async = AsyncMock()
    transport._send_channel_eof_async = AsyncMock()
    transport._send_channel_close_async = AsyncMock()
    transport._send_channel_window_adjust_async = AsyncMock()
    transport._channels = {}
    transport._state_lock = asyncio.Lock()

    channel = AsyncChannel(transport, channel_id=1)
    channel._remote_channel_id = 100
    channel._remote_window_size = 1024 * 1024
    channel._remote_max_packet_size = 32768
    channel._local_window_size = DEFAULT_WINDOW_SIZE
    channel._closed = False
    channel._eof_received = False
    return channel, transport


# ---------------------------------------------------------------------------
# __init__
# ---------------------------------------------------------------------------


def test_init_creates_queue_and_event():
    channel, _ = make_async_channel()
    assert isinstance(channel._send_queue, asyncio.Queue)
    assert isinstance(channel._recv_queue, asyncio.Queue)
    assert isinstance(channel._closed_event, asyncio.Event)


def test_init_buffers_are_bytes():
    channel, _ = make_async_channel()
    assert channel._recv_buffer == b""
    assert channel._stderr_buffer == b""


def test_init_buffer_lock_is_threading_lock():
    channel, _ = make_async_channel()
    assert isinstance(channel._buffer_lock, type(threading.Lock()))


# ---------------------------------------------------------------------------
# _handle_data
# ---------------------------------------------------------------------------


def test_handle_data_appends_to_recv_buffer():
    channel, _ = make_async_channel()
    channel._handle_data(b"hello")
    channel._handle_data(b" world")
    assert channel._recv_buffer == b"hello world"


def test_handle_data_empty_bytes():
    channel, _ = make_async_channel()
    channel._handle_data(b"")
    assert channel._recv_buffer == b""


# ---------------------------------------------------------------------------
# _handle_extended_data
# ---------------------------------------------------------------------------


def test_handle_extended_data_stderr_type():
    channel, _ = make_async_channel()
    channel._handle_extended_data(SSH_EXTENDED_DATA_STDERR, b"error output")
    assert channel._stderr_buffer == b"error output"


def test_handle_extended_data_non_stderr_ignored():
    channel, _ = make_async_channel()
    channel._handle_extended_data(2, b"ignored")
    assert channel._stderr_buffer == b""


def test_handle_extended_data_appends():
    channel, _ = make_async_channel()
    channel._handle_extended_data(SSH_EXTENDED_DATA_STDERR, b"a")
    channel._handle_extended_data(SSH_EXTENDED_DATA_STDERR, b"b")
    assert channel._stderr_buffer == b"ab"


# ---------------------------------------------------------------------------
# _handle_eof
# ---------------------------------------------------------------------------


def test_handle_eof_sets_flag():
    channel, _ = make_async_channel()
    assert not channel._eof_received
    channel._handle_eof()
    assert channel._eof_received


# ---------------------------------------------------------------------------
# send
# ---------------------------------------------------------------------------


async def test_send_raises_when_closed():
    channel, _ = make_async_channel()
    channel._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await channel.send(b"data")


async def test_send_empty_bytes_returns_zero():
    channel, _ = make_async_channel()
    result = await channel.send(b"")
    assert result == 0


async def test_send_empty_string_returns_zero():
    channel, _ = make_async_channel()
    result = await channel.send("")
    assert result == 0


async def test_send_bytes_calls_transport():
    channel, transport = make_async_channel()
    result = await channel.send(b"hello")
    assert result == 5
    transport._send_channel_data_async.assert_called_once_with(1, b"hello")


async def test_send_string_is_encoded():
    channel, transport = make_async_channel()
    result = await channel.send("hi")
    assert result == 2
    # Called with encoded bytes
    transport._send_channel_data_async.assert_called_once()
    call_args = transport._send_channel_data_async.call_args[0]
    assert call_args[1] == b"hi"


async def test_send_decrements_remote_window_size():
    channel, transport = make_async_channel()
    initial = channel._remote_window_size
    await channel.send(b"abc")
    assert channel._remote_window_size == initial - 3


async def test_send_chunks_respect_max_packet_size():
    channel, transport = make_async_channel()
    channel._remote_max_packet_size = 4
    await channel.send(b"12345678")
    # Should have sent at least 2 chunks of ≤4 bytes
    assert transport._send_channel_data_async.call_count >= 2


async def test_send_window_zero_pumps_transport():
    channel, transport = make_async_channel()
    channel._remote_window_size = 0

    pump_call_count = 0

    async def pump_side_effect():
        nonlocal pump_call_count
        pump_call_count += 1
        channel._remote_window_size = 1024  # grant window after first pump

    transport._pump_async.side_effect = pump_side_effect
    await channel.send(b"data")
    assert pump_call_count >= 1


# ---------------------------------------------------------------------------
# sendall
# ---------------------------------------------------------------------------


async def test_sendall_delegates_to_send():
    channel, transport = make_async_channel()
    await channel.sendall(b"hello")
    transport._send_channel_data_async.assert_called_once()


# ---------------------------------------------------------------------------
# recv
# ---------------------------------------------------------------------------


async def test_recv_returns_data_from_buffer():
    channel, _ = make_async_channel()
    channel._recv_buffer = b"hello world"
    data = await channel.recv(5)
    assert data == b"hello"
    assert channel._recv_buffer == b" world"


async def test_recv_nbytes_zero_returns_all():
    channel, _ = make_async_channel()
    channel._recv_buffer = b"all data"
    data = await channel.recv(0)
    assert data == b"all data"
    assert channel._recv_buffer == b""


async def test_recv_eof_returns_empty():
    channel, _ = make_async_channel()
    channel._eof_received = True
    data = await channel.recv(10)
    assert data == b""


async def test_recv_closed_raises():
    channel, _ = make_async_channel()
    channel._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await channel.recv(10)


async def test_recv_pumps_when_buffer_empty():
    channel, transport = make_async_channel()

    call_count = 0

    async def pump_side_effect():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            channel._recv_buffer = b"data"

    transport._pump_async.side_effect = pump_side_effect
    data = await channel.recv(10)
    assert data == b"data"
    assert call_count >= 1


async def test_recv_calls_adjust_window():
    channel, transport = make_async_channel()
    # Drive window low to trigger adjust
    channel._local_window_size = 0
    channel._recv_buffer = b"hello"
    await channel.recv(5)
    transport._send_channel_window_adjust_async.assert_called()


# ---------------------------------------------------------------------------
# recv_exactly
# ---------------------------------------------------------------------------


async def test_recv_exactly_returns_exact_bytes():
    channel, _ = make_async_channel()
    channel._recv_buffer = b"1234567890"
    data = await channel.recv_exactly(5)
    assert data == b"12345"


async def test_recv_exactly_raises_on_early_eof():
    channel, _ = make_async_channel()
    channel._eof_received = True
    with pytest.raises(ChannelException, match="closed"):
        await channel.recv_exactly(5)


async def test_recv_exactly_accumulates_chunks():
    channel, transport = make_async_channel()

    call_count = 0

    async def pump_side_effect():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            channel._recv_buffer = b"abc"
        elif call_count == 2:
            channel._recv_buffer = b"de"

    transport._pump_async.side_effect = pump_side_effect
    data = await channel.recv_exactly(5)
    assert data == b"abcde"


# ---------------------------------------------------------------------------
# recv_stderr
# ---------------------------------------------------------------------------


async def test_recv_stderr_closed_and_empty_raises():
    channel, _ = make_async_channel()
    channel._closed = True
    channel._stderr_buffer = b""
    with pytest.raises(ChannelException, match="closed"):
        await channel.recv_stderr(10)


async def test_recv_stderr_returns_data():
    channel, _ = make_async_channel()
    channel._stderr_buffer = b"error"
    data = await channel.recv_stderr(10)
    assert data == b"error"
    assert channel._stderr_buffer == b""


async def test_recv_stderr_eof_with_empty_buffer_returns_empty():
    channel, _ = make_async_channel()
    channel._eof_received = True
    channel._stderr_buffer = b""
    data = await channel.recv_stderr(10)
    assert data == b""


async def test_recv_stderr_nbytes_zero_returns_all():
    channel, _ = make_async_channel()
    channel._stderr_buffer = b"stderr data"
    data = await channel.recv_stderr(0)
    assert data == b"stderr data"


async def test_recv_stderr_pumps_when_empty():
    channel, transport = make_async_channel()

    call_count = 0

    async def pump_side_effect():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            channel._stderr_buffer = b"err"

    transport._pump_async.side_effect = pump_side_effect
    data = await channel.recv_stderr(10)
    assert data == b"err"
    assert call_count >= 1


# ---------------------------------------------------------------------------
# _wait_for_channel_request_result
# ---------------------------------------------------------------------------


async def test_wait_for_request_result_returns_true_on_success():
    channel, transport = make_async_channel()

    async def pump_side_effect():
        channel._request_success = True
        channel._request_event.set()

    transport._pump_async.side_effect = pump_side_effect
    result = await channel._wait_for_channel_request_result()
    assert result is True


async def test_wait_for_request_result_returns_false_on_failure():
    channel, transport = make_async_channel()

    async def pump_side_effect():
        channel._request_success = False
        channel._request_event.set()

    transport._pump_async.side_effect = pump_side_effect
    result = await channel._wait_for_channel_request_result()
    assert result is False


# ---------------------------------------------------------------------------
# exec_command
# ---------------------------------------------------------------------------


async def test_exec_command_raises_when_closed():
    channel, _ = make_async_channel()
    channel._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await channel.exec_command("ls")


async def test_exec_command_success():
    channel, transport = make_async_channel()

    async def pump_side_effect():
        channel._request_success = True
        channel._request_event.set()

    transport._pump_async.side_effect = pump_side_effect
    await channel.exec_command("ls")
    transport._send_channel_request_async.assert_called_once()
    call_args = transport._send_channel_request_async.call_args[0]
    assert call_args[1] == "exec"
    assert call_args[2] is True


async def test_exec_command_failure_raises():
    channel, transport = make_async_channel()

    async def pump_side_effect():
        channel._request_success = False
        channel._request_event.set()

    transport._pump_async.side_effect = pump_side_effect
    with pytest.raises(ChannelException):
        await channel.exec_command("bad_command")


# ---------------------------------------------------------------------------
# invoke_shell
# ---------------------------------------------------------------------------


async def test_invoke_shell_raises_when_closed():
    channel, _ = make_async_channel()
    channel._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await channel.invoke_shell()


async def test_invoke_shell_success():
    channel, transport = make_async_channel()

    async def pump_side_effect():
        channel._request_success = True
        channel._request_event.set()

    transport._pump_async.side_effect = pump_side_effect
    await channel.invoke_shell()
    call_args = transport._send_channel_request_async.call_args[0]
    assert call_args[1] == "shell"


async def test_invoke_shell_failure_raises():
    channel, transport = make_async_channel()

    async def pump_side_effect():
        channel._request_success = False
        channel._request_event.set()

    transport._pump_async.side_effect = pump_side_effect
    with pytest.raises(ChannelException):
        await channel.invoke_shell()


# ---------------------------------------------------------------------------
# invoke_subsystem
# ---------------------------------------------------------------------------


async def test_invoke_subsystem_raises_when_closed():
    channel, _ = make_async_channel()
    channel._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await channel.invoke_subsystem("sftp")


async def test_invoke_subsystem_success():
    channel, transport = make_async_channel()

    async def pump_side_effect():
        channel._request_success = True
        channel._request_event.set()

    transport._pump_async.side_effect = pump_side_effect
    await channel.invoke_subsystem("sftp")
    call_args = transport._send_channel_request_async.call_args[0]
    assert call_args[1] == "subsystem"


async def test_invoke_subsystem_failure_raises():
    channel, transport = make_async_channel()

    async def pump_side_effect():
        channel._request_success = False
        channel._request_event.set()

    transport._pump_async.side_effect = pump_side_effect
    with pytest.raises(ChannelException):
        await channel.invoke_subsystem("sftp")


# ---------------------------------------------------------------------------
# send_exit_status
# ---------------------------------------------------------------------------


async def test_send_exit_status_calls_transport():
    channel, transport = make_async_channel()
    await channel.send_exit_status(0)
    transport._send_channel_request_async.assert_called_once()
    call_args = transport._send_channel_request_async.call_args[0]
    assert call_args[1] == "exit-status"
    assert call_args[2] is False


# ---------------------------------------------------------------------------
# recv_exit_status
# ---------------------------------------------------------------------------


async def test_recv_exit_status_returns_code():
    channel, transport = make_async_channel()
    channel._exit_status = 42

    status = await channel.recv_exit_status()
    assert status == 42


async def test_recv_exit_status_pumps_until_available():
    channel, transport = make_async_channel()
    channel._exit_status = None

    call_count = 0

    async def pump_side_effect():
        nonlocal call_count
        call_count += 1
        channel._exit_status = 0

    transport._pump_async.side_effect = pump_side_effect
    status = await channel.recv_exit_status()
    assert status == 0
    assert call_count >= 1


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


async def test_close_sends_eof_and_close():
    channel, transport = make_async_channel()
    await channel.close()
    transport._send_channel_eof_async.assert_called_once_with(1)
    transport._send_channel_close_async.assert_called_once_with(1)


async def test_close_sets_closed_flag():
    channel, transport = make_async_channel()
    await channel.close()
    assert channel._closed is True


async def test_close_idempotent():
    channel, transport = make_async_channel()
    await channel.close()
    await channel.close()
    # Should only send once (first close)
    assert transport._send_channel_eof_async.call_count == 1


async def test_close_removes_from_transport_channels():
    channel, transport = make_async_channel()
    transport._channels = {1: channel}
    await channel.close()
    assert 1 not in transport._channels


async def test_wait_closed_returns_after_close():
    channel, transport = make_async_channel()
    await channel.close()
    # Should resolve immediately since event is set
    await asyncio.wait_for(channel.wait_closed(), timeout=1.0)


# ---------------------------------------------------------------------------
# _adjust_window_async
# ---------------------------------------------------------------------------


async def test_adjust_window_sends_when_below_threshold():
    channel, transport = make_async_channel()
    channel._local_window_size = 0  # force below threshold
    await channel._adjust_window_async(10)
    transport._send_channel_window_adjust_async.assert_called_once()


async def test_adjust_window_no_send_when_above_threshold():
    channel, transport = make_async_channel()
    channel._local_window_size = DEFAULT_WINDOW_SIZE  # already full
    await channel._adjust_window_async(1)
    transport._send_channel_window_adjust_async.assert_not_called()


# ---------------------------------------------------------------------------
# makefile / makefile_stderr
# ---------------------------------------------------------------------------


def test_makefile_returns_async_channel_file():
    channel, _ = make_async_channel()
    f = channel.makefile("r")
    assert isinstance(f, AsyncChannelFile)
    assert f._is_stderr is False


def test_makefile_stderr_returns_async_channel_file():
    channel, _ = make_async_channel()
    f = channel.makefile_stderr("r")
    assert isinstance(f, AsyncChannelFile)
    assert f._is_stderr is True


# ---------------------------------------------------------------------------
# AsyncChannelFile tests
# ---------------------------------------------------------------------------


def test_channel_file_init_attributes():
    channel, _ = make_async_channel()
    f = AsyncChannelFile(channel, mode="rb", bufsize=1024, is_stderr=False)
    assert f._channel is channel
    assert f._mode == "rb"
    assert f._bufsize == 1024
    assert f._is_stderr is False
    assert f._closed is False


async def test_channel_file_read_returns_data():
    channel, transport = make_async_channel()
    channel._recv_buffer = b"file data"
    f = AsyncChannelFile(channel, mode="r")
    data = await f.read(9)
    assert data == b"file data"


async def test_channel_file_read_size_zero_returns_empty():
    channel, _ = make_async_channel()
    f = AsyncChannelFile(channel, mode="r")
    data = await f.read(0)
    assert data == b""


async def test_channel_file_read_raises_when_closed():
    channel, _ = make_async_channel()
    f = AsyncChannelFile(channel, mode="r")
    f._closed = True
    with pytest.raises(ValueError, match="closed"):
        await f.read(10)


async def test_channel_file_write_calls_send():
    channel, transport = make_async_channel()
    f = AsyncChannelFile(channel, mode="w")
    await f.write(b"write me")
    transport._send_channel_data_async.assert_called_once()


async def test_channel_file_write_raises_when_closed():
    channel, _ = make_async_channel()
    f = AsyncChannelFile(channel, mode="w")
    f._closed = True
    with pytest.raises(ValueError, match="closed"):
        await f.write(b"data")


async def test_channel_file_close_sets_closed():
    channel, _ = make_async_channel()
    f = AsyncChannelFile(channel, mode="r")
    await f.close()
    assert f._closed is True


async def test_channel_file_close_idempotent():
    channel, _ = make_async_channel()
    f = AsyncChannelFile(channel, mode="r")
    await f.close()
    await f.close()  # should not raise


async def test_channel_file_readline():
    channel, transport = make_async_channel()

    # Simulate reading "hi\n" one byte at a time
    chars = iter([b"h", b"i", b"\n"])

    async def mock_recv(nbytes):
        try:
            return next(chars)
        except StopIteration:
            return b""

    channel.recv = mock_recv

    f = AsyncChannelFile(channel, mode="r")
    line = await f.readline()
    assert line == "hi\n"


async def test_channel_file_aiter():
    channel, _ = make_async_channel()
    f = AsyncChannelFile(channel, mode="r")
    assert f.__aiter__() is f


async def test_channel_file_anext_raises_stop_async_iteration_on_eof():
    channel, _ = make_async_channel()
    channel._eof_received = True

    f = AsyncChannelFile(channel, mode="r")
    with pytest.raises(StopAsyncIteration):
        await f.__anext__()


async def test_channel_file_stderr_reads_stderr_buffer():
    channel, transport = make_async_channel()
    channel._stderr_buffer = b"stderr content"
    f = AsyncChannelFile(channel, mode="r", is_stderr=True)
    data = await f.read(14)
    assert data == b"stderr content"


def test_channel_file_get_exit_status():
    channel, _ = make_async_channel()
    channel._exit_status = 5
    f = AsyncChannelFile(channel, mode="r")
    assert f.get_exit_status() == 5


def test_channel_file_channel_property():
    channel, _ = make_async_channel()
    f = AsyncChannelFile(channel, mode="r")
    assert f.channel is channel
