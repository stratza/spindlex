"""Unit tests for AsyncChannel and AsyncChannelFile."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from spindlex.exceptions import ChannelException
from spindlex.transport.async_channel import AsyncChannel, AsyncChannelFile


def _make_transport(channels=None):
    t = MagicMock()
    t._channels = channels if channels is not None else {}
    t._state_lock = asyncio.Lock()
    t._pump_async = AsyncMock()
    t._send_channel_data_async = AsyncMock()
    t._send_channel_request_async = AsyncMock()
    t._send_channel_eof_async = AsyncMock()
    t._send_channel_close_async = AsyncMock()
    t._send_channel_window_adjust_async = AsyncMock()
    return t


def _make_channel(channel_id=0, remote_window=65536, remote_max_packet=32768):
    t = _make_transport()
    chan = AsyncChannel(t, channel_id)
    t._channels[channel_id] = chan
    chan._remote_channel_id = 1
    chan._remote_window_size = remote_window
    chan._remote_max_packet_size = remote_max_packet
    return chan, t


# ── Construction ────────────────────────────────────────────────────────────


def test_init_sets_defaults():
    t = _make_transport()
    chan = AsyncChannel(t, 7)
    assert chan._channel_id == 7
    assert chan._recv_buffer == b""
    assert chan._stderr_buffer == b""
    assert not chan._closed


# ── Internal handlers ────────────────────────────────────────────────────────


def test_handle_data_appends():
    chan, _ = _make_channel()
    chan._handle_data(b"hello")
    chan._handle_data(b" world")
    assert chan._recv_buffer == b"hello world"


def test_handle_extended_data_stderr():
    from spindlex.protocol.constants import SSH_EXTENDED_DATA_STDERR

    chan, _ = _make_channel()
    chan._handle_extended_data(SSH_EXTENDED_DATA_STDERR, b"err")
    assert chan._stderr_buffer == b"err"


def test_handle_extended_data_unknown_ignored():
    chan, _ = _make_channel()
    chan._handle_extended_data(99, b"ignored")
    assert chan._stderr_buffer == b""


def test_handle_eof():
    chan, _ = _make_channel()
    chan._handle_eof()
    assert chan._eof_received


# ── send ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_closed_raises():
    chan, _ = _make_channel()
    chan._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await chan.send(b"data")


@pytest.mark.asyncio
async def test_send_empty_returns_zero():
    chan, _ = _make_channel()
    result = await chan.send(b"")
    assert result == 0


@pytest.mark.asyncio
async def test_send_string_encodes():
    chan, t = _make_channel()
    await chan.send("hello")
    t._send_channel_data_async.assert_called_once_with(0, b"hello")


@pytest.mark.asyncio
async def test_send_bytes():
    chan, t = _make_channel()
    n = await chan.send(b"ping")
    assert n == 4
    t._send_channel_data_async.assert_called_once_with(0, b"ping")
    assert chan._remote_window_size == 65536 - 4


@pytest.mark.asyncio
async def test_send_pumps_when_window_zero():
    chan, t = _make_channel(remote_window=0)
    # After one pump, window is still 0 then channel gets force-closed to break loop
    # We allow one pump call then open the window to avoid infinite loop
    call_count = 0

    async def open_window():
        nonlocal call_count
        call_count += 1
        if call_count >= 1:
            chan._remote_window_size = 100

    t._pump_async.side_effect = open_window
    await chan.send(b"x")
    assert t._pump_async.call_count >= 1


@pytest.mark.asyncio
async def test_send_wraps_non_channel_exception():
    chan, t = _make_channel()
    t._send_channel_data_async.side_effect = RuntimeError("boom")
    with pytest.raises(ChannelException, match="Send failed"):
        await chan.send(b"data")


@pytest.mark.asyncio
async def test_sendall_delegates():
    chan, t = _make_channel()
    await chan.sendall(b"abc")
    t._send_channel_data_async.assert_called_once()


# ── recv ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_recv_closed_empty_raises():
    chan, _ = _make_channel()
    chan._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await chan.recv(10)


@pytest.mark.asyncio
async def test_recv_returns_buffered_data():
    chan, t = _make_channel()
    chan._recv_buffer = b"helloworld"
    data = await chan.recv(5)
    assert data == b"hello"
    assert chan._recv_buffer == b"world"


@pytest.mark.asyncio
async def test_recv_nbytes_zero_returns_all():
    chan, t = _make_channel()
    chan._recv_buffer = b"all"
    data = await chan.recv(0)
    assert data == b"all"
    assert chan._recv_buffer == b""


@pytest.mark.asyncio
async def test_recv_eof_returns_empty():
    chan, t = _make_channel()
    chan._eof_received = True
    data = await chan.recv(10)
    assert data == b""


@pytest.mark.asyncio
async def test_recv_pumps_then_gets_data():
    chan, t = _make_channel()

    async def fill_buffer():
        chan._recv_buffer = b"hello"

    t._pump_async.side_effect = fill_buffer
    data = await chan.recv(10)
    assert data == b"hello"
    assert t._pump_async.call_count == 1


@pytest.mark.asyncio
async def test_recv_wraps_exception():
    chan, t = _make_channel()
    t._pump_async.side_effect = RuntimeError("net error")
    with pytest.raises(ChannelException, match="Receive failed"):
        await chan.recv(10)


# ── recv_exactly ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_recv_exactly_accumulates():
    chan, t = _make_channel()
    chan._recv_buffer = b"hello world"
    data = await chan.recv_exactly(5)
    assert data == b"hello"


@pytest.mark.asyncio
async def test_recv_exactly_raises_on_premature_close():
    chan, t = _make_channel()
    chan._eof_received = True  # will return b"" immediately
    with pytest.raises(ChannelException, match="Connection closed"):
        await chan.recv_exactly(5)


# ── recv_stderr ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_recv_stderr_closed_raises():
    chan, _ = _make_channel()
    chan._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await chan.recv_stderr(10)


@pytest.mark.asyncio
async def test_recv_stderr_returns_buffered():
    chan, t = _make_channel()
    chan._stderr_buffer = b"err"
    data = await chan.recv_stderr(100)
    assert data == b"err"
    assert chan._stderr_buffer == b""


@pytest.mark.asyncio
async def test_recv_stderr_eof_empty():
    chan, t = _make_channel()
    chan._eof_received = True
    data = await chan.recv_stderr(10)
    assert data == b""


# ── exec_command ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_exec_command_closed_raises():
    chan, _ = _make_channel()
    chan._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await chan.exec_command("ls")


@pytest.mark.asyncio
async def test_exec_command_success():
    chan, t = _make_channel()
    chan._request_success = True
    chan._request_event = MagicMock()
    chan._request_event.is_set.side_effect = [False, True]

    async def pump():
        chan._request_event.is_set.side_effect = [True]

    t._pump_async.side_effect = pump
    await chan.exec_command("echo hi")
    t._send_channel_request_async.assert_called_once()


@pytest.mark.asyncio
async def test_exec_command_failure_raises():
    chan, t = _make_channel()
    chan._request_success = False
    chan._request_event = MagicMock()
    chan._request_event.is_set.side_effect = [True]
    with pytest.raises(ChannelException):
        await chan.exec_command("bad")


# ── invoke_shell ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invoke_shell_closed_raises():
    chan, _ = _make_channel()
    chan._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await chan.invoke_shell()


@pytest.mark.asyncio
async def test_invoke_shell_success():
    chan, t = _make_channel()
    chan._request_success = True
    chan._request_event = MagicMock()
    chan._request_event.is_set.return_value = True
    await chan.invoke_shell()
    t._send_channel_request_async.assert_called_once_with(0, "shell", True, b"")


@pytest.mark.asyncio
async def test_invoke_shell_failure():
    chan, t = _make_channel()
    chan._request_success = False
    chan._request_event = MagicMock()
    chan._request_event.is_set.return_value = True
    with pytest.raises(ChannelException, match="Shell invocation failed"):
        await chan.invoke_shell()


# ── invoke_subsystem ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_invoke_subsystem_closed_raises():
    chan, _ = _make_channel()
    chan._closed = True
    with pytest.raises(ChannelException, match="closed"):
        await chan.invoke_subsystem("sftp")


@pytest.mark.asyncio
async def test_invoke_subsystem_success():
    chan, t = _make_channel()
    chan._request_success = True
    chan._request_event = MagicMock()
    chan._request_event.is_set.return_value = True
    await chan.invoke_subsystem("sftp")
    t._send_channel_request_async.assert_called_once()


@pytest.mark.asyncio
async def test_invoke_subsystem_failure():
    chan, t = _make_channel()
    chan._request_success = False
    chan._request_event = MagicMock()
    chan._request_event.is_set.return_value = True
    with pytest.raises(ChannelException, match="Subsystem invocation failed"):
        await chan.invoke_subsystem("sftp")


# ── send_exit_status ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_exit_status():
    chan, t = _make_channel()
    await chan.send_exit_status(0)
    t._send_channel_request_async.assert_called_once()
    args = t._send_channel_request_async.call_args[0]
    assert args[1] == "exit-status"
    assert args[2] is False


@pytest.mark.asyncio
async def test_send_exit_status_wraps_error():
    chan, t = _make_channel()
    t._send_channel_request_async.side_effect = RuntimeError("fail")
    with pytest.raises(ChannelException, match="Failed to send exit status"):
        await chan.send_exit_status(1)


# ── recv_exit_status ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_recv_exit_status_already_set():
    chan, t = _make_channel()
    chan._exit_status = 42
    status = await chan.recv_exit_status()
    assert status == 42
    t._pump_async.assert_not_called()


@pytest.mark.asyncio
async def test_recv_exit_status_pumps_until_set():
    chan, t = _make_channel()

    async def set_status():
        chan._exit_status = 0

    t._pump_async.side_effect = set_status
    status = await chan.recv_exit_status()
    assert status == 0


# ── close / wait_closed ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_close_marks_closed_and_removes_from_channels():
    chan, t = _make_channel()
    t._channels[0] = chan
    await chan.close()
    assert chan.closed
    assert 0 not in t._channels


@pytest.mark.asyncio
async def test_close_already_closed_is_noop():
    chan, t = _make_channel()
    chan._closed = True
    await chan.close()
    t._send_channel_eof_async.assert_not_called()


@pytest.mark.asyncio
async def test_wait_closed():
    chan, t = _make_channel()
    asyncio.get_event_loop().call_soon(lambda: chan._closed_event.set())
    await chan.wait_closed()
    assert chan._closed_event.is_set()


# ── makefile / makefile_stderr ────────────────────────────────────────────────


def test_makefile_returns_channel_file():
    chan, _ = _make_channel()
    f = chan.makefile()
    assert isinstance(f, AsyncChannelFile)
    assert not f._is_stderr


def test_makefile_stderr_returns_stderr_file():
    chan, _ = _make_channel()
    f = chan.makefile_stderr()
    assert isinstance(f, AsyncChannelFile)
    assert f._is_stderr


# ── AsyncChannelFile ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_channel_file_read():
    chan, t = _make_channel()
    chan._recv_buffer = b"data"
    f = AsyncChannelFile(chan, "r")
    result = await f.read(4)
    assert result == b"data"


@pytest.mark.asyncio
async def test_channel_file_read_stderr():
    chan, t = _make_channel()
    chan._stderr_buffer = b"err"
    f = AsyncChannelFile(chan, "r", is_stderr=True)
    result = await f.read(3)
    assert result == b"err"


@pytest.mark.asyncio
async def test_channel_file_read_closed_raises():
    chan, _ = _make_channel()
    f = AsyncChannelFile(chan, "r")
    f._closed = True
    with pytest.raises(ValueError, match="closed"):
        await f.read(1)


@pytest.mark.asyncio
async def test_channel_file_write():
    chan, t = _make_channel()
    f = AsyncChannelFile(chan, "w")
    n = await f.write(b"hello")
    assert n == 5


@pytest.mark.asyncio
async def test_channel_file_write_closed_raises():
    chan, _ = _make_channel()
    f = AsyncChannelFile(chan, "w")
    f._closed = True
    with pytest.raises(ValueError, match="closed"):
        await f.write(b"x")


@pytest.mark.asyncio
async def test_channel_file_close():
    chan, _ = _make_channel()
    f = AsyncChannelFile(chan, "r")
    await f.close()
    assert f._closed


def test_channel_file_get_exit_status():
    chan, _ = _make_channel()
    chan._exit_status = 5
    f = AsyncChannelFile(chan, "r")
    assert f.get_exit_status() == 5


@pytest.mark.asyncio
async def test_channel_file_recv_exit_status():
    chan, t = _make_channel()
    chan._exit_status = 3
    f = AsyncChannelFile(chan, "r")
    assert await f.recv_exit_status() == 3


@pytest.mark.asyncio
async def test_channel_file_readline():
    chan, t = _make_channel()
    lines = iter([b"h", b"i", b"\n"])
    t._pump_async.side_effect = None

    async def fake_recv(n):
        try:
            return next(lines)
        except StopIteration:
            return b""

    chan.recv = fake_recv
    f = AsyncChannelFile(chan, "r")
    line = await f.readline()
    assert line == "hi\n"


@pytest.mark.asyncio
async def test_channel_file_aiter():
    chan, t = _make_channel()
    # AsyncChannelFile.readline() reads 1 byte at a time, so we need to provide
    # bytes individually or handle multiple calls correctly.
    data = b"line1\nline2\n"
    it = iter(data)

    async def fake_recv(n):
        try:
            # Return 1 byte at a time to satisfy readline's loop
            return bytes([next(it)])
        except StopIteration:
            return b""

    chan.recv = fake_recv
    f = AsyncChannelFile(chan, "r")
    results = []
    async for line in f:
        results.append(line)
    assert results == ["line1\n", "line2\n"]


def test_channel_file_channel_property():
    chan, _ = _make_channel()
    f = AsyncChannelFile(chan, "r")
    assert f.channel is chan
