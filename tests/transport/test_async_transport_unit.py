"""Unit tests for AsyncTransport."""

import asyncio
import socket
from collections import deque
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from spindlex.exceptions import TransportException
from spindlex.transport.async_transport import AsyncTransport


def _make_sock():
    sock = MagicMock(spec=socket.socket)
    sock.fileno.return_value = 5
    sock.gettimeout.return_value = None
    return sock


def _make_transport(sock=None):
    if sock is None:
        sock = _make_sock()
    with patch.object(AsyncTransport, "__init__", lambda self, s, **kw: None):
        t = AsyncTransport.__new__(AsyncTransport)
    # Minimal attribute setup mirroring real __init__
    t._socket = sock
    t._reader = None
    t._writer = None
    t._loop = asyncio.get_event_loop()
    t._port_forwarding_manager = None
    t._send_lock = asyncio.Lock()
    t._recv_lock = asyncio.Lock()
    t._state_lock = asyncio.Lock()
    t._is_async = True
    t._active = False
    t._server_mode = False
    t._authenticated = False
    t._kex_in_progress = False
    t._kex_thread = None
    t._channels = {}
    t._next_channel_id = 0
    t._message_queue = deque()
    t._sequence_number_out = 0
    t._sequence_number_in = 0
    t._userauth_service_requested = False
    t._connect_timeout = None
    t._bytes_since_rekey = 0
    return t


# ── connect_existing ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_connect_existing_sets_reader_writer():
    t = _make_transport()
    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    await t.connect_existing(reader, writer)
    assert t._reader is reader
    assert t._writer is writer


# ── get_port_forwarding_manager ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_port_forwarding_manager_creates_once():
    t = _make_transport()
    mgr = t.get_port_forwarding_manager()
    assert mgr is not None
    mgr2 = t.get_port_forwarding_manager()
    assert mgr is mgr2


# ── _send_version_async ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_version_async_no_writer_raises():
    t = _make_transport()
    t._reader = None
    t._writer = None
    with pytest.raises(TransportException, match="not initialized"):
        await t._send_version_async()


@pytest.mark.asyncio
async def test_send_version_async_client_mode():
    t = _make_transport()
    t._server_mode = False
    writer = MagicMock()
    writer.drain = AsyncMock()
    t._writer = writer
    await t._send_version_async()
    writer.write.assert_called_once()
    written = writer.write.call_args[0][0]
    assert b"SSH-" in written


# ── _recv_version_async ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_recv_version_async_no_reader_raises():
    t = _make_transport()
    with pytest.raises(TransportException, match="not initialized"):
        await t._recv_version_async()


@pytest.mark.asyncio
async def test_recv_version_async_skips_banner_lines():
    t = _make_transport()
    reader = MagicMock(spec=asyncio.StreamReader)
    reader.readline = AsyncMock(
        side_effect=[b"banner line\r\n", b"SSH-2.0-OpenSSH_8.9\r\n"]
    )
    t._reader = reader
    t._server_mode = False
    await t._recv_version_async()
    assert t._server_version == "SSH-2.0-OpenSSH_8.9"


@pytest.mark.asyncio
async def test_recv_version_async_empty_raises():
    t = _make_transport()
    reader = MagicMock(spec=asyncio.StreamReader)
    reader.readline = AsyncMock(return_value=b"")
    t._reader = reader
    with pytest.raises(TransportException, match="Connection closed"):
        await t._recv_version_async()


# ── _build_keyboard_interactive_data ─────────────────────────────────────────


def test_build_keyboard_interactive_data():
    t = _make_transport()
    data = t._build_keyboard_interactive_data()
    assert isinstance(data, bytes)
    assert len(data) > 0


# ── _send_message bridge ──────────────────────────────────────────────────────


def test_send_message_no_loop_uses_super():
    t = _make_transport()
    t._loop = None
    msg = MagicMock()
    with patch("spindlex.transport.transport.Transport._send_message") as mock_super:
        t._send_message(msg)
        mock_super.assert_called_once_with(msg)


def test_send_message_loop_not_running_uses_super():
    t = _make_transport()
    loop = MagicMock()
    loop.is_running.return_value = False
    t._loop = loop
    msg = MagicMock()
    with patch("spindlex.transport.transport.Transport._send_message") as mock_super:
        t._send_message(msg)
        mock_super.assert_called_once_with(msg)


# ── _recv_message bridge ──────────────────────────────────────────────────────


def test_recv_message_no_loop_uses_super():
    t = _make_transport()
    t._loop = None
    msg = MagicMock()
    with patch(
        "spindlex.transport.transport.Transport._recv_message", return_value=msg
    ):
        result = t._recv_message()
        assert result is msg


# ── _recv_bytes bridge ────────────────────────────────────────────────────────


def test_recv_bytes_no_reader_raises():
    t = _make_transport()
    t._reader = None
    t._loop = None
    with pytest.raises(TransportException, match="not initialized"):
        t._recv_bytes(4)


# ── _send_message_async ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_message_async_no_writer_raises():
    t = _make_transport()
    t._writer = None
    msg = MagicMock()
    msg.msg_type = 5
    msg.pack.return_value = b"\x00" * 10
    with (
        patch.object(t, "_build_packet", return_value=b"\x00" * 20),
        patch.object(t, "_encrypt_packet", return_value=b"\x00" * 20),
        pytest.raises(TransportException, match="not initialized"),
    ):
        await t._send_message_async(msg)


@pytest.mark.asyncio
async def test_send_message_async_sends_and_drains():
    from spindlex.protocol.constants import MSG_NEWKEYS

    t = _make_transport()
    writer = MagicMock()
    writer.drain = AsyncMock()
    t._writer = writer

    msg = MagicMock()
    msg.msg_type = MSG_NEWKEYS
    msg.pack.return_value = b"\x00" * 4

    with (
        patch.object(t, "_build_packet", return_value=b"\x00" * 16),
        patch.object(t, "_encrypt_packet", return_value=b"\x00" * 16),
        patch.object(t, "_activate_outbound_encryption"),
    ):
        await t._send_message_async(msg)

    writer.write.assert_called_once()
    writer.drain.assert_awaited_once()


# ── _expect_message_async ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_expect_message_async_from_queue():
    t = _make_transport()
    msg = MagicMock()
    msg.msg_type = 20
    t._message_queue.append(msg)

    result = await t._expect_message_async(20)
    assert result is msg
    assert len(t._message_queue) == 0


@pytest.mark.asyncio
async def test_expect_message_async_queues_unmatched():
    t = _make_transport()
    wrong = MagicMock()
    wrong.msg_type = 99
    right = MagicMock()
    right.msg_type = 20

    call_count = [0]

    async def fake_recv(check_queue=True):
        call_count[0] += 1
        if call_count[0] == 1:
            return wrong
        return right

    with patch.object(t, "_recv_message_async", side_effect=fake_recv):
        result = await t._expect_message_async(20)

    assert result is right
    assert wrong in t._message_queue


# ── open_channel ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_open_channel_success():
    from spindlex.protocol.messages import ChannelOpenConfirmationMessage

    t = _make_transport()

    confirm = MagicMock(spec=ChannelOpenConfirmationMessage)
    confirm.msg_type = 91
    confirm.sender_channel = 5
    confirm.initial_window_size = 65536
    confirm.maximum_packet_size = 32768

    with (
        patch.object(t, "_send_message_async", new_callable=AsyncMock),
        patch.object(
            t, "_expect_message_async", new_callable=AsyncMock, return_value=confirm
        ),
    ):
        chan = await t.open_channel("session")

    assert chan is not None
    assert chan._remote_channel_id == 5


@pytest.mark.asyncio
async def test_open_channel_failure_raises():
    from spindlex.protocol.messages import ChannelOpenFailureMessage

    t = _make_transport()

    fail = MagicMock(spec=ChannelOpenFailureMessage)
    fail.msg_type = 92

    with (
        patch.object(t, "_send_message_async", new_callable=AsyncMock),
        patch.object(
            t, "_expect_message_async", new_callable=AsyncMock, return_value=fail
        ),
        pytest.raises(TransportException, match="Failed to open channel"),
    ):
        await t.open_channel("session")


# ── channel send helpers ──────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_channel_request_async():
    t = _make_transport()
    chan = MagicMock()
    chan._remote_channel_id = 7
    t._channels[0] = chan

    with patch.object(t, "_send_message_async", new_callable=AsyncMock) as m:
        await t._send_channel_request_async(0, "exec", True, b"data")
        m.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_channel_request_no_remote_id_raises():
    t = _make_transport()
    chan = MagicMock()
    chan._remote_channel_id = None
    t._channels[0] = chan
    with pytest.raises(TransportException):
        await t._send_channel_request_async(0, "exec", True, b"")


@pytest.mark.asyncio
async def test_send_channel_data_async():
    t = _make_transport()
    chan = MagicMock()
    chan._remote_channel_id = 3
    t._channels[0] = chan
    with patch.object(t, "_send_message_async", new_callable=AsyncMock) as m:
        await t._send_channel_data_async(0, b"hello")
        m.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_channel_eof_async_no_remote_id():
    t = _make_transport()
    chan = MagicMock()
    chan._remote_channel_id = None
    t._channels[0] = chan
    # Should return silently
    await t._send_channel_eof_async(0)


@pytest.mark.asyncio
async def test_send_channel_close_async_no_remote_id():
    t = _make_transport()
    chan = MagicMock()
    chan._remote_channel_id = None
    t._channels[0] = chan
    await t._send_channel_close_async(0)


@pytest.mark.asyncio
async def test_send_channel_window_adjust_async():
    t = _make_transport()
    chan = MagicMock()
    chan._remote_channel_id = 2
    t._channels[0] = chan
    with patch.object(t, "_send_message_async", new_callable=AsyncMock) as m:
        await t._send_channel_window_adjust_async(0, 1024)
        m.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_channel_window_adjust_missing_channel():
    t = _make_transport()
    # Channel 99 doesn't exist — should return silently
    await t._send_channel_window_adjust_async(99, 1024)


# ── _send_global_request_async ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_send_global_request_no_reply():
    t = _make_transport()
    with patch.object(t, "_send_message_async", new_callable=AsyncMock) as m:
        result = await t._send_global_request_async("keepalive", False)
    assert result is None
    m.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_global_request_with_reply():
    from spindlex.protocol.constants import MSG_REQUEST_SUCCESS

    t = _make_transport()
    reply = MagicMock()
    reply.msg_type = MSG_REQUEST_SUCCESS

    with (
        patch.object(t, "_send_message_async", new_callable=AsyncMock),
        patch.object(
            t, "_expect_message_async", new_callable=AsyncMock, return_value=reply
        ),
    ):
        result = await t._send_global_request_async("tcpip-forward", True, b"\x00" * 8)

    assert result is reply


# ── close ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_close_marks_inactive_and_closes_writer():
    t = _make_transport()
    writer = MagicMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    t._writer = writer
    t._active = True
    await t.close()
    assert not t._active
    writer.close.assert_called_once()


@pytest.mark.asyncio
async def test_close_closes_async_channels():
    from spindlex.transport.async_channel import AsyncChannel

    t = _make_transport()
    t._writer = None
    chan = MagicMock(spec=AsyncChannel)
    chan.close = AsyncMock()
    t._channels[0] = chan
    await t.close()
    chan.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_close_closes_sync_channels():
    from spindlex.transport.channel import Channel

    t = _make_transport()
    t._writer = None
    chan = MagicMock(spec=Channel)
    t._channels[0] = chan
    await t.close()
    chan.close.assert_called_once()


# ── _handle_forwarded_tcpip_open ──────────────────────────────────────────────


def test_handle_forwarded_no_manager_sends_failure():
    t = _make_transport()
    t._port_forwarding_manager = None
    t._loop = asyncio.get_event_loop()

    with patch.object(t, "_send_message") as m:
        t._handle_forwarded_tcpip_open(5, 65536, 32768, b"")

    m.assert_called_once()


def test_handle_forwarded_with_manager_schedules():
    t = _make_transport()
    mgr = MagicMock()
    mgr.handle_forwarded_connection_async = AsyncMock(return_value=None)
    t._port_forwarding_manager = mgr

    loop = asyncio.new_event_loop()
    t._loop = loop

    try:
        with patch("asyncio.run_coroutine_threadsafe") as m:
            t._handle_forwarded_tcpip_open(5, 65536, 32768, b"")
            m.assert_called_once()
    finally:
        loop.close()


# ── start_client already active ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_start_client_already_active_raises():
    t = _make_transport()
    t._active = True
    with pytest.raises(TransportException, match="already active"):
        await t.start_client()
