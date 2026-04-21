"""Unit tests for async port forwarding."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from spindlex.exceptions import SSHException
from spindlex.transport.async_forwarding import (
    AsyncForwardingTunnel,
    AsyncLocalPortForwarder,
    AsyncPortForwardingManager,
    AsyncRemotePortForwarder,
)

# ── AsyncForwardingTunnel ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_tunnel_close_cancels_tasks():
    tunnel = AsyncForwardingTunnel("t1", ("127.0.0.1", 1234), ("host", 22), "local")
    task = MagicMock(spec=asyncio.Task)
    task.done.return_value = False
    tunnel.tasks.append(task)
    tunnel.active = True
    await tunnel.close()
    task.cancel.assert_called_once()
    assert not tunnel.active
    assert tunnel.tasks == []


@pytest.mark.asyncio
async def test_tunnel_close_skips_done_tasks():
    tunnel = AsyncForwardingTunnel("t1", ("127.0.0.1", 0), ("h", 22), "local")
    task = MagicMock(spec=asyncio.Task)
    task.done.return_value = True
    tunnel.tasks.append(task)
    await tunnel.close()
    task.cancel.assert_not_called()


# ── AsyncLocalPortForwarder ───────────────────────────────────────────────────


def _make_local_forwarder():
    transport = MagicMock()
    transport._state_lock = asyncio.Lock()
    transport._channels = {}
    transport._next_channel_id = 0
    transport.open_channel = AsyncMock()
    transport._send_message_async = AsyncMock()
    fwd = AsyncLocalPortForwarder(transport)
    return fwd, transport


@pytest.mark.asyncio
async def test_local_forwarder_create_tunnel_success():
    fwd, _ = _make_local_forwarder()
    server = MagicMock()
    server.wait_closed = AsyncMock()

    with patch("asyncio.start_server", new_callable=AsyncMock, return_value=server):
        tid = await fwd.create_tunnel(0, "127.0.0.1", 22)

    assert "local_" in tid
    assert tid in fwd._tunnels
    assert fwd._tunnels[tid].active


@pytest.mark.asyncio
async def test_local_forwarder_duplicate_tunnel_raises():
    fwd, _ = _make_local_forwarder()
    server = MagicMock()
    server.wait_closed = AsyncMock()

    with patch("asyncio.start_server", new_callable=AsyncMock, return_value=server):
        await fwd.create_tunnel(0, "127.0.0.1", 22)
        with pytest.raises(SSHException, match="already exists"):
            await fwd.create_tunnel(0, "127.0.0.1", 22)


@pytest.mark.asyncio
async def test_local_forwarder_create_tunnel_error_wraps():
    fwd, _ = _make_local_forwarder()
    with patch("asyncio.start_server", side_effect=OSError("port in use")):
        with pytest.raises(SSHException, match="Failed to create"):
            await fwd.create_tunnel(9999, "127.0.0.1", 22)


@pytest.mark.asyncio
async def test_local_forwarder_close_tunnel():
    fwd, _ = _make_local_forwarder()
    server = MagicMock()
    server.wait_closed = AsyncMock()
    server.close = MagicMock()

    with patch("asyncio.start_server", new_callable=AsyncMock, return_value=server):
        tid = await fwd.create_tunnel(0, "127.0.0.1", 22)

    await fwd.close_tunnel(tid)
    assert tid not in fwd._tunnels
    server.close.assert_called_once()


@pytest.mark.asyncio
async def test_local_forwarder_close_tunnel_nonexistent():
    fwd, _ = _make_local_forwarder()
    # Should not raise
    await fwd.close_tunnel("nonexistent")


@pytest.mark.asyncio
async def test_local_forwarder_close_all():
    fwd, _ = _make_local_forwarder()
    server = MagicMock()
    server.wait_closed = AsyncMock()
    server.close = MagicMock()

    with patch("asyncio.start_server", new_callable=AsyncMock, return_value=server):
        await fwd.create_tunnel(0, "127.0.0.1", 22)
        await fwd.create_tunnel(0, "127.0.0.1", 2222, local_host="0.0.0.0")

    await fwd.close_all()
    assert fwd._tunnels == {}


@pytest.mark.asyncio
async def test_relay_stream_to_channel():
    fwd, _ = _make_local_forwarder()
    reader = MagicMock(spec=asyncio.StreamReader)
    reader.read = AsyncMock(side_effect=[b"data", b""])
    channel = MagicMock()
    channel.send = AsyncMock()
    channel.close = AsyncMock()

    await fwd._relay_stream_to_channel(reader, channel)

    channel.send.assert_awaited_once_with(b"data")
    channel.close.assert_awaited_once()


@pytest.mark.asyncio
async def test_relay_channel_to_stream():
    fwd, _ = _make_local_forwarder()
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    channel = MagicMock()
    channel.recv = AsyncMock(side_effect=[b"hello", b""])

    await fwd._relay_channel_to_stream(channel, writer)

    writer.write.assert_called_once_with(b"hello")
    writer.close.assert_called_once()


@pytest.mark.asyncio
async def test_handle_client_inactive_tunnel_closes_writer():
    fwd, _ = _make_local_forwarder()
    tunnel = AsyncForwardingTunnel("t", ("127.0.0.1", 0), ("h", 22), "local")
    tunnel.active = False

    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    await fwd._handle_client(tunnel, reader, writer)
    writer.close.assert_called_once()


# ── AsyncRemotePortForwarder ──────────────────────────────────────────────────


def _make_remote_forwarder():
    transport = MagicMock()
    transport._state_lock = asyncio.Lock()
    transport._channels = {}
    transport._next_channel_id = 0
    transport._send_message_async = AsyncMock()
    transport._send_global_request_async = AsyncMock()
    fwd = AsyncRemotePortForwarder(transport)
    return fwd, transport


@pytest.mark.asyncio
async def test_remote_forwarder_create_tunnel_success():
    fwd, t = _make_remote_forwarder()
    from spindlex.protocol.constants import MSG_REQUEST_SUCCESS

    reply = MagicMock()
    reply.msg_type = MSG_REQUEST_SUCCESS
    t._send_global_request_async.return_value = reply

    tid = await fwd.create_tunnel(8080, "127.0.0.1", 8080)
    assert "remote_" in tid
    assert tid in fwd._tunnels


@pytest.mark.asyncio
async def test_remote_forwarder_create_tunnel_denied_raises():
    fwd, t = _make_remote_forwarder()
    t._send_global_request_async.return_value = None

    with pytest.raises(SSHException, match="denied"):
        await fwd.create_tunnel(8080, "127.0.0.1", 8080)


@pytest.mark.asyncio
async def test_remote_forwarder_duplicate_raises():
    fwd, t = _make_remote_forwarder()
    from spindlex.protocol.constants import MSG_REQUEST_SUCCESS

    reply = MagicMock()
    reply.msg_type = MSG_REQUEST_SUCCESS
    t._send_global_request_async.return_value = reply

    await fwd.create_tunnel(8080, "127.0.0.1", 8080)
    with pytest.raises(SSHException, match="already exists"):
        await fwd.create_tunnel(8080, "127.0.0.1", 8080)


@pytest.mark.asyncio
async def test_remote_forwarder_close_tunnel():
    fwd, t = _make_remote_forwarder()
    from spindlex.protocol.constants import MSG_REQUEST_SUCCESS

    reply = MagicMock()
    reply.msg_type = MSG_REQUEST_SUCCESS
    t._send_global_request_async.return_value = reply

    tid = await fwd.create_tunnel(8080, "127.0.0.1", 8080)
    await fwd.close_tunnel(tid)
    assert tid not in fwd._tunnels


@pytest.mark.asyncio
async def test_remote_forwarder_close_all():
    fwd, t = _make_remote_forwarder()
    from spindlex.protocol.constants import MSG_REQUEST_SUCCESS

    reply = MagicMock()
    reply.msg_type = MSG_REQUEST_SUCCESS
    t._send_global_request_async.return_value = reply

    await fwd.create_tunnel(8080, "127.0.0.1", 8080)
    await fwd.create_tunnel(9090, "127.0.0.1", 9090, remote_host="")
    await fwd.close_all()
    assert fwd._tunnels == {}


@pytest.mark.asyncio
async def test_handle_forwarded_connection_no_tunnel():
    from spindlex.protocol.utils import write_string, write_uint32

    fwd, t = _make_remote_forwarder()

    data = bytearray()
    data.extend(write_string("127.0.0.1"))
    data.extend(write_uint32(9999))  # port that has no tunnel

    # Should log error and attempt to send failure without crashing
    t._send_message_async.return_value = None
    await fwd.handle_forwarded_connection_async(1, 65536, 32768, bytes(data))
    # Failure message attempted
    t._send_message_async.assert_awaited()


# ── AsyncPortForwardingManager ────────────────────────────────────────────────


def _make_manager():
    transport = MagicMock()
    transport._state_lock = asyncio.Lock()
    transport._channels = {}
    transport._next_channel_id = 0
    transport._send_global_request_async = AsyncMock()
    transport._send_message_async = AsyncMock()
    return AsyncPortForwardingManager(transport), transport


@pytest.mark.asyncio
async def test_manager_create_local_tunnel():
    mgr, _ = _make_manager()
    server = MagicMock()
    server.wait_closed = AsyncMock()
    server.close = MagicMock()

    with patch("asyncio.start_server", new_callable=AsyncMock, return_value=server):
        tid = await mgr.create_local_tunnel(0, "127.0.0.1", 22)

    assert tid.startswith("local_")


@pytest.mark.asyncio
async def test_manager_create_remote_tunnel():
    from spindlex.protocol.constants import MSG_REQUEST_SUCCESS

    mgr, t = _make_manager()
    reply = MagicMock()
    reply.msg_type = MSG_REQUEST_SUCCESS
    t._send_global_request_async.return_value = reply

    tid = await mgr.create_remote_tunnel(8080, "127.0.0.1", 8080)
    assert tid.startswith("remote_")


@pytest.mark.asyncio
async def test_manager_close_local_tunnel():
    mgr, _ = _make_manager()
    server = MagicMock()
    server.wait_closed = AsyncMock()
    server.close = MagicMock()

    with patch("asyncio.start_server", new_callable=AsyncMock, return_value=server):
        tid = await mgr.create_local_tunnel(0, "127.0.0.1", 22)

    await mgr.close_tunnel(tid)
    assert tid not in mgr.local_forwarder._tunnels


@pytest.mark.asyncio
async def test_manager_close_remote_tunnel():
    from spindlex.protocol.constants import MSG_REQUEST_SUCCESS

    mgr, t = _make_manager()
    reply = MagicMock()
    reply.msg_type = MSG_REQUEST_SUCCESS
    t._send_global_request_async.return_value = reply

    tid = await mgr.create_remote_tunnel(8080, "127.0.0.1", 8080)
    await mgr.close_tunnel(tid)
    assert tid not in mgr.remote_forwarder._tunnels


@pytest.mark.asyncio
async def test_manager_close_all_tunnels():
    from spindlex.protocol.constants import MSG_REQUEST_SUCCESS

    mgr, t = _make_manager()
    reply = MagicMock()
    reply.msg_type = MSG_REQUEST_SUCCESS
    t._send_global_request_async.return_value = reply

    server = MagicMock()
    server.wait_closed = AsyncMock()
    server.close = MagicMock()

    with patch("asyncio.start_server", new_callable=AsyncMock, return_value=server):
        await mgr.create_local_tunnel(0, "127.0.0.1", 22)

    await mgr.create_remote_tunnel(8080, "127.0.0.1", 8080)
    await mgr.close_all_tunnels()
    assert mgr.get_all_tunnels() == {}


def test_manager_get_all_tunnels_empty():
    mgr, _ = _make_manager()
    assert mgr.get_all_tunnels() == {}
