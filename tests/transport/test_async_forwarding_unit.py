"""
Unit tests for spindlex/transport/async_forwarding.py

All tests are mock-based — no real SSH server connections are made.
pytest-asyncio is configured with asyncio_mode = "auto" in pyproject.toml,
so individual async tests do NOT need @pytest.mark.asyncio.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spindlex.exceptions import SSHException
from spindlex.protocol.constants import (
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_WINDOW_SIZE,
    MSG_REQUEST_SUCCESS,
)
from spindlex.transport.async_forwarding import (
    AsyncForwardingTunnel,
    AsyncLocalPortForwarder,
    AsyncPortForwardingManager,
    AsyncRemotePortForwarder,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_transport() -> MagicMock:
    transport = MagicMock()
    transport._send_global_request_async = AsyncMock()
    transport._send_message_async = AsyncMock()
    transport._state_lock = asyncio.Lock()
    transport._next_channel_id = 10
    transport._channels = {}
    transport.open_channel = AsyncMock()
    return transport


def make_mock_server() -> MagicMock:
    server = MagicMock()
    server.wait_closed = AsyncMock()
    return server


def make_mock_channel() -> MagicMock:
    channel = MagicMock()
    channel.send = AsyncMock()
    channel.recv = AsyncMock(return_value=b"")
    channel.close = AsyncMock()
    return channel


def make_mock_reader_writer(data: bytes = b"") -> tuple[MagicMock, MagicMock]:
    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    reader.read = AsyncMock(side_effect=[data, b""])  # data then EOF
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()
    return reader, writer


# ---------------------------------------------------------------------------
# AsyncForwardingTunnel
# ---------------------------------------------------------------------------


def test_forwarding_tunnel_init_attributes():
    tunnel = AsyncForwardingTunnel(
        tunnel_id="t1",
        local_addr=("127.0.0.1", 8080),
        remote_addr=("example.com", 80),
        tunnel_type="local",
    )
    assert tunnel.tunnel_id == "t1"
    assert tunnel.local_addr == ("127.0.0.1", 8080)
    assert tunnel.remote_addr == ("example.com", 80)
    assert tunnel.tunnel_type == "local"
    assert tunnel.active is False
    assert tunnel.tasks == []


async def test_forwarding_tunnel_close_sets_inactive():
    tunnel = AsyncForwardingTunnel("t1", ("127.0.0.1", 8080), ("h", 22), "local")
    tunnel.active = True
    await tunnel.close()
    assert tunnel.active is False


async def test_forwarding_tunnel_close_cancels_tasks():
    tunnel = AsyncForwardingTunnel("t1", ("127.0.0.1", 8080), ("h", 22), "local")
    tunnel.active = True

    async def long_running():
        await asyncio.sleep(999)

    task = asyncio.create_task(long_running())
    tunnel.tasks.append(task)

    await tunnel.close()
    # Give the event loop a chance to process the cancellation
    await asyncio.sleep(0)
    assert task.cancelled() or task.done()


async def test_forwarding_tunnel_close_clears_task_list():
    tunnel = AsyncForwardingTunnel("t1", ("127.0.0.1", 8080), ("h", 22), "local")
    mock_task = MagicMock()
    mock_task.done.return_value = True
    tunnel.tasks.append(mock_task)
    await tunnel.close()
    assert tunnel.tasks == []


async def test_forwarding_tunnel_close_skips_done_tasks():
    """Tasks that are already done should not have cancel() called."""
    tunnel = AsyncForwardingTunnel("t1", ("127.0.0.1", 8080), ("h", 22), "local")
    done_task = MagicMock()
    done_task.done.return_value = True
    tunnel.tasks.append(done_task)
    await tunnel.close()
    done_task.cancel.assert_not_called()


# ---------------------------------------------------------------------------
# AsyncLocalPortForwarder — create_tunnel
# ---------------------------------------------------------------------------


async def test_local_create_tunnel_invalid_port_low():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)
    with pytest.raises(SSHException, match="Invalid local port"):
        await fwd.create_tunnel(-1, "remote.host", 80)


async def test_local_create_tunnel_invalid_port_high():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)
    with pytest.raises(SSHException, match="Invalid local port"):
        await fwd.create_tunnel(99999, "remote.host", 80)


async def test_local_create_tunnel_duplicate_raises():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        await fwd.create_tunnel(8080, "remote.host", 80)

        with pytest.raises(SSHException, match="Tunnel already exists"):
            await fwd.create_tunnel(8080, "remote.host", 80)


async def test_local_create_tunnel_success_returns_tunnel_id():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        tid = await fwd.create_tunnel(8080, "remote.host", 80)

    assert tid == "local_127.0.0.1_8080_remote.host_80"
    assert tid in fwd._tunnels
    assert fwd._tunnels[tid].active is True


async def test_local_create_tunnel_stores_server():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        tid = await fwd.create_tunnel(8080, "remote.host", 80)

    assert fwd._servers[tid] is mock_server


async def test_local_create_tunnel_custom_local_host():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        tid = await fwd.create_tunnel(9000, "remote.host", 443, local_host="0.0.0.0")

    assert "0.0.0.0" in tid


# ---------------------------------------------------------------------------
# AsyncLocalPortForwarder — _handle_client
# ---------------------------------------------------------------------------


async def test_handle_client_inactive_tunnel_closes_writer():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    tunnel = AsyncForwardingTunnel("t1", ("127.0.0.1", 8080), ("h", 22), "local")
    tunnel.active = False

    reader, writer = make_mock_reader_writer()
    await fwd._handle_client(tunnel, reader, writer)

    writer.close.assert_called()
    writer.wait_closed.assert_called()


async def test_handle_client_active_opens_channel():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    channel = make_mock_channel()
    channel.recv = AsyncMock(return_value=b"")
    transport.open_channel = AsyncMock(return_value=channel)

    tunnel = AsyncForwardingTunnel(
        "t1", ("127.0.0.1", 8080), ("remote.host", 80), "local"
    )
    tunnel.active = True

    reader, writer = make_mock_reader_writer(b"")
    await fwd._handle_client(tunnel, reader, writer)

    transport.open_channel.assert_called_once()


# ---------------------------------------------------------------------------
# AsyncLocalPortForwarder — _relay_stream_to_channel
# ---------------------------------------------------------------------------


async def test_relay_stream_to_channel_sends_data():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    channel = make_mock_channel()
    reader = MagicMock(spec=asyncio.StreamReader)
    reader.read = AsyncMock(side_effect=[b"chunk", b""])

    await fwd._relay_stream_to_channel(reader, channel)

    channel.send.assert_called_once_with(b"chunk")
    channel.close.assert_called()


async def test_relay_stream_to_channel_closes_on_empty():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    channel = make_mock_channel()
    reader = MagicMock(spec=asyncio.StreamReader)
    reader.read = AsyncMock(return_value=b"")

    await fwd._relay_stream_to_channel(reader, channel)
    channel.send.assert_not_called()
    channel.close.assert_called()


# ---------------------------------------------------------------------------
# AsyncLocalPortForwarder — _relay_channel_to_stream
# ---------------------------------------------------------------------------


async def test_relay_channel_to_stream_writes_data():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    channel = make_mock_channel()
    channel.recv = AsyncMock(side_effect=[b"response", b""])

    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.drain = AsyncMock()
    writer.close = MagicMock()

    await fwd._relay_channel_to_stream(channel, writer)

    writer.write.assert_called_once_with(b"response")
    writer.close.assert_called()


async def test_relay_channel_to_stream_closes_writer_on_empty():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    channel = make_mock_channel()
    channel.recv = AsyncMock(return_value=b"")

    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.drain = AsyncMock()
    writer.close = MagicMock()

    await fwd._relay_channel_to_stream(channel, writer)
    writer.close.assert_called()


# ---------------------------------------------------------------------------
# AsyncLocalPortForwarder — close_tunnel / close_all
# ---------------------------------------------------------------------------


async def test_local_close_tunnel_removes_entry():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        tid = await fwd.create_tunnel(8080, "remote.host", 80)

    await fwd.close_tunnel(tid)
    assert tid not in fwd._tunnels
    assert tid not in fwd._servers


async def test_local_close_tunnel_calls_server_close():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        tid = await fwd.create_tunnel(8080, "remote.host", 80)

    await fwd.close_tunnel(tid)
    mock_server.close.assert_called()
    mock_server.wait_closed.assert_called()


async def test_local_close_tunnel_nonexistent_is_noop():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)
    # Should not raise
    await fwd.close_tunnel("nonexistent_tunnel")


async def test_local_close_all_closes_all_tunnels():
    transport = make_transport()
    fwd = AsyncLocalPortForwarder(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        await fwd.create_tunnel(8080, "remote.host", 80)
        await fwd.create_tunnel(8081, "remote.host", 81)

    await fwd.close_all()
    assert len(fwd._tunnels) == 0


# ---------------------------------------------------------------------------
# AsyncRemotePortForwarder — create_tunnel
# ---------------------------------------------------------------------------


async def test_remote_create_tunnel_invalid_remote_port():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)
    with pytest.raises(SSHException, match="Invalid remote port"):
        await fwd.create_tunnel(-1, "localhost", 8080)


async def test_remote_create_tunnel_invalid_local_port():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)
    with pytest.raises(SSHException, match="Invalid local port"):
        await fwd.create_tunnel(2222, "localhost", 99999)


async def test_remote_create_tunnel_duplicate_raises():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    await fwd.create_tunnel(2222, "localhost", 8080)
    with pytest.raises(SSHException, match="Tunnel already exists"):
        await fwd.create_tunnel(2222, "localhost", 8080)


async def test_remote_create_tunnel_server_denies_raises():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    transport._send_global_request_async.return_value = None

    with pytest.raises(SSHException, match="denied"):
        await fwd.create_tunnel(2222, "localhost", 8080)


async def test_remote_create_tunnel_success():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    tid = await fwd.create_tunnel(2222, "localhost", 8080)
    assert tid in fwd._tunnels
    assert fwd._tunnels[tid].active is True


async def test_remote_create_tunnel_sends_global_request():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    await fwd.create_tunnel(2222, "localhost", 8080, remote_host="")
    transport._send_global_request_async.assert_called_once()
    args = transport._send_global_request_async.call_args[0]
    assert args[0] == "tcpip-forward"
    assert args[1] is True


# ---------------------------------------------------------------------------
# AsyncRemotePortForwarder — close_tunnel / close_all
# ---------------------------------------------------------------------------


async def test_remote_close_tunnel_sends_cancel_request():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    tid = await fwd.create_tunnel(2222, "localhost", 8080)

    # reset mock so we can assert cancel call
    transport._send_global_request_async.reset_mock()
    await fwd.close_tunnel(tid)

    transport._send_global_request_async.assert_called_once()
    cancel_args = transport._send_global_request_async.call_args[0]
    assert cancel_args[0] == "cancel-tcpip-forward"


async def test_remote_close_tunnel_removes_entry():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    tid = await fwd.create_tunnel(2222, "localhost", 8080)
    await fwd.close_tunnel(tid)
    assert tid not in fwd._tunnels


async def test_remote_close_all():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    await fwd.create_tunnel(2222, "localhost", 8080)
    await fwd.create_tunnel(2223, "localhost", 8081)

    await fwd.close_all()
    assert len(fwd._tunnels) == 0


# ---------------------------------------------------------------------------
# AsyncRemotePortForwarder — _relay methods (shared impl but needs coverage)
# ---------------------------------------------------------------------------


async def test_remote_relay_stream_to_channel_sends_data():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    channel = make_mock_channel()
    reader = MagicMock(spec=asyncio.StreamReader)
    reader.read = AsyncMock(side_effect=[b"payload", b""])

    await fwd._relay_stream_to_channel(reader, channel)
    channel.send.assert_called_once_with(b"payload")


async def test_remote_relay_channel_to_stream_writes_data():
    transport = make_transport()
    fwd = AsyncRemotePortForwarder(transport)

    channel = make_mock_channel()
    channel.recv = AsyncMock(side_effect=[b"response", b""])

    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.drain = AsyncMock()
    writer.close = MagicMock()

    await fwd._relay_channel_to_stream(channel, writer)
    writer.write.assert_called_once_with(b"response")


# ---------------------------------------------------------------------------
# AsyncPortForwardingManager
# ---------------------------------------------------------------------------


def test_manager_init_creates_forwarders():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)
    assert isinstance(mgr.local_forwarder, AsyncLocalPortForwarder)
    assert isinstance(mgr.remote_forwarder, AsyncRemotePortForwarder)
    assert mgr._transport is transport


async def test_manager_create_local_tunnel_delegates():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        tid = await mgr.create_local_tunnel(8080, "remote.host", 80)

    assert tid in mgr.local_forwarder._tunnels


async def test_manager_create_remote_tunnel_delegates():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    tid = await mgr.create_remote_tunnel(2222, "localhost", 8080)
    assert tid in mgr.remote_forwarder._tunnels


async def test_manager_close_local_tunnel():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        tid = await mgr.create_local_tunnel(8080, "remote.host", 80)

    await mgr.close_tunnel(tid)
    assert tid not in mgr.local_forwarder._tunnels


async def test_manager_close_remote_tunnel():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    tid = await mgr.create_remote_tunnel(2222, "localhost", 8080)
    transport._send_global_request_async.reset_mock()
    await mgr.close_tunnel(tid)
    assert tid not in mgr.remote_forwarder._tunnels


async def test_manager_get_all_tunnels_combines_both():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        local_tid = await mgr.create_local_tunnel(8080, "remote.host", 80)

    remote_tid = await mgr.create_remote_tunnel(2222, "localhost", 8080)

    all_tunnels = mgr.get_all_tunnels()
    assert local_tid in all_tunnels
    assert remote_tid in all_tunnels


async def test_manager_close_all_tunnels():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)

    success_msg = MagicMock()
    success_msg.msg_type = MSG_REQUEST_SUCCESS
    transport._send_global_request_async.return_value = success_msg

    mock_server = make_mock_server()
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start:
        mock_start.return_value = mock_server
        await mgr.create_local_tunnel(8080, "remote.host", 80)

    await mgr.create_remote_tunnel(2222, "localhost", 8080)

    transport._send_global_request_async.reset_mock()
    await mgr.close_all_tunnels()

    assert len(mgr.local_forwarder._tunnels) == 0
    assert len(mgr.remote_forwarder._tunnels) == 0


async def test_manager_handle_forwarded_connection_async_delegates():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)

    mgr.remote_forwarder.handle_forwarded_connection_async = AsyncMock()

    await mgr.handle_forwarded_connection_async(
        sender_channel=5,
        initial_window_size=DEFAULT_WINDOW_SIZE,
        maximum_packet_size=DEFAULT_MAX_PACKET_SIZE,
        type_specific_data=b"\x00\x00\x00\x04host\x00\x00\x00\x50",
    )

    mgr.remote_forwarder.handle_forwarded_connection_async.assert_called_once_with(
        5,
        DEFAULT_WINDOW_SIZE,
        DEFAULT_MAX_PACKET_SIZE,
        b"\x00\x00\x00\x04host\x00\x00\x00\x50",
    )


async def test_manager_close_tunnel_unknown_prefix_is_noop():
    transport = make_transport()
    mgr = AsyncPortForwardingManager(transport)
    # Should not raise for unrecognised prefix
    await mgr.close_tunnel("unknown_tunnel_id")
