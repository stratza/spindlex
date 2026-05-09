"""Unit tests for spindlex/transport/async_forwarding.py to boost coverage."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spindlex.exceptions import SSHException
from spindlex.protocol.constants import MSG_REQUEST_SUCCESS
from spindlex.transport.async_forwarding import (
    AsyncForwardingTunnel,
    AsyncLocalPortForwarder,
    AsyncPortForwardingManager,
    AsyncRemotePortForwarder,
)


@pytest.fixture
def mock_transport():
    t = MagicMock()
    t.open_channel = AsyncMock()
    t._send_global_request_async = AsyncMock()
    t._send_message_async = AsyncMock()
    t._state_lock = AsyncMock()
    t._state_lock.__aenter__ = AsyncMock()
    t._state_lock.__aexit__ = AsyncMock()
    t._channels = {}
    t._next_channel_id = 0
    return t


# ---- AsyncForwardingTunnel ----


class TestAsyncForwardingTunnel:
    @pytest.mark.asyncio
    async def test_init_and_close(self):
        tunnel = AsyncForwardingTunnel(
            "t1", ("127.0.0.1", 8080), ("remote", 80), "local"
        )
        tunnel.active = True

        mock_task = MagicMock(spec=asyncio.Task)
        mock_task.done.return_value = False
        tunnel.tasks.append(mock_task)

        await tunnel.close()
        assert tunnel.active is False
        mock_task.cancel.assert_called_once()
        assert len(tunnel.tasks) == 0


# ---- AsyncLocalPortForwarder ----


class TestAsyncLocalPortForwarder:
    @pytest.mark.asyncio
    async def test_create_tunnel_invalid_port(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        with pytest.raises(SSHException, match="Invalid local port"):
            await lpf.create_tunnel(-1, "remote", 80)

    @pytest.mark.asyncio
    async def test_create_tunnel_duplicate(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        lpf._tunnels["local_127.0.0.1_8080_remote_80"] = MagicMock()
        with pytest.raises(SSHException, match="already exists"):
            await lpf.create_tunnel(8080, "remote", 80)

    @pytest.mark.asyncio
    async def test_create_tunnel_start_server_fails(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        with patch("asyncio.start_server", side_effect=OSError("fail")):
            with pytest.raises(
                SSHException, match="Failed to create local port forwarding"
            ):
                await lpf.create_tunnel(8080, "remote", 80)

    @pytest.mark.asyncio
    async def test_create_tunnel_success(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        mock_server = MagicMock()
        with patch("asyncio.start_server", new=AsyncMock(return_value=mock_server)):
            tid = await lpf.create_tunnel(8080, "remote", 80)
        assert tid in lpf._tunnels
        assert tid in lpf._servers

    @pytest.mark.asyncio
    async def test_handle_client_inactive(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        tunnel = AsyncForwardingTunnel(
            "t1", ("127.0.0.1", 8080), ("remote", 80), "local"
        )
        writer = MagicMock()
        writer.wait_closed = AsyncMock()
        await lpf._handle_client(tunnel, MagicMock(), writer)
        writer.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_tunnel(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        tunnel = AsyncForwardingTunnel(
            "t1", ("127.0.0.1", 8080), ("remote", 80), "local"
        )
        tunnel.close = AsyncMock()
        lpf._tunnels["t1"] = tunnel
        mock_server = MagicMock()
        mock_server.wait_closed = AsyncMock()
        lpf._servers["t1"] = mock_server

        await lpf.close_tunnel("t1")
        assert "t1" not in lpf._tunnels
        tunnel.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_relay_stream_to_channel(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        reader = MagicMock()
        reader.read = AsyncMock(side_effect=[b"data", b""])
        channel = MagicMock()
        channel.send = AsyncMock()
        channel.close = AsyncMock()

        await lpf._relay_stream_to_channel(reader, channel)
        channel.send.assert_awaited_once_with(b"data")
        channel.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_relay_channel_to_stream(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        channel = MagicMock()
        channel.recv = AsyncMock(side_effect=[b"data", b""])
        writer = MagicMock()
        writer.drain = AsyncMock()

        await lpf._relay_channel_to_stream(channel, writer)
        writer.write.assert_called_once_with(b"data")
        writer.drain.assert_awaited_once()


# ---- AsyncRemotePortForwarder ----


class TestAsyncRemotePortForwarder:
    @pytest.mark.asyncio
    async def test_create_tunnel_invalid_remote_port(self, mock_transport):
        rpf = AsyncRemotePortForwarder(mock_transport)
        with pytest.raises(SSHException, match="Invalid remote port"):
            await rpf.create_tunnel(-1, "local", 80)

    @pytest.mark.asyncio
    async def test_create_tunnel_invalid_local_port(self, mock_transport):
        rpf = AsyncRemotePortForwarder(mock_transport)
        with pytest.raises(SSHException, match="Invalid local port"):
            await rpf.create_tunnel(8080, "local", -1)

    @pytest.mark.asyncio
    async def test_create_tunnel_duplicate(self, mock_transport):
        rpf = AsyncRemotePortForwarder(mock_transport)
        rpf._tunnels["remote__8080_local_80"] = MagicMock()
        with pytest.raises(SSHException, match="already exists"):
            await rpf.create_tunnel(8080, "local", 80)

    @pytest.mark.asyncio
    async def test_create_tunnel_denied(self, mock_transport):
        rpf = AsyncRemotePortForwarder(mock_transport)
        mock_transport._send_global_request_async.return_value = None
        with pytest.raises(SSHException, match="denied"):
            await rpf.create_tunnel(8080, "local", 80)

    @pytest.mark.asyncio
    async def test_create_tunnel_success(self, mock_transport):
        rpf = AsyncRemotePortForwarder(mock_transport)
        res = MagicMock()
        res.msg_type = MSG_REQUEST_SUCCESS
        mock_transport._send_global_request_async.return_value = res

        tid = await rpf.create_tunnel(8080, "local", 80)
        assert tid in rpf._tunnels

    @pytest.mark.asyncio
    async def test_close_tunnel(self, mock_transport):
        rpf = AsyncRemotePortForwarder(mock_transport)
        tunnel = AsyncForwardingTunnel("t1", ("local", 80), ("remote", 8080), "remote")
        tunnel.close = AsyncMock()
        rpf._tunnels["t1"] = tunnel

        await rpf.close_tunnel("t1")
        assert "t1" not in rpf._tunnels
        mock_transport._send_global_request_async.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_relay_stream_to_channel_with_writer(self, mock_transport):
        rpf = AsyncRemotePortForwarder(mock_transport)
        reader = MagicMock()
        reader.read = AsyncMock(side_effect=[b"data", b""])
        channel = MagicMock()
        channel.send = AsyncMock()
        channel.close = AsyncMock()
        writer = MagicMock()

        await rpf._relay_stream_to_channel(reader, channel, writer)
        channel.send.assert_awaited_once_with(b"data")
        writer.close.assert_called_once()


# ---- AsyncPortForwardingManager ----


class TestAsyncPortForwardingManager:
    @pytest.mark.asyncio
    async def test_close_tunnel_local(self, mock_transport):
        mgr = AsyncPortForwardingManager(mock_transport)
        mgr.local_forwarder.close_tunnel = AsyncMock()
        await mgr.close_tunnel("local_123")
        mgr.local_forwarder.close_tunnel.assert_awaited_once_with("local_123")

    @pytest.mark.asyncio
    async def test_close_tunnel_remote(self, mock_transport):
        mgr = AsyncPortForwardingManager(mock_transport)
        mgr.remote_forwarder.close_tunnel = AsyncMock()
        await mgr.close_tunnel("remote_123")
        mgr.remote_forwarder.close_tunnel.assert_awaited_once_with("remote_123")

    @pytest.mark.asyncio
    async def test_get_all_tunnels(self, mock_transport):
        mgr = AsyncPortForwardingManager(mock_transport)
        mgr.local_forwarder._tunnels["t1"] = MagicMock()
        mgr.remote_forwarder._tunnels["t2"] = MagicMock()
        tunnels = mgr.get_all_tunnels()
        assert "t1" in tunnels
        assert "t2" in tunnels
