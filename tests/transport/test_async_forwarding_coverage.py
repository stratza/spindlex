"""
Additional coverage tests for spindlex/transport/async_forwarding.py.

Targets missed lines:
- AsyncLocalPortForwarder._handle_client (active path, exception path)
- AsyncLocalPortForwarder._relay_stream_to_channel (exception in channel.close)
- AsyncLocalPortForwarder._relay_channel_to_stream (exception path)
- AsyncLocalPortForwarder.close_all
- AsyncRemotePortForwarder.handle_forwarded_connection_async (full path)
- AsyncRemotePortForwarder._relay_stream_to_channel (exception, writer=None path)
- AsyncRemotePortForwarder._relay_channel_to_stream (exception path)
- AsyncRemotePortForwarder.close_all
- AsyncPortForwardingManager.create_local_tunnel
- AsyncPortForwardingManager.create_remote_tunnel
- AsyncPortForwardingManager.handle_forwarded_connection_async
- AsyncPortForwardingManager.close_all_tunnels
"""

from __future__ import annotations

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
    t._state_lock.__aenter__ = AsyncMock(return_value=None)
    t._state_lock.__aexit__ = AsyncMock(return_value=None)
    t._channels = {}
    t._next_channel_id = 0
    return t


# ---------------------------------------------------------------------------
# AsyncLocalPortForwarder._handle_client — active tunnel path
# ---------------------------------------------------------------------------


class TestAsyncLocalHandleClientActivePath:
    async def test_handle_client_active_tunnel(self, mock_transport):
        """_handle_client when tunnel is active — opens channel and relays."""
        lpf = AsyncLocalPortForwarder(mock_transport)
        tunnel = AsyncForwardingTunnel(
            "t1", ("127.0.0.1", 8080), ("remote", 80), "local"
        )
        tunnel.active = True

        channel = MagicMock()
        channel.send = AsyncMock()
        channel.recv = AsyncMock(return_value=b"")
        channel.close = AsyncMock()
        mock_transport.open_channel.return_value = channel

        reader = MagicMock()
        reader.read = AsyncMock(return_value=b"")  # EOF immediately
        writer = MagicMock()
        writer.drain = AsyncMock()
        writer.wait_closed = AsyncMock()

        await lpf._handle_client(tunnel, reader, writer)
        mock_transport.open_channel.assert_awaited_once()
        writer.close.assert_called()

    async def test_handle_client_exception_in_open_channel(self, mock_transport):
        """_handle_client logs error if open_channel fails."""
        lpf = AsyncLocalPortForwarder(mock_transport)
        tunnel = AsyncForwardingTunnel(
            "t1", ("127.0.0.1", 8080), ("remote", 80), "local"
        )
        tunnel.active = True

        mock_transport.open_channel.side_effect = SSHException("conn fail")
        reader = MagicMock()
        writer = MagicMock()
        writer.wait_closed = AsyncMock()

        # Should not raise, just log
        await lpf._handle_client(tunnel, reader, writer)
        writer.close.assert_called()

    async def test_handle_client_wait_closed_raises(self, mock_transport):
        """_handle_client handles wait_closed raising an exception."""
        lpf = AsyncLocalPortForwarder(mock_transport)
        tunnel = AsyncForwardingTunnel(
            "t1", ("127.0.0.1", 8080), ("remote", 80), "local"
        )
        tunnel.active = True

        mock_transport.open_channel.side_effect = SSHException("fail")
        reader = MagicMock()
        writer = MagicMock()
        writer.wait_closed = AsyncMock(side_effect=OSError("already closed"))

        # Should not raise
        await lpf._handle_client(tunnel, reader, writer)


# ---------------------------------------------------------------------------
# AsyncLocalPortForwarder relay methods — exception paths
# ---------------------------------------------------------------------------


class TestAsyncLocalRelayExceptionPaths:
    async def test_relay_stream_to_channel_exception_in_read(self, mock_transport):
        """Exception in reader.read is caught and channel.close is called."""
        lpf = AsyncLocalPortForwarder(mock_transport)
        reader = MagicMock()
        reader.read = AsyncMock(side_effect=ConnectionResetError("reset"))
        channel = MagicMock()
        channel.close = AsyncMock()

        await lpf._relay_stream_to_channel(reader, channel)
        channel.close.assert_awaited_once()

    async def test_relay_stream_to_channel_close_raises(self, mock_transport):
        """Exception in channel.close during finally is caught."""
        lpf = AsyncLocalPortForwarder(mock_transport)
        reader = MagicMock()
        reader.read = AsyncMock(return_value=b"")  # EOF
        channel = MagicMock()
        channel.close = AsyncMock(side_effect=RuntimeError("close fail"))

        # Should not propagate
        await lpf._relay_stream_to_channel(reader, channel)

    async def test_relay_channel_to_stream_exception(self, mock_transport):
        """Exception in channel.recv is caught."""
        lpf = AsyncLocalPortForwarder(mock_transport)
        channel = MagicMock()
        channel.recv = AsyncMock(side_effect=ConnectionResetError("reset"))
        writer = MagicMock()

        await lpf._relay_channel_to_stream(channel, writer)
        writer.close.assert_called()


# ---------------------------------------------------------------------------
# AsyncLocalPortForwarder.close_all
# ---------------------------------------------------------------------------


class TestAsyncLocalCloseAll:
    async def test_close_all(self, mock_transport):
        lpf = AsyncLocalPortForwarder(mock_transport)
        t1 = AsyncForwardingTunnel("t1", ("h", 1), ("r", 2), "local")
        t2 = AsyncForwardingTunnel("t2", ("h", 3), ("r", 4), "local")
        t1.close = AsyncMock()
        t2.close = AsyncMock()
        lpf._tunnels["t1"] = t1
        lpf._tunnels["t2"] = t2
        mock_s1 = MagicMock()
        mock_s1.wait_closed = AsyncMock()
        mock_s2 = MagicMock()
        mock_s2.wait_closed = AsyncMock()
        lpf._servers["t1"] = mock_s1
        lpf._servers["t2"] = mock_s2

        await lpf.close_all()
        assert len(lpf._tunnels) == 0


# ---------------------------------------------------------------------------
# AsyncRemotePortForwarder.handle_forwarded_connection_async
# ---------------------------------------------------------------------------


class TestAsyncRemoteHandleForwardedConnection:
    def _make_type_specific_data(self, host: str, port: int) -> bytes:
        from spindlex.protocol.utils import write_string, write_uint32

        return write_string(host) + write_uint32(port)

    async def test_handle_no_matching_tunnel(self, mock_transport):
        """When no tunnel matches the port, exception is caught and failure sent."""
        rpf = AsyncRemotePortForwarder(mock_transport)
        data = self._make_type_specific_data("0.0.0.0", 9999)

        # Should not raise - exception is caught internally
        await rpf.handle_forwarded_connection_async(1, 32768, 32768, data)
        # Failure message should have been sent
        mock_transport._send_message_async.assert_awaited()

    async def test_handle_inactive_tunnel(self, mock_transport):
        """When tunnel exists but is inactive, exception is caught."""
        rpf = AsyncRemotePortForwarder(mock_transport)
        tunnel = AsyncForwardingTunnel(
            "remote__8080_local_80", ("local", 80), ("", 8080), "remote"
        )
        tunnel.active = False
        rpf._tunnels["remote__8080_local_80"] = tunnel

        data = self._make_type_specific_data("0.0.0.0", 8080)
        await rpf.handle_forwarded_connection_async(1, 32768, 32768, data)
        mock_transport._send_message_async.assert_awaited()

    async def test_handle_forwarded_success(self, mock_transport):
        """Full success path: open_connection and create relay tasks."""
        rpf = AsyncRemotePortForwarder(mock_transport)
        tunnel = AsyncForwardingTunnel(
            "remote__8080_local_80", ("127.0.0.1", 80), ("", 8080), "remote"
        )
        tunnel.active = True
        rpf._tunnels["remote__8080_local_80"] = tunnel

        data = self._make_type_specific_data("0.0.0.0", 8080)

        mock_reader = MagicMock()
        mock_reader.read = AsyncMock(return_value=b"")
        mock_writer = MagicMock()
        mock_writer.drain = AsyncMock()

        with patch(
            "asyncio.open_connection",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            await rpf.handle_forwarded_connection_async(1, 32768, 32768, data)

        # Channel confirmation should have been sent
        mock_transport._send_message_async.assert_awaited()


# ---------------------------------------------------------------------------
# AsyncRemotePortForwarder relay — exception paths and writer=None
# ---------------------------------------------------------------------------


class TestAsyncRemoteRelayExceptionPaths:
    async def test_relay_stream_to_channel_no_writer(self, mock_transport):
        """_relay_stream_to_channel with writer=None doesn't call writer.close."""
        rpf = AsyncRemotePortForwarder(mock_transport)
        reader = MagicMock()
        reader.read = AsyncMock(return_value=b"")  # EOF immediately
        channel = MagicMock()
        channel.close = AsyncMock()

        # writer=None is default, should succeed without error
        await rpf._relay_stream_to_channel(reader, channel, writer=None)
        channel.close.assert_awaited_once()

    async def test_relay_stream_to_channel_exception_in_read(self, mock_transport):
        """Exception during read is caught."""
        rpf = AsyncRemotePortForwarder(mock_transport)
        reader = MagicMock()
        reader.read = AsyncMock(side_effect=ConnectionResetError("reset"))
        channel = MagicMock()
        channel.close = AsyncMock()
        writer = MagicMock()

        await rpf._relay_stream_to_channel(reader, channel, writer=writer)
        writer.close.assert_called()

    async def test_relay_stream_channel_close_raises(self, mock_transport):
        """Exception in channel.close during finally is swallowed."""
        rpf = AsyncRemotePortForwarder(mock_transport)
        reader = MagicMock()
        reader.read = AsyncMock(return_value=b"")
        channel = MagicMock()
        channel.close = AsyncMock(side_effect=RuntimeError("close error"))

        await rpf._relay_stream_to_channel(reader, channel)

    async def test_relay_channel_to_stream_exception(self, mock_transport):
        """Exception in channel.recv is caught."""
        rpf = AsyncRemotePortForwarder(mock_transport)
        channel = MagicMock()
        channel.recv = AsyncMock(side_effect=ConnectionResetError("reset"))
        writer = MagicMock()

        await rpf._relay_channel_to_stream(channel, writer)
        writer.close.assert_called()

    async def test_relay_channel_to_stream_normal_flow(self, mock_transport):
        """Normal flow with data then EOF."""
        rpf = AsyncRemotePortForwarder(mock_transport)
        channel = MagicMock()
        channel.recv = AsyncMock(side_effect=[b"hello", b""])
        writer = MagicMock()
        writer.drain = AsyncMock()

        await rpf._relay_channel_to_stream(channel, writer)
        writer.write.assert_called_once_with(b"hello")
        writer.close.assert_called()


# ---------------------------------------------------------------------------
# AsyncRemotePortForwarder.close_all
# ---------------------------------------------------------------------------


class TestAsyncRemoteCloseAll:
    async def test_close_all(self, mock_transport):
        rpf = AsyncRemotePortForwarder(mock_transport)
        res = MagicMock()
        res.msg_type = MSG_REQUEST_SUCCESS
        mock_transport._send_global_request_async.return_value = res
        t1 = AsyncForwardingTunnel("t1", ("local", 80), ("", 8080), "remote")
        t1.close = AsyncMock()
        rpf._tunnels["t1"] = t1

        await rpf.close_all()
        assert "t1" not in rpf._tunnels


# ---------------------------------------------------------------------------
# AsyncPortForwardingManager delegation methods
# ---------------------------------------------------------------------------


class TestAsyncPortForwardingManagerDelegation:
    async def test_create_local_tunnel(self, mock_transport):
        mgr = AsyncPortForwardingManager(mock_transport)
        mgr.local_forwarder.create_tunnel = AsyncMock(return_value="local_tid")
        result = await mgr.create_local_tunnel(8080, "remote", 80)
        assert result == "local_tid"
        mgr.local_forwarder.create_tunnel.assert_awaited_once_with(
            8080, "remote", 80, "127.0.0.1"
        )

    async def test_create_remote_tunnel(self, mock_transport):
        mgr = AsyncPortForwardingManager(mock_transport)
        mgr.remote_forwarder.create_tunnel = AsyncMock(return_value="remote_tid")
        result = await mgr.create_remote_tunnel(8080, "local", 80)
        assert result == "remote_tid"

    async def test_handle_forwarded_connection_async(self, mock_transport):
        mgr = AsyncPortForwardingManager(mock_transport)
        mgr.remote_forwarder.handle_forwarded_connection_async = AsyncMock()
        await mgr.handle_forwarded_connection_async(1, 32768, 32768, b"\x00" * 10)
        mgr.remote_forwarder.handle_forwarded_connection_async.assert_awaited_once()

    async def test_close_all_tunnels(self, mock_transport):
        mgr = AsyncPortForwardingManager(mock_transport)
        mgr.local_forwarder.close_all = AsyncMock()
        mgr.remote_forwarder.close_all = AsyncMock()
        await mgr.close_all_tunnels()
        mgr.local_forwarder.close_all.assert_awaited_once()
        mgr.remote_forwarder.close_all.assert_awaited_once()

    async def test_close_tunnel_unknown_prefix(self, mock_transport):
        """Tunnel id with unknown prefix does nothing."""
        mgr = AsyncPortForwardingManager(mock_transport)
        mgr.local_forwarder.close_tunnel = AsyncMock()
        mgr.remote_forwarder.close_tunnel = AsyncMock()
        await mgr.close_tunnel("unknown_tid")
        mgr.local_forwarder.close_tunnel.assert_not_awaited()
        mgr.remote_forwarder.close_tunnel.assert_not_awaited()
