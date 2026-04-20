"""
Unit tests for transport/forwarding.py — ForwardingTunnel, LocalPortForwarder,
PortForwardingManager covering the untested 65%.
"""
import socket
import threading
import time
from unittest.mock import MagicMock, patch, call

import pytest

from spindlex.exceptions import SSHException
from spindlex.transport.forwarding import (
    ForwardingTunnel,
    LocalPortForwarder,
    PortForwardingManager,
)


# ---------------------------------------------------------------------------
# ForwardingTunnel
# ---------------------------------------------------------------------------

class TestForwardingTunnel:
    def _make_tunnel(self, tunnel_type="local"):
        return ForwardingTunnel(
            tunnel_id="test_tunnel_1",
            local_addr=("127.0.0.1", 9000),
            remote_addr=("remote.host", 22),
            tunnel_type=tunnel_type,
        )

    def test_initial_state(self):
        t = self._make_tunnel()
        assert t.tunnel_id == "test_tunnel_1"
        assert t.local_addr == ("127.0.0.1", 9000)
        assert t.remote_addr == ("remote.host", 22)
        assert t.tunnel_type == "local"
        assert not t.active
        assert t.connections == {}

    def test_close_inactive_tunnel(self):
        t = self._make_tunnel()
        t.close()  # should not raise

    def test_close_active_tunnel(self):
        t = self._make_tunnel()
        t.active = True
        t.close()
        assert not t.active

    def test_close_with_socket_connections(self):
        t = self._make_tunnel()
        t.active = True

        # Use a real socket so isinstance(item, socket.socket) passes
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        t.connections["conn1"] = {"client_socket": s}

        t.close()
        # After close, socket should be closed (connections cleared)
        assert t.connections == {}
        s.close()  # safe to call again

    def test_close_with_channel_connections(self):
        from spindlex.transport.channel import Channel
        t = self._make_tunnel()
        t.active = True

        # Use a real Channel so isinstance check passes
        mock_transport = MagicMock()
        mock_transport.active = False
        ch = Channel(mock_transport, channel_id=1)
        ch._remote_channel_id = 1
        t.connections["conn2"] = {"channel": ch}

        t.close()
        assert t.connections == {}

    def test_close_with_multiple_connections(self):
        t = self._make_tunnel()
        t.active = True

        socks = [socket.socket(socket.AF_INET, socket.SOCK_STREAM) for _ in range(3)]
        for i, s in enumerate(socks):
            t.connections[f"conn{i}"] = {"client_socket": s}

        t.close()
        assert t.connections == {}
        for s in socks:
            s.close()  # safe to call again

    def test_close_silences_connection_close_errors(self):
        t = self._make_tunnel()
        t.active = True

        # Use a real socket and close it before the tunnel does, so the second close raises
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.close()  # pre-close so tunnel's close() may or may not error
        t.connections["bad_conn"] = {"client_socket": s}

        t.close()  # should not raise regardless


# ---------------------------------------------------------------------------
# LocalPortForwarder
# ---------------------------------------------------------------------------

class TestLocalPortForwarder:
    def _make_forwarder(self):
        transport = MagicMock()
        transport.active = True
        return LocalPortForwarder(transport), transport

    def test_create_tunnel_binds_and_returns_id(self):
        forwarder, transport = self._make_forwarder()
        tunnel_id = forwarder.create_tunnel(
            local_port=19500, remote_host="127.0.0.1", remote_port=22
        )
        assert tunnel_id is not None
        assert "19500" in tunnel_id
        # Cleanup
        forwarder.close_tunnel(tunnel_id)

    def test_create_tunnel_duplicate_raises(self):
        forwarder, transport = self._make_forwarder()
        tunnel_id = forwarder.create_tunnel(
            local_port=19501, remote_host="127.0.0.1", remote_port=22
        )
        try:
            with pytest.raises(SSHException, match="already exists"):
                forwarder.create_tunnel(
                    local_port=19501, remote_host="127.0.0.1", remote_port=22
                )
        finally:
            forwarder.close_tunnel(tunnel_id)

    def test_close_tunnel_stops_and_removes(self):
        forwarder, transport = self._make_forwarder()
        tunnel_id = forwarder.create_tunnel(
            local_port=19502, remote_host="127.0.0.1", remote_port=22
        )
        forwarder.close_tunnel(tunnel_id)
        assert tunnel_id not in forwarder._tunnels

    def test_close_nonexistent_tunnel_noop(self):
        forwarder, transport = self._make_forwarder()
        forwarder.close_tunnel("nonexistent_tunnel")  # should not raise

    def test_get_tunnels_returns_active(self):
        forwarder, transport = self._make_forwarder()
        tunnel_id = forwarder.create_tunnel(
            local_port=19503, remote_host="127.0.0.1", remote_port=22
        )
        try:
            tunnels = forwarder.get_tunnels()
            assert tunnel_id in tunnels
        finally:
            forwarder.close_tunnel(tunnel_id)

    def test_create_tunnel_on_invalid_port_raises(self):
        forwarder, transport = self._make_forwarder()
        with pytest.raises(SSHException, match="Failed to create"):
            forwarder.create_tunnel(
                local_port=99999,  # invalid port
                remote_host="127.0.0.1",
                remote_port=22
            )


# ---------------------------------------------------------------------------
# PortForwardingManager
# ---------------------------------------------------------------------------

class TestPortForwardingManager:
    def _make_manager(self):
        transport = MagicMock()
        transport.active = True
        return PortForwardingManager(transport), transport

    def test_create_local_tunnel(self):
        manager, transport = self._make_manager()
        tunnel_id = manager.create_local_tunnel(
            local_host="127.0.0.1",
            local_port=19510,
            remote_host="127.0.0.1",
            remote_port=22,
        )
        assert tunnel_id is not None
        manager.close_tunnel(tunnel_id)

    def test_close_tunnel(self):
        manager, transport = self._make_manager()
        tunnel_id = manager.create_local_tunnel(
            local_host="127.0.0.1",
            local_port=19511,
            remote_host="127.0.0.1",
            remote_port=22,
        )
        manager.close_tunnel(tunnel_id)
        tunnels = manager.get_all_tunnels()
        assert tunnel_id not in tunnels

    def test_get_all_tunnels_empty(self):
        manager, transport = self._make_manager()
        assert manager.get_all_tunnels() == {}

    def test_close_all_tunnels(self):
        manager, transport = self._make_manager()
        t1 = manager.create_local_tunnel(
            local_host="127.0.0.1", local_port=19512,
            remote_host="127.0.0.1", remote_port=22
        )
        t2 = manager.create_local_tunnel(
            local_host="127.0.0.1", local_port=19513,
            remote_host="127.0.0.1", remote_port=22
        )
        manager.close_all_tunnels()
        assert manager.get_all_tunnels() == {}
