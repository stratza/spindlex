"""Unit tests for spindlex/transport/forwarding.py to boost coverage."""

from __future__ import annotations

import socket
import time
from unittest.mock import MagicMock

import pytest

from spindlex.exceptions import SSHException
from spindlex.transport.forwarding import (
    ForwardingTunnel,
    LocalPortForwarder,
    PortForwardingManager,
    RemotePortForwarder,
)


def _make_transport():
    t = MagicMock()
    t._active = True
    t._send_global_request = MagicMock(return_value=True)
    t.open_channel = MagicMock()
    return t


# ---- ForwardingTunnel ----


class TestForwardingTunnel:
    def test_init(self):
        ft = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        assert ft.tunnel_id == "t1"
        assert ft.local_addr == ("127.0.0.1", 8080)
        assert ft.remote_addr == ("remote", 80)
        assert ft.tunnel_type == "local"
        assert ft.active is False

    def test_close_empty(self):
        ft = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        ft.active = True
        ft.close()
        assert ft.active is False
        assert len(ft.connections) == 0

    def test_close_with_socket_connections(self):
        ft = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        ft.active = True
        mock_sock = MagicMock()
        ft.connections["c1"] = {"client_socket": mock_sock}
        ft.close()
        assert ft.active is False
        assert len(ft.connections) == 0

    def test_close_with_error_in_connection(self):
        ft = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        ft.active = True
        mock_sock = MagicMock(spec=socket.socket)
        mock_sock.close.side_effect = OSError("fail")
        ft.connections["c1"] = {"client_socket": mock_sock}
        ft.close()  # should not raise


# ---- LocalPortForwarder ----


class TestLocalPortForwarder:
    def test_create_tunnel_invalid_port(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        with pytest.raises(SSHException, match="Invalid local port"):
            lpf.create_tunnel(-1, "remote", 80)

    def test_create_tunnel_duplicate(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        tunnel = ForwardingTunnel(
            "local_127.0.0.1_8080_remote_80",
            ("127.0.0.1", 8080),
            ("remote", 80),
            "local",
        )
        lpf._tunnels["local_127.0.0.1_8080_remote_80"] = tunnel
        with pytest.raises(SSHException, match="already exists"):
            lpf.create_tunnel(8080, "remote", 80)

    def test_close_tunnel_nonexistent(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        lpf.close_tunnel("nonexistent")  # should not raise

    def test_close_tunnel_existing(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        tunnel = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        tunnel.active = True
        lpf._tunnels["t1"] = tunnel
        mock_server = MagicMock(spec=socket.socket)
        lpf._servers["t1"] = mock_server
        lpf.close_tunnel("t1")
        assert "t1" not in lpf._tunnels
        mock_server.shutdown.assert_called_once_with(socket.SHUT_RDWR)
        mock_server.close.assert_called_once()

    def test_close_tunnel_releases_listening_port(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        tunnel_id = lpf.create_tunnel(0, "remote", 80, "127.0.0.1")
        port = lpf._servers[tunnel_id].getsockname()[1]
        # Let the accept thread block in accept() before closing.
        time.sleep(0.05)
        lpf.close_tunnel(tunnel_id)

        # The port must be rebindable without SO_REUSEADDR once the tunnel
        # is closed; a leaked accept thread would keep it bound.
        deadline = time.monotonic() + 5
        while True:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind(("127.0.0.1", port))
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
            finally:
                probe.close()

    def test_get_tunnels(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        tunnel = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        lpf._tunnels["t1"] = tunnel
        tunnels = lpf.get_tunnels()
        assert "t1" in tunnels
        assert tunnels is not lpf._tunnels  # should be a copy

    def test_close_all(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        tunnel = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        tunnel.active = True
        lpf._tunnels["t1"] = tunnel
        lpf._servers["t1"] = MagicMock(spec=socket.socket)
        lpf.close_all()
        assert len(lpf._tunnels) == 0

    def test_relay_data_socket_to_channel(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        source = MagicMock(spec=socket.socket)
        source.recv.side_effect = [b"data", b""]
        dest = MagicMock()  # Channel mock
        lpf._relay_data(source, dest, "relay1")
        dest.send.assert_called_once_with(b"data")

    def test_relay_data_channel_to_socket(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        source = MagicMock()  # Channel mock
        source.recv.side_effect = [b"data", b""]
        dest = MagicMock(spec=socket.socket)
        lpf._relay_data(source, dest, "relay2")
        dest.sendall.assert_called_once_with(b"data")

    def test_relay_data_os_error(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        source = MagicMock()
        source.recv.side_effect = OSError("broken pipe")
        dest = MagicMock()
        lpf._relay_data(source, dest, "relay3")  # should not raise

    def test_accept_connections_no_tunnel(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        server = MagicMock(spec=socket.socket)
        lpf._accept_connections("nonexistent", server)  # should return immediately

    def test_accept_connections_inactive_tunnel(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        tunnel = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        tunnel.active = False
        lpf._tunnels["t1"] = tunnel
        server = MagicMock(spec=socket.socket)
        lpf._accept_connections("t1", server)  # loop condition false, returns

    def test_handle_local_connection_no_tunnel(self):
        t = _make_transport()
        lpf = LocalPortForwarder(t)
        mock_sock = MagicMock(spec=socket.socket)
        lpf._handle_local_connection("nonexistent", mock_sock, ("127.0.0.1", 1234))
        mock_sock.close.assert_called_once()


# ---- RemotePortForwarder ----


class TestRemotePortForwarder:
    def test_create_tunnel_invalid_remote_port(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        with pytest.raises(SSHException, match="Invalid remote port"):
            rpf.create_tunnel(-1, "localhost", 80)

    def test_create_tunnel_invalid_local_port(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        with pytest.raises(SSHException, match="Invalid local port"):
            rpf.create_tunnel(8080, "localhost", -1)

    def test_create_tunnel_duplicate(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        tunnel = ForwardingTunnel(
            "remote__8080_localhost_80", ("localhost", 80), ("", 8080), "remote"
        )
        rpf._tunnels["remote__8080_localhost_80"] = tunnel
        with pytest.raises(SSHException, match="already exists"):
            rpf.create_tunnel(8080, "localhost", 80)

    def test_create_tunnel_denied(self):
        t = _make_transport()
        t._send_global_request.return_value = False
        rpf = RemotePortForwarder(t)
        with pytest.raises(SSHException, match="denied"):
            rpf.create_tunnel(8080, "localhost", 80)

    def test_create_tunnel_success(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        tid = rpf.create_tunnel(8080, "localhost", 80)
        assert tid in rpf._tunnels

    def test_close_tunnel_nonexistent(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        rpf.close_tunnel("nonexistent")  # should not raise

    def test_close_tunnel_existing(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        tunnel = ForwardingTunnel("t1", ("localhost", 80), ("", 8080), "remote")
        tunnel.active = True
        rpf._tunnels["t1"] = tunnel
        rpf.close_tunnel("t1")
        assert "t1" not in rpf._tunnels

    def test_close_tunnel_cancel_request_error(self):
        t = _make_transport()
        t._send_global_request.side_effect = Exception("fail")
        rpf = RemotePortForwarder(t)
        tunnel = ForwardingTunnel("t1", ("localhost", 80), ("", 8080), "remote")
        tunnel.active = True
        rpf._tunnels["t1"] = tunnel
        rpf.close_tunnel("t1")  # should not raise
        assert "t1" not in rpf._tunnels

    def test_get_tunnels(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        tunnel = ForwardingTunnel("t1", ("localhost", 80), ("", 8080), "remote")
        rpf._tunnels["t1"] = tunnel
        tunnels = rpf.get_tunnels()
        assert "t1" in tunnels

    def test_close_all(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        tunnel = ForwardingTunnel("t1", ("localhost", 80), ("", 8080), "remote")
        rpf._tunnels["t1"] = tunnel
        rpf.close_all()
        assert len(rpf._tunnels) == 0

    def test_send_tcpip_forward_error(self):
        t = _make_transport()
        t._send_global_request.side_effect = Exception("fail")
        rpf = RemotePortForwarder(t)
        assert rpf._send_tcpip_forward_request("0.0.0.0", 8080) is False

    def test_send_cancel_forward_error(self):
        t = _make_transport()
        t._send_global_request.side_effect = Exception("fail")
        rpf = RemotePortForwarder(t)
        assert rpf._send_cancel_tcpip_forward_request("0.0.0.0", 8080) is False

    def test_handle_forwarded_no_matching_tunnel(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        ch = MagicMock()
        rpf.handle_forwarded_connection(ch, ("1.2.3.4", 5555), ("0.0.0.0", 9999))
        ch.close.assert_called_once()

    def test_relay_data_error(self):
        t = _make_transport()
        rpf = RemotePortForwarder(t)
        source = MagicMock()
        source.recv.side_effect = OSError("broken")
        dest = MagicMock()
        rpf._relay_data(source, dest, "relay")  # should not raise


# ---- PortForwardingManager ----


class TestPortForwardingManager:
    def test_close_tunnel_local(self):
        t = _make_transport()
        mgr = PortForwardingManager(t)
        tunnel = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        mgr.local_forwarder._tunnels["t1"] = tunnel
        mgr.local_forwarder._servers["t1"] = MagicMock(spec=socket.socket)
        mgr.close_tunnel("t1")
        assert "t1" not in mgr.local_forwarder._tunnels

    def test_close_tunnel_remote(self):
        t = _make_transport()
        mgr = PortForwardingManager(t)
        tunnel = ForwardingTunnel("t2", ("localhost", 80), ("", 8080), "remote")
        mgr.remote_forwarder._tunnels["t2"] = tunnel
        mgr.close_tunnel("t2")
        assert "t2" not in mgr.remote_forwarder._tunnels

    def test_close_tunnel_not_found(self):
        t = _make_transport()
        mgr = PortForwardingManager(t)
        mgr.close_tunnel("nonexistent")  # should not raise

    def test_get_all_tunnels(self):
        t = _make_transport()
        mgr = PortForwardingManager(t)
        t1 = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        t2 = ForwardingTunnel("t2", ("localhost", 80), ("", 8080), "remote")
        mgr.local_forwarder._tunnels["t1"] = t1
        mgr.remote_forwarder._tunnels["t2"] = t2
        all_tunnels = mgr.get_all_tunnels()
        assert "t1" in all_tunnels
        assert "t2" in all_tunnels

    def test_close_all_tunnels(self):
        t = _make_transport()
        mgr = PortForwardingManager(t)
        t1 = ForwardingTunnel("t1", ("127.0.0.1", 8080), ("remote", 80), "local")
        mgr.local_forwarder._tunnels["t1"] = t1
        mgr.local_forwarder._servers["t1"] = MagicMock(spec=socket.socket)
        mgr.close_all_tunnels()
        assert len(mgr.local_forwarder._tunnels) == 0
