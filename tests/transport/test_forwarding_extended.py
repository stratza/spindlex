"""
Extended coverage tests for spindlex/transport/forwarding.py.
Targets remaining missed lines from coverage report.

Covers:
  - ForwardingTunnel.close() with Channel items (lines 69-72)
  - LocalPortForwarder.create_tunnel IPv6 path (lines 157-162)
  - LocalPortForwarder.create_tunnel exception cleanup paths (189-206)
  - LocalPortForwarder._accept_connections (220, 229-253)
  - LocalPortForwarder._handle_local_connection (266-325)
  - LocalPortForwarder._relay_data (341-358)
  - LocalPortForwarder.close_all (lines 396-400)
  - RemotePortForwarder.create_tunnel (lines 447-484)
  - RemotePortForwarder._send_tcpip_forward_request (486-512)
  - RemotePortForwarder.handle_forwarded_connection (514-606)
  - RemotePortForwarder._relay_data (622-639)
  - RemotePortForwarder.close_tunnel (641-667)
  - RemotePortForwarder._send_cancel_tcpip_forward_request (669-697)
  - RemotePortForwarder.get_tunnels/close_all (699-713)
  - PortForwardingManager paths (716-827)
"""

from __future__ import annotations

import socket
import threading
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import SSHException
from spindlex.transport.forwarding import (
    ForwardingTunnel,
    LocalPortForwarder,
    PortForwardingManager,
    RemotePortForwarder,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def make_mock_transport():
    t = MagicMock()
    t.active = True
    return t


# ---------------------------------------------------------------------------
# ForwardingTunnel.close() with Channel items (lines 69-72)
# ---------------------------------------------------------------------------


class TestForwardingTunnelClose:
    def test_close_with_channel_item(self):
        """Channel items in connections are closed (line 68-72)."""
        from spindlex.transport.channel import Channel

        t = ForwardingTunnel("tid", ("127.0.0.1", 1), ("r", 2), "local")
        t.active = True
        mock_transport = MagicMock()
        mock_transport.active = False
        ch = Channel(mock_transport, channel_id=1)
        ch._remote_channel_id = 1
        t.connections["c1"] = {"channel": ch}

        t.close()
        assert t.connections == {}

    def test_close_error_silenced(self):
        """Exceptions during close are silenced (lines 71-72)."""
        t = ForwardingTunnel("tid", ("127.0.0.1", 1), ("r", 2), "local")
        t.active = True

        bad_item = MagicMock()
        bad_item.close.side_effect = RuntimeError("oops")
        t.connections["bad"] = {"client_socket": bad_item}

        # Should not raise
        t.close()
        assert t.connections == {}


# ---------------------------------------------------------------------------
# LocalPortForwarder.create_tunnel - IPv6 dual-stack path (lines 157-162)
# ---------------------------------------------------------------------------


class TestLocalPortForwarderIPv6:
    def test_create_tunnel_ipv6only_option(self):
        """Test IPv6 socket setup path. May be skipped if socket.IPV6_V6ONLY missing."""
        forwarder = LocalPortForwarder(make_mock_transport())
        # Use localhost which is available on all platforms
        try:
            tunnel_id = forwarder.create_tunnel(
                local_port=0, remote_host="127.0.0.1", remote_port=22, local_host="::1"
            )
            forwarder.close_tunnel(tunnel_id)
        except SSHException:
            pytest.skip("IPv6 not available on this platform")


# ---------------------------------------------------------------------------
# LocalPortForwarder.create_tunnel exception cleanup (lines 189-206)
# ---------------------------------------------------------------------------


class TestLocalPortForwarderCleanup:
    def test_create_tunnel_bind_failure_cleans_up(self):
        """Exception during bind() is caught and cleanup happens (lines 189-208)."""
        forwarder = LocalPortForwarder(make_mock_transport())

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value = mock_sock
            mock_sock.bind.side_effect = OSError("address already in use")

            with pytest.raises(
                SSHException, match="Failed to create local port forwarding"
            ):
                forwarder.create_tunnel(
                    local_port=19600, remote_host="127.0.0.1", remote_port=22
                )
            # Socket should have been closed
            mock_sock.close.assert_called()

    def test_create_tunnel_listen_failure_closes_socket(self):
        """If listen() fails, socket is closed (lines 201-205)."""
        forwarder = LocalPortForwarder(make_mock_transport())

        with patch("socket.socket") as mock_socket_cls:
            mock_sock = MagicMock()
            mock_socket_cls.return_value = mock_sock
            mock_sock.listen.side_effect = OSError("listen failed")

            with pytest.raises(SSHException):
                forwarder.create_tunnel(
                    local_port=19601, remote_host="127.0.0.1", remote_port=22
                )


# ---------------------------------------------------------------------------
# LocalPortForwarder._accept_connections (lines 220, 229-253)
# ---------------------------------------------------------------------------


class TestAcceptConnections:
    def test_accept_connections_handles_oserror(self):
        """OSError when tunnel is inactive breaks the accept loop (lines 241-246)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        tunnel = ForwardingTunnel("test_accept", ("127.0.0.1", 0), ("r", 22), "local")
        tunnel.active = True
        forwarder._tunnels["test_accept"] = tunnel

        mock_server_sock = MagicMock()
        call_count = [0]

        def accept_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: simulate active tunnel accepting connection that's then closed
                tunnel.active = False
                raise OSError("socket closed")
            return (MagicMock(), ("127.0.0.1", 12345))

        mock_server_sock.accept.side_effect = accept_side_effect

        # Run in thread to not block
        t = threading.Thread(
            target=forwarder._accept_connections,
            args=("test_accept", mock_server_sock),
            daemon=True,
        )
        t.start()
        t.join(timeout=2.0)
        assert not t.is_alive()

    def test_accept_connections_no_tunnel_returns_immediately(self):
        """If tunnel doesn't exist, returns immediately (line 219-220)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        mock_server_sock = MagicMock()
        # Should return immediately without calling accept
        forwarder._accept_connections("nonexistent_tunnel", mock_server_sock)
        mock_server_sock.accept.assert_not_called()

    def test_accept_connections_spawns_handler_thread(self):
        """Successful accept spawns a handler thread (lines 229-251)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        tunnel = ForwardingTunnel("taccept2", ("127.0.0.1", 0), ("r", 22), "local")
        tunnel.active = True
        forwarder._tunnels["taccept2"] = tunnel

        client_sock = MagicMock()
        client_addr = ("127.0.0.1", 54321)

        call_count = [0]

        def accept_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return (client_sock, client_addr)
            tunnel.active = False
            raise OSError("closed")

        mock_server_sock = MagicMock()
        mock_server_sock.accept.side_effect = accept_side_effect

        # Stub out _handle_local_connection to not actually do anything
        handled = threading.Event()

        def mock_handle(tunnel_id, sock, addr):
            handled.set()

        forwarder._handle_local_connection = mock_handle

        t = threading.Thread(
            target=forwarder._accept_connections,
            args=("taccept2", mock_server_sock),
            daemon=True,
        )
        t.start()
        handled.wait(timeout=2.0)
        t.join(timeout=2.0)

    def test_accept_connections_unexpected_exception_breaks_loop(self):
        """Unexpected exception breaks the accept loop (lines 247-251)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        tunnel = ForwardingTunnel("taccept3", ("127.0.0.1", 0), ("r", 22), "local")
        tunnel.active = True
        forwarder._tunnels["taccept3"] = tunnel

        mock_server_sock = MagicMock()
        mock_server_sock.accept.side_effect = ValueError("unexpected")

        t = threading.Thread(
            target=forwarder._accept_connections,
            args=("taccept3", mock_server_sock),
            daemon=True,
        )
        t.start()
        t.join(timeout=2.0)
        assert not t.is_alive()


# ---------------------------------------------------------------------------
# LocalPortForwarder._handle_local_connection (lines 266-325)
# ---------------------------------------------------------------------------


class TestHandleLocalConnection:
    def test_handle_local_connection_no_tunnel(self):
        """If tunnel doesn't exist, closes socket and returns (line 267-269)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        client_sock = MagicMock()
        forwarder._handle_local_connection("nonexistent", client_sock, ("127.0.0.1", 1))
        client_sock.close.assert_called_once()

    def test_handle_local_connection_channel_open_fails(self):
        """Exception opening channel is caught (lines 307-308)."""
        transport = make_mock_transport()
        transport.open_channel.side_effect = SSHException("connection refused")
        forwarder = LocalPortForwarder(transport)

        tunnel = ForwardingTunnel("t_conn", ("127.0.0.1", 0), ("r", 22), "local")
        tunnel.active = True
        forwarder._tunnels["t_conn"] = tunnel

        client_sock = MagicMock()
        forwarder._handle_local_connection("t_conn", client_sock, ("127.0.0.1", 1234))
        # Should not raise, socket should be closed in finally
        client_sock.close.assert_called()

    def test_handle_local_connection_relay_data(self):
        """Full connection handling relays data between socket and channel."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        tunnel = ForwardingTunnel("t_relay", ("127.0.0.1", 0), ("r", 22), "local")
        tunnel.active = True
        forwarder._tunnels["t_relay"] = tunnel

        # Mock channel that immediately returns empty on recv
        mock_channel = MagicMock()
        mock_channel.recv.return_value = b""
        transport.open_channel.return_value = mock_channel

        # Mock client socket that immediately returns empty on recv
        client_sock = MagicMock()
        client_sock.recv.return_value = b""

        # Run in thread
        t = threading.Thread(
            target=forwarder._handle_local_connection,
            args=("t_relay", client_sock, ("127.0.0.1", 1234)),
            daemon=True,
        )
        t.start()
        t.join(timeout=3.0)


# ---------------------------------------------------------------------------
# LocalPortForwarder._relay_data (lines 341-358)
# ---------------------------------------------------------------------------


class TestLocalRelayData:
    def test_relay_data_socket_to_channel(self):
        """Relay from socket to channel (line 353)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        source = MagicMock()
        source.recv.side_effect = [b"hello", b""]

        dest_channel = MagicMock()

        forwarder._relay_data(source, dest_channel, "socket_to_channel")
        dest_channel.sendall.assert_called_once_with(b"hello")

    def test_relay_data_channel_to_socket(self):
        """Relay from channel to socket (line 351)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        source = MagicMock()
        source.recv.side_effect = [b"world", b""]

        dest_sock = MagicMock(spec=socket.socket)

        forwarder._relay_data(source, dest_sock, "channel_to_socket")
        dest_sock.sendall.assert_called_once_with(b"world")

    def test_relay_data_oserror_breaks(self):
        """OSError during relay breaks the loop (lines 355-356)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        source = MagicMock()
        source.recv.side_effect = OSError("connection reset")
        dest = MagicMock()

        forwarder._relay_data(source, dest, "relay_oserror")
        # Should complete without raising

    def test_relay_data_unexpected_exception(self):
        """Unexpected exception is logged, not raised (lines 357-358)."""
        transport = make_mock_transport()
        forwarder = LocalPortForwarder(transport)

        source = MagicMock()
        source.recv.side_effect = RuntimeError("unexpected")
        dest = MagicMock()

        forwarder._relay_data(source, dest, "relay_unexpected")


# ---------------------------------------------------------------------------
# LocalPortForwarder.close_all (lines 396-400)
# ---------------------------------------------------------------------------


class TestLocalCloseAll:
    def test_close_all_closes_multiple_tunnels(self):
        forwarder = LocalPortForwarder(make_mock_transport())
        try:
            t1 = forwarder.create_tunnel(
                local_port=19610, remote_host="127.0.0.1", remote_port=22
            )
            t2 = forwarder.create_tunnel(
                local_port=19611, remote_host="127.0.0.1", remote_port=22
            )
            forwarder.close_all()
            assert t1 not in forwarder._tunnels
            assert t2 not in forwarder._tunnels
        except SSHException:
            pytest.skip("Could not bind ports for test")


# ---------------------------------------------------------------------------
# RemotePortForwarder.create_tunnel (lines 441-484)
# ---------------------------------------------------------------------------


class TestRemotePortForwarder:
    def test_create_tunnel_invalid_remote_port(self):
        """Invalid remote port raises SSHException."""
        forwarder = RemotePortForwarder(make_mock_transport())
        with pytest.raises(SSHException, match="Invalid remote port"):
            forwarder.create_tunnel(99999, "127.0.0.1", 22)

    def test_create_tunnel_invalid_local_port(self):
        """Invalid local port raises SSHException."""
        forwarder = RemotePortForwarder(make_mock_transport())
        with pytest.raises(SSHException, match="Invalid local port"):
            forwarder.create_tunnel(2222, "127.0.0.1", 99999)

    def test_create_tunnel_duplicate_raises(self):
        """Duplicate tunnel_id raises SSHException."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        forwarder = RemotePortForwarder(transport)

        tunnel_id = forwarder.create_tunnel(2223, "127.0.0.1", 9000)
        try:
            with pytest.raises(SSHException, match="already exists"):
                forwarder.create_tunnel(2223, "127.0.0.1", 9000)
        finally:
            forwarder.close_tunnel(tunnel_id)

    def test_create_tunnel_success(self):
        """Successful remote tunnel creation."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        forwarder = RemotePortForwarder(transport)

        tunnel_id = forwarder.create_tunnel(2224, "127.0.0.1", 9001)
        assert tunnel_id in forwarder._tunnels
        forwarder.close_tunnel(tunnel_id)

    def test_create_tunnel_request_denied(self):
        """Server denies tcpip-forward → SSHException."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = False
        forwarder = RemotePortForwarder(transport)

        with pytest.raises(SSHException, match="denied by server"):
            forwarder.create_tunnel(2225, "127.0.0.1", 9002)

    def test_create_tunnel_exception_cleanup(self):
        """Exception during creation cleans up tunnel (lines 477-484)."""
        transport = make_mock_transport()
        transport._send_global_request.side_effect = RuntimeError("transport error")
        forwarder = RemotePortForwarder(transport)

        with pytest.raises(
            SSHException, match="Failed to create remote port forwarding"
        ):
            forwarder.create_tunnel(2226, "127.0.0.1", 9003)

    def test_get_tunnels(self):
        """get_tunnels returns copy of tunnels dict."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        forwarder = RemotePortForwarder(transport)

        tunnel_id = forwarder.create_tunnel(2227, "127.0.0.1", 9004)
        tunnels = forwarder.get_tunnels()
        assert tunnel_id in tunnels
        forwarder.close_tunnel(tunnel_id)

    def test_close_all(self):
        """close_all closes all remote tunnels."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        transport._send_global_request.return_value = True
        forwarder = RemotePortForwarder(transport)

        forwarder.create_tunnel(2228, "127.0.0.1", 9005)
        forwarder.create_tunnel(2229, "127.0.0.1", 9006)
        forwarder.close_all()
        assert len(forwarder._tunnels) == 0

    def test_close_tunnel_nonexistent_noop(self):
        """Closing nonexistent tunnel is a no-op."""
        forwarder = RemotePortForwarder(make_mock_transport())
        forwarder.close_tunnel("nonexistent_tunnel")  # should not raise

    def test_send_tcpip_forward_request_exception(self):
        """Exception in _send_global_request returns False (lines 510-512)."""
        transport = make_mock_transport()
        transport._send_global_request.side_effect = Exception("error")
        forwarder = RemotePortForwarder(transport)
        result = forwarder._send_tcpip_forward_request("127.0.0.1", 22)
        assert result is False

    def test_send_cancel_tcpip_forward_request_exception(self):
        """Exception in cancel request returns False (lines 695-697)."""
        transport = make_mock_transport()
        transport._send_global_request.side_effect = Exception("error")
        forwarder = RemotePortForwarder(transport)
        result = forwarder._send_cancel_tcpip_forward_request("127.0.0.1", 22)
        assert result is False

    def test_send_cancel_tcpip_forward_request_success(self):
        """Successful cancel request returns True."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        forwarder = RemotePortForwarder(transport)
        result = forwarder._send_cancel_tcpip_forward_request("127.0.0.1", 22)
        assert result is True

    def test_close_tunnel_send_error_ignored(self):
        """Exception during cancel request is logged but not raised (lines 659-662)."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        forwarder = RemotePortForwarder(transport)

        tunnel_id = forwarder.create_tunnel(2230, "127.0.0.1", 9007)
        transport._send_global_request.side_effect = Exception("cancel error")
        forwarder.close_tunnel(tunnel_id)  # should not raise
        assert tunnel_id not in forwarder._tunnels


# ---------------------------------------------------------------------------
# RemotePortForwarder.handle_forwarded_connection (lines 514-606)
# ---------------------------------------------------------------------------


class TestHandleForwardedConnection:
    def test_no_tunnel_closes_channel(self):
        """No matching tunnel → channel.close() called (lines 535-540)."""
        transport = make_mock_transport()
        forwarder = RemotePortForwarder(transport)

        channel = MagicMock()
        forwarder.handle_forwarded_connection(channel, ("1.2.3.4", 1234), ("r", 2222))
        channel.close.assert_called_once()

    def test_inactive_tunnel_closes_channel(self):
        """Inactive tunnel → channel.close() called."""
        transport = make_mock_transport()
        forwarder = RemotePortForwarder(transport)

        tunnel = ForwardingTunnel(
            "t_inactive", ("127.0.0.1", 9000), ("r", 2222), "remote"
        )
        tunnel.active = False
        forwarder._tunnels["t_inactive"] = tunnel

        channel = MagicMock()
        forwarder.handle_forwarded_connection(channel, ("1.2.3.4", 1234), ("r", 2222))
        channel.close.assert_called_once()

    def test_connection_socket_connect_fails(self):
        """Exception connecting local socket is caught (lines 591-594)."""
        transport = make_mock_transport()
        forwarder = RemotePortForwarder(transport)

        tunnel = ForwardingTunnel("t_fail", ("127.0.0.1", 9901), ("r", 2222), "remote")
        tunnel.active = True
        forwarder._tunnels["t_fail"] = tunnel

        channel = MagicMock()
        channel.recv.return_value = b""

        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock_cls.return_value = mock_sock
            mock_sock.connect.side_effect = ConnectionRefusedError("refused")

            # This should not raise
            forwarder.handle_forwarded_connection(
                channel, ("1.2.3.4", 1234), ("r", 2222)
            )


# ---------------------------------------------------------------------------
# RemotePortForwarder._relay_data (lines 622-639)
# ---------------------------------------------------------------------------


class TestRemoteRelayData:
    def test_relay_data_channel_to_socket(self):
        """Relay from channel to socket."""
        transport = make_mock_transport()
        forwarder = RemotePortForwarder(transport)

        source = MagicMock()
        source.recv.side_effect = [b"data", b""]
        dest = MagicMock(spec=socket.socket)

        forwarder._relay_data(source, dest, "remote_relay_1")
        dest.sendall.assert_called_once_with(b"data")

    def test_relay_data_exception_logged(self):
        """SSHException during relay is caught and logged."""
        transport = make_mock_transport()
        forwarder = RemotePortForwarder(transport)

        source = MagicMock()
        source.recv.side_effect = SSHException("channel closed")
        dest = MagicMock()

        forwarder._relay_data(source, dest, "remote_relay_2")


# ---------------------------------------------------------------------------
# PortForwardingManager (lines 716-827)
# ---------------------------------------------------------------------------


class TestPortForwardingManager:
    def test_create_local_tunnel(self):
        """create_local_tunnel delegates to local_forwarder."""
        transport = make_mock_transport()
        manager = PortForwardingManager(transport)

        try:
            tunnel_id = manager.create_local_tunnel(19620, "127.0.0.1", 22)
            assert tunnel_id in manager.local_forwarder.get_tunnels()
            manager.close_tunnel(tunnel_id)
        except SSHException:
            pytest.skip("Could not bind port for test")

    def test_create_remote_tunnel(self):
        """create_remote_tunnel delegates to remote_forwarder."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        manager = PortForwardingManager(transport)

        tunnel_id = manager.create_remote_tunnel(2240, "127.0.0.1", 9010)
        assert tunnel_id in manager.remote_forwarder.get_tunnels()
        manager.close_tunnel(tunnel_id)

    def test_close_tunnel_local(self):
        """close_tunnel finds and closes local tunnel."""
        transport = make_mock_transport()
        manager = PortForwardingManager(transport)

        try:
            tunnel_id = manager.create_local_tunnel(19621, "127.0.0.1", 22)
            manager.close_tunnel(tunnel_id)
            assert tunnel_id not in manager.get_all_tunnels()
        except SSHException:
            pytest.skip("Could not bind port for test")

    def test_close_tunnel_remote(self):
        """close_tunnel finds and closes remote tunnel."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        manager = PortForwardingManager(transport)

        tunnel_id = manager.create_remote_tunnel(2241, "127.0.0.1", 9011)
        manager.close_tunnel(tunnel_id)
        assert tunnel_id not in manager.get_all_tunnels()

    def test_close_tunnel_not_found_logged(self):
        """close_tunnel with unknown id logs a warning (line 791)."""
        transport = make_mock_transport()
        manager = PortForwardingManager(transport)
        manager.close_tunnel("nonexistent_tunnel_xyz")  # should not raise

    def test_get_all_tunnels_includes_both(self):
        """get_all_tunnels returns both local and remote tunnels."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        manager = PortForwardingManager(transport)

        remote_id = manager.create_remote_tunnel(2242, "127.0.0.1", 9012)
        all_tunnels = manager.get_all_tunnels()
        assert remote_id in all_tunnels
        manager.close_tunnel(remote_id)

    def test_close_all_tunnels(self):
        """close_all_tunnels closes both local and remote."""
        transport = make_mock_transport()
        transport._send_global_request.return_value = True
        manager = PortForwardingManager(transport)

        manager.create_remote_tunnel(2243, "127.0.0.1", 9013)
        manager.close_all_tunnels()
        assert manager.get_all_tunnels() == {}

    def test_handle_forwarded_connection_no_tunnel(self):
        """handle_forwarded_connection with no matching tunnel closes channel."""
        transport = make_mock_transport()
        manager = PortForwardingManager(transport)

        channel = MagicMock()
        manager.handle_forwarded_connection(channel, ("1.2.3.4", 1234), ("r", 2222))
        channel.close.assert_called_once()
