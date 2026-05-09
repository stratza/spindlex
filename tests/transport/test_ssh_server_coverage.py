"""
Coverage tests for spindlex/server/ssh_server.py.

Covers missed lines:
- SSHServer.start_server (raises when no key)
- SSHServer.get_active_channels
- SSHServer.get_channel_count
- SSHServer.close_channel / close_all_channels
- SSHServer.is_channel_authorized
- SSHServer.on_channel_opened / on_channel_closed
- SSHServer.on_authentication_successful / on_authentication_failed
- SSHServer.check_port_forward_cancel_request
- SSHServerManager.__init__, setters
- SSHServerManager.start_server / stop_server
- SSHServerManager._cleanup_connection (lines 825-833)
- SSHServerManager._close_all_connections
- SSHServerManager._cleanup_server_socket
- SSHServerManager.get_connection_stats
- SSHServerManager.close_connection
- SSHServerManager._handle_connection (error path)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import TransportException
from spindlex.server.ssh_server import SSHServer, SSHServerManager

# ---------------------------------------------------------------------------
# SSHServer
# ---------------------------------------------------------------------------


class TestSSHServer:
    def test_start_server_raises_without_key(self):
        server = SSHServer()
        mock_sock = MagicMock()
        with pytest.raises(TransportException, match="Server key must be set"):
            server.start_server(mock_sock)

    def test_get_active_channels_empty(self):
        server = SSHServer()
        channels = server.get_active_channels()
        assert channels == []

    def test_get_active_channels_with_transports(self):
        server = SSHServer()
        mock_transport = MagicMock()
        mock_transport.active = True
        mock_channel = MagicMock()
        mock_transport._channels = {"ch1": mock_channel}
        server._transports = [mock_transport]

        channels = server.get_active_channels()
        assert mock_channel in channels

    def test_get_active_channels_filters_inactive(self):
        server = SSHServer()
        active_t = MagicMock()
        active_t.active = True
        active_t._channels = {}
        inactive_t = MagicMock()
        inactive_t.active = False
        server._transports = [active_t, inactive_t]

        server.get_active_channels()
        # inactive transport should have been filtered out
        assert inactive_t not in server._transports

    def test_get_channel_count(self):
        server = SSHServer()
        mock_t = MagicMock()
        mock_t.active = True
        mock_t._channels = {"ch1": MagicMock(), "ch2": MagicMock()}
        server._transports = [mock_t]

        count = server.get_channel_count()
        assert count == 2

    def test_close_channel_success(self):
        server = SSHServer()
        mock_channel = MagicMock()
        server.close_channel(mock_channel)
        mock_channel.close.assert_called_once()

    def test_close_channel_error_is_logged(self):
        server = SSHServer()
        mock_channel = MagicMock()
        mock_channel.close.side_effect = Exception("close fail")
        # Should not raise
        server.close_channel(mock_channel)

    def test_close_all_channels(self):
        server = SSHServer()
        mock_t = MagicMock()
        mock_t.active = True
        mock_ch = MagicMock()
        mock_t._channels = {"c": mock_ch}
        server._transports = [mock_t]

        server.close_all_channels()
        mock_ch.close.assert_called()

    def test_is_channel_authorized_true(self):
        server = SSHServer()
        server._authenticated_users["alice"] = True
        mock_channel = MagicMock()
        assert server.is_channel_authorized(mock_channel, "alice") is True

    def test_is_channel_authorized_false_unknown_user(self):
        server = SSHServer()
        mock_channel = MagicMock()
        assert server.is_channel_authorized(mock_channel, "bob") is False

    def test_is_channel_authorized_false_when_false(self):
        server = SSHServer()
        server._authenticated_users["charlie"] = False
        mock_channel = MagicMock()
        assert server.is_channel_authorized(mock_channel, "charlie") is False

    def test_on_channel_opened_default_noop(self):
        server = SSHServer()
        mock_channel = MagicMock()
        server.on_channel_opened(mock_channel)  # Should not raise

    def test_on_channel_closed_default_noop(self):
        server = SSHServer()
        mock_channel = MagicMock()
        server.on_channel_closed(mock_channel)  # Should not raise

    def test_on_authentication_successful_updates_users(self):
        server = SSHServer()
        server.on_authentication_successful("alice", "password")
        assert server._authenticated_users.get("alice") is True

    def test_on_authentication_failed_default_noop(self):
        server = SSHServer()
        server.on_authentication_failed("bob", "password")  # Should not raise

    def test_check_port_forward_cancel_request(self):
        server = SSHServer()
        result = server.check_port_forward_cancel_request("127.0.0.1", 8080)
        assert result is True

    def test_check_global_request_default_false(self):
        server = SSHServer()
        assert server.check_global_request("keepalive", MagicMock()) is False

    def test_check_channel_pty_request_default_true(self):
        """Default PTY request returns True (allow)."""
        server = SSHServer()
        mock_channel = MagicMock()
        result = server.check_channel_pty_request(
            mock_channel, "xterm", 80, 24, 0, 0, b""
        )
        assert result is True


# ---------------------------------------------------------------------------
# SSHServerManager
# ---------------------------------------------------------------------------


def _make_server_manager(port: int = 12345) -> SSHServerManager:
    server = SSHServer()
    mock_key = MagicMock()
    mgr = SSHServerManager(server, mock_key, "127.0.0.1", port)
    return mgr


class TestSSHServerManager:
    def test_init_sets_attributes(self):
        mgr = _make_server_manager()
        assert mgr._bind_address == "127.0.0.1"
        assert mgr._running is False
        assert mgr._max_connections == 100

    def test_set_max_connections(self):
        mgr = _make_server_manager()
        mgr.set_max_connections(50)
        assert mgr._max_connections == 50

    def test_set_connection_timeout(self):
        mgr = _make_server_manager()
        mgr.set_connection_timeout(60.0)
        assert mgr._connection_timeout == 60.0

    def test_set_auth_timeout(self):
        mgr = _make_server_manager()
        mgr.set_auth_timeout(45.0)
        assert mgr._auth_timeout == 45.0

    def test_start_server_already_running_raises(self):
        mgr = _make_server_manager()
        mgr._running = True
        with pytest.raises(TransportException, match="already running"):
            mgr.start_server()

    def test_start_server_bind_failure_raises(self):
        """start_server raises TransportException on socket bind failure."""
        mgr = _make_server_manager(port=1)  # Port 1 requires root (permission denied)
        with patch("socket.socket") as mock_socket_class:
            mock_sock = MagicMock()
            mock_sock.bind.side_effect = OSError("permission denied")
            mock_socket_class.return_value = mock_sock
            with pytest.raises(TransportException, match="Failed to start SSH server"):
                mgr.start_server()

    def test_stop_server_not_running_noop(self):
        mgr = _make_server_manager()
        mgr.stop_server()  # Should not raise

    def test_is_running(self):
        mgr = _make_server_manager()
        assert mgr.is_running() is False
        mgr._running = True
        assert mgr.is_running() is True

    def test_get_connection_count(self):
        mgr = _make_server_manager()
        assert mgr.get_connection_count() == 0
        mgr._connections["id1"] = MagicMock()
        assert mgr.get_connection_count() == 1

    def test_get_connection_stats(self):
        mgr = _make_server_manager()
        mgr._total_connections = 5
        mgr._active_connections = 2
        mgr._failed_connections = 1
        stats = mgr.get_connection_stats()
        assert stats["total_connections"] == 5
        assert stats["active_connections"] == 2
        assert stats["failed_connections"] == 1

    def test_get_active_connections(self):
        mgr = _make_server_manager()
        mgr._connections["conn1"] = MagicMock()
        mgr._connections["conn2"] = MagicMock()
        ids = mgr.get_active_connections()
        assert "conn1" in ids
        assert "conn2" in ids

    def test_close_connection_found(self):
        mgr = _make_server_manager()
        mock_t = MagicMock()
        mgr._connections["id1"] = mock_t
        result = mgr.close_connection("id1")
        assert result is True
        mock_t.close.assert_called_once()

    def test_close_connection_not_found(self):
        mgr = _make_server_manager()
        result = mgr.close_connection("nonexistent")
        assert result is False

    def test_cleanup_server_socket(self):
        mgr = _make_server_manager()
        mock_sock = MagicMock()
        mgr._server_socket = mock_sock
        mgr._cleanup_server_socket()
        mock_sock.close.assert_called_once()
        assert mgr._server_socket is None

    def test_cleanup_server_socket_error_ignored(self):
        mgr = _make_server_manager()
        mock_sock = MagicMock()
        mock_sock.close.side_effect = OSError("close fail")
        mgr._server_socket = mock_sock
        mgr._cleanup_server_socket()  # Should not raise
        assert mgr._server_socket is None

    def test_cleanup_connection(self):
        mgr = _make_server_manager()
        mgr._active_connections = 2
        mgr._connections["id1"] = MagicMock()
        mgr._connection_threads["id1"] = MagicMock()

        mock_transport = MagicMock()
        mock_socket = MagicMock()
        mgr._cleanup_connection("id1", mock_transport, mock_socket)

        mock_transport.close.assert_called_once()
        mock_socket.close.assert_called_once()
        assert "id1" not in mgr._connections
        assert mgr._active_connections == 1

    def test_cleanup_connection_none_transport(self):
        mgr = _make_server_manager()
        mock_socket = MagicMock()
        mgr._cleanup_connection("id_none", None, mock_socket)
        mock_socket.close.assert_called_once()

    def test_cleanup_connection_close_error_ignored(self):
        mgr = _make_server_manager()
        mock_transport = MagicMock()
        mock_transport.close.side_effect = Exception("transport close fail")
        mock_socket = MagicMock()
        mgr._cleanup_connection("id2", mock_transport, mock_socket)
        # No exception raised

    def test_close_all_connections(self):
        mgr = _make_server_manager()
        mock_t = MagicMock()
        mgr._connections["id1"] = mock_t
        mgr._close_all_connections()
        mock_t.close.assert_called_once()
        assert len(mgr._connections) == 0

    def test_handle_connection_start_server_fails(self):
        mgr = _make_server_manager()
        mock_sock = MagicMock()
        mock_sock.settimeout = MagicMock()
        mock_sock.close = MagicMock()
        mgr._server_interface.start_server = MagicMock(
            side_effect=TransportException("handshake failed")
        )
        # Should not raise
        mgr._handle_connection(mock_sock, ("127.0.0.1", 12345), "test-conn-id")
        assert mgr._failed_connections == 1

    def test_accept_connections_stops_when_not_running(self):
        """_accept_connections exits when server_socket is None."""
        mgr = _make_server_manager()
        mgr._running = True
        mgr._server_socket = None
        # Should exit immediately
        mgr._accept_connections()
