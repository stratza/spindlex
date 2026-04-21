import socket
from unittest.mock import MagicMock, patch

import pytest
from spindlex.crypto.pkey import PKey
from spindlex.exceptions import TransportException
from spindlex.protocol.constants import AUTH_FAILED, CHANNEL_SESSION
from spindlex.server.ssh_server import SSHServer, SSHServerManager


class StubSSHServer(SSHServer):
    pass


class TestSSHServer:
    def test_set_get_server_key(self):
        server = SSHServer()
        key = MagicMock(spec=PKey)
        server.set_server_key(key)
        assert server.get_server_key() == key

    def test_start_server_no_key(self):
        server = SSHServer()
        mock_sock = MagicMock(spec=socket.socket)
        with pytest.raises(TransportException, match="Server key must be set"):
            server.start_server(mock_sock)

    def test_default_auth_methods(self):
        server = SSHServer()
        assert server.check_auth_password("alice", "password") == AUTH_FAILED
        assert server.check_auth_publickey("alice", MagicMock()) == AUTH_FAILED
        assert server.check_auth_keyboard_interactive("alice", "") == AUTH_FAILED
        assert server.check_auth_gssapi_with_mic("alice", 0, "") == AUTH_FAILED
        assert server.get_allowed_auths("alice") == ["password", "publickey"]

    def test_check_port_forward(self):
        server = SSHServer()
        assert server.check_port_forward_request("localhost", 8080) is False
        assert server.check_port_forward_cancel_request("localhost", 8080) is True

    def test_check_channel_request(self):
        server = SSHServer()
        assert server.check_channel_request(CHANNEL_SESSION, 0) == 0
        assert server.check_channel_request("unknown", 0) != 0

    def test_check_channel_ops(self):
        server = SSHServer()
        mock_chan = MagicMock()
        assert server.check_channel_exec_request(mock_chan, b"ls") is False
        assert server.check_channel_shell_request(mock_chan) is False
        assert server.check_channel_subsystem_request(mock_chan, "sftp") is False
        assert (
            server.check_channel_pty_request(mock_chan, "xterm", 80, 24, 0, 0, b"")
            is True
        )
        assert (
            server.check_channel_window_change_request(mock_chan, 80, 24, 0, 0) is True
        )
        assert server.check_channel_x11_request(mock_chan, False, "", b"", 0) is False
        assert server.check_channel_env_request(mock_chan, "VAR", "VAL") is False

    def test_authentication_status(self):
        server = SSHServer()
        server.on_authentication_successful("alice", "password")
        assert server._authenticated_users["alice"] is True

        mock_chan = MagicMock()
        assert server.is_channel_authorized(mock_chan, "alice") is True
        assert server.is_channel_authorized(mock_chan, "bob") is False

    def test_channel_management(self):
        server = SSHServer()
        mock_trans = MagicMock()
        mock_chan = MagicMock()
        mock_trans._channels = {1: mock_chan}
        mock_trans.active = True
        server._transports.append(mock_trans)

        assert server.get_channel_count() == 1
        assert server.get_active_channels() == [mock_chan]

        server.close_channel(mock_chan)
        assert mock_chan.close.called

        server.close_all_channels()
        assert mock_chan.close.call_count >= 1


class TestSSHServerManager:
    def test_manager_init(self):
        server = StubSSHServer()
        key = MagicMock(spec=PKey)
        manager = SSHServerManager(server, key, port=2222)
        assert manager._port == 2222

        manager.set_max_connections(10)
        assert manager._max_connections == 10

        manager.set_connection_timeout(5.0)
        assert manager._connection_timeout == 5.0

        manager.set_auth_timeout(5.0)
        assert manager._auth_timeout == 5.0

    @patch("socket.socket")
    def test_start_stop_server(self, mock_socket_cls):
        mock_socket = mock_socket_cls.return_value
        server = StubSSHServer()
        key = MagicMock(spec=PKey)
        manager = SSHServerManager(server, key)

        manager.start_server()
        assert manager._running is True
        assert mock_socket.bind.called
        assert mock_socket.listen.called

        # Test double start
        with pytest.raises(TransportException, match="Server is already running"):
            manager.start_server()

        manager.stop_server()
        assert manager._running is False
        assert mock_socket.close.called

    @patch("socket.socket")
    @patch("threading.Thread")
    def test_accept_connections_loop(self, mock_thread_cls, mock_socket_cls):
        mock_socket = mock_socket_cls.return_value
        mock_socket.accept.return_value = (MagicMock(), ("127.0.0.1", 12345))

        server = StubSSHServer()
        key = MagicMock(spec=PKey)
        manager = SSHServerManager(server, key)
        manager._server_socket = mock_socket
        manager._running = True

        # Run one iteration of accept_connections
        # We need to make it break after one iteration
        def stop_running(*args, **kwargs):
            manager._running = False
            return (MagicMock(), ("127.0.0.1", 12345))

        mock_socket.accept.side_effect = stop_running

        manager._accept_connections()

        assert mock_socket.accept.called
        assert mock_thread_cls.called  # Handle connection thread started
