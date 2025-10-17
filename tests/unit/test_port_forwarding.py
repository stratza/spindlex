"""
Tests for SSH Port Forwarding functionality.

Tests local and remote port forwarding, tunnel management,
and concurrent connection handling.
"""

import socket
import threading
import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from spindlex.client.ssh_client import SSHClient
from spindlex.exceptions import SSHException, TransportException
from spindlex.transport.channel import Channel
from spindlex.transport.forwarding import (
    ForwardingTunnel,
    LocalPortForwarder,
    PortForwardingManager,
    RemotePortForwarder,
)
from spindlex.transport.transport import Transport


class TestForwardingTunnel:
    """Test ForwardingTunnel class."""

    def test_tunnel_creation(self):
        """Test tunnel creation and initialization."""
        tunnel = ForwardingTunnel(
            "test_tunnel", ("127.0.0.1", 8080), ("remote.host", 80), "local"
        )

        assert tunnel.tunnel_id == "test_tunnel"
        assert tunnel.local_addr == ("127.0.0.1", 8080)
        assert tunnel.remote_addr == ("remote.host", 80)
        assert tunnel.tunnel_type == "local"
        assert not tunnel.active
        assert len(tunnel.connections) == 0

    def test_tunnel_close(self):
        """Test tunnel closure and cleanup."""
        tunnel = ForwardingTunnel(
            "test_tunnel", ("127.0.0.1", 8080), ("remote.host", 80), "local"
        )

        # Add mock connections
        mock_conn1 = Mock()
        mock_conn2 = Mock()
        tunnel.connections["conn1"] = mock_conn1
        tunnel.connections["conn2"] = mock_conn2
        tunnel.active = True

        # Close tunnel
        tunnel.close()

        assert not tunnel.active
        assert len(tunnel.connections) == 0
        mock_conn1.close.assert_called_once()
        mock_conn2.close.assert_called_once()


class TestLocalPortForwarder:
    """Test LocalPortForwarder class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_transport = Mock(spec=Transport)
        self.forwarder = LocalPortForwarder(self.mock_transport)

    def test_forwarder_creation(self):
        """Test forwarder initialization."""
        assert self.forwarder._transport == self.mock_transport
        assert len(self.forwarder._tunnels) == 0
        assert len(self.forwarder._servers) == 0

    @patch("socket.socket")
    def test_create_tunnel_success(self, mock_socket_class):
        """Test successful tunnel creation."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        # Mock socket operations
        mock_socket.bind.return_value = None
        mock_socket.listen.return_value = None

        with patch("threading.Thread") as mock_thread:
            tunnel_id = self.forwarder.create_tunnel(8080, "remote.host", 80)

        # Verify tunnel creation
        assert tunnel_id in self.forwarder._tunnels
        assert tunnel_id in self.forwarder._servers

        tunnel = self.forwarder._tunnels[tunnel_id]
        assert tunnel.local_addr == ("127.0.0.1", 8080)
        assert tunnel.remote_addr == ("remote.host", 80)
        assert tunnel.tunnel_type == "local"
        assert tunnel.active

        # Verify socket setup
        mock_socket.setsockopt.assert_called_once()
        mock_socket.bind.assert_called_once_with(("127.0.0.1", 8080))
        mock_socket.listen.assert_called_once_with(5)

        # Verify thread creation
        mock_thread.assert_called_once()

    @patch("socket.socket")
    def test_create_tunnel_failure(self, mock_socket_class):
        """Test tunnel creation failure."""
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        # Mock socket bind failure
        mock_socket.bind.side_effect = OSError("Address already in use")

        with pytest.raises(
            SSHException, match="Failed to create local port forwarding"
        ):
            self.forwarder.create_tunnel(8080, "remote.host", 80)

        # Verify cleanup
        assert len(self.forwarder._tunnels) == 0
        assert len(self.forwarder._servers) == 0

    def test_create_duplicate_tunnel(self):
        """Test creating duplicate tunnel."""
        with patch("socket.socket"), patch("threading.Thread"):
            tunnel_id = self.forwarder.create_tunnel(8080, "remote.host", 80)

        # Try to create same tunnel again
        with pytest.raises(SSHException, match="Tunnel already exists"):
            self.forwarder.create_tunnel(8080, "remote.host", 80)

    def test_close_tunnel(self):
        """Test tunnel closure."""
        with patch("socket.socket") as mock_socket_class, patch("threading.Thread"):
            mock_socket = Mock()
            mock_socket_class.return_value = mock_socket

            tunnel_id = self.forwarder.create_tunnel(8080, "remote.host", 80)

        # Close tunnel
        self.forwarder.close_tunnel(tunnel_id)

        # Verify cleanup
        assert tunnel_id not in self.forwarder._tunnels
        assert tunnel_id not in self.forwarder._servers
        mock_socket.close.assert_called_once()

    def test_close_nonexistent_tunnel(self):
        """Test closing non-existent tunnel."""
        # Should not raise exception
        self.forwarder.close_tunnel("nonexistent")

    def test_get_tunnels(self):
        """Test getting tunnel list."""
        with patch("socket.socket"), patch("threading.Thread"):
            tunnel_id = self.forwarder.create_tunnel(8080, "remote.host", 80)

        tunnels = self.forwarder.get_tunnels()
        assert tunnel_id in tunnels
        assert isinstance(tunnels[tunnel_id], ForwardingTunnel)

    def test_close_all(self):
        """Test closing all tunnels."""
        with patch("socket.socket"), patch("threading.Thread"):
            tunnel_id1 = self.forwarder.create_tunnel(8080, "remote.host", 80)
            tunnel_id2 = self.forwarder.create_tunnel(8081, "remote.host", 81)

        self.forwarder.close_all()

        assert len(self.forwarder._tunnels) == 0
        assert len(self.forwarder._servers) == 0


class TestRemotePortForwarder:
    """Test RemotePortForwarder class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_transport = Mock(spec=Transport)
        self.forwarder = RemotePortForwarder(self.mock_transport)

    def test_forwarder_creation(self):
        """Test forwarder initialization."""
        assert self.forwarder._transport == self.mock_transport
        assert len(self.forwarder._tunnels) == 0

    def test_create_tunnel_success(self):
        """Test successful remote tunnel creation."""
        # Mock successful global request
        self.forwarder._send_tcpip_forward_request = Mock(return_value=True)

        tunnel_id = self.forwarder.create_tunnel(8080, "127.0.0.1", 80)

        # Verify tunnel creation
        assert tunnel_id in self.forwarder._tunnels

        tunnel = self.forwarder._tunnels[tunnel_id]
        assert tunnel.local_addr == ("127.0.0.1", 80)
        assert tunnel.remote_addr == ("", 8080)
        assert tunnel.tunnel_type == "remote"
        assert tunnel.active

        # Verify global request was sent
        self.forwarder._send_tcpip_forward_request.assert_called_once_with("", 8080)

    def test_create_tunnel_failure(self):
        """Test remote tunnel creation failure."""
        # Mock failed global request
        self.forwarder._send_tcpip_forward_request = Mock(return_value=False)

        with pytest.raises(SSHException, match="Remote port forwarding request denied"):
            self.forwarder.create_tunnel(8080, "127.0.0.1", 80)

        # Verify no tunnel was created
        assert len(self.forwarder._tunnels) == 0

    def test_create_duplicate_tunnel(self):
        """Test creating duplicate remote tunnel."""
        self.forwarder._send_tcpip_forward_request = Mock(return_value=True)

        tunnel_id = self.forwarder.create_tunnel(8080, "127.0.0.1", 80)

        # Try to create same tunnel again
        with pytest.raises(SSHException, match="Tunnel already exists"):
            self.forwarder.create_tunnel(8080, "127.0.0.1", 80)

    @patch("socket.socket")
    def test_handle_forwarded_connection(self, mock_socket_class):
        """Test handling forwarded connection."""
        # Create tunnel
        self.forwarder._send_tcpip_forward_request = Mock(return_value=True)
        tunnel_id = self.forwarder.create_tunnel(8080, "127.0.0.1", 80)

        # Mock local socket
        mock_socket = Mock()
        mock_socket_class.return_value = mock_socket

        # Mock channel
        mock_channel = Mock(spec=Channel)

        with patch("threading.Thread") as mock_thread:
            self.forwarder.handle_forwarded_connection(
                mock_channel, ("client.host", 12345), ("", 8080)
            )

        # Verify local connection was made
        mock_socket.connect.assert_called_once_with(("127.0.0.1", 80))

        # Verify relay threads were started
        assert mock_thread.call_count == 2

    def test_handle_forwarded_connection_no_tunnel(self):
        """Test handling forwarded connection with no matching tunnel."""
        mock_channel = Mock(spec=Channel)

        self.forwarder.handle_forwarded_connection(
            mock_channel, ("client.host", 12345), ("", 9999)  # No tunnel for this port
        )

        # Channel should be closed
        mock_channel.close.assert_called_once()

    def test_close_tunnel(self):
        """Test remote tunnel closure."""
        self.forwarder._send_tcpip_forward_request = Mock(return_value=True)
        self.forwarder._send_cancel_tcpip_forward_request = Mock(return_value=True)

        tunnel_id = self.forwarder.create_tunnel(8080, "127.0.0.1", 80)

        # Close tunnel
        self.forwarder.close_tunnel(tunnel_id)

        # Verify cleanup
        assert tunnel_id not in self.forwarder._tunnels

        # Verify cancel request was sent
        self.forwarder._send_cancel_tcpip_forward_request.assert_called_once_with(
            "", 8080
        )


class TestPortForwardingManager:
    """Test PortForwardingManager class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_transport = Mock(spec=Transport)
        self.manager = PortForwardingManager(self.mock_transport)

    def test_manager_creation(self):
        """Test manager initialization."""
        assert self.manager._transport == self.mock_transport
        assert isinstance(self.manager.local_forwarder, LocalPortForwarder)
        assert isinstance(self.manager.remote_forwarder, RemotePortForwarder)

    def test_create_local_tunnel(self):
        """Test creating local tunnel through manager."""
        with patch.object(self.manager.local_forwarder, "create_tunnel") as mock_create:
            mock_create.return_value = "tunnel_id"

            result = self.manager.create_local_tunnel(8080, "remote.host", 80)

            assert result == "tunnel_id"
            mock_create.assert_called_once_with(8080, "remote.host", 80, "127.0.0.1")

    def test_create_remote_tunnel(self):
        """Test creating remote tunnel through manager."""
        with patch.object(
            self.manager.remote_forwarder, "create_tunnel"
        ) as mock_create:
            mock_create.return_value = "tunnel_id"

            result = self.manager.create_remote_tunnel(8080, "127.0.0.1", 80)

            assert result == "tunnel_id"
            mock_create.assert_called_once_with(8080, "127.0.0.1", 80, "")

    def test_close_local_tunnel(self):
        """Test closing local tunnel through manager."""
        # Mock local tunnel exists
        mock_tunnel = Mock()
        self.manager.local_forwarder._tunnels["local_tunnel"] = mock_tunnel

        with patch.object(self.manager.local_forwarder, "close_tunnel") as mock_close:
            self.manager.close_tunnel("local_tunnel")
            mock_close.assert_called_once_with("local_tunnel")

    def test_close_remote_tunnel(self):
        """Test closing remote tunnel through manager."""
        # Mock remote tunnel exists
        mock_tunnel = Mock()
        self.manager.remote_forwarder._tunnels["remote_tunnel"] = mock_tunnel

        with patch.object(self.manager.remote_forwarder, "close_tunnel") as mock_close:
            self.manager.close_tunnel("remote_tunnel")
            mock_close.assert_called_once_with("remote_tunnel")

    def test_get_all_tunnels(self):
        """Test getting all tunnels."""
        # Mock tunnels in both forwarders
        local_tunnel = Mock()
        remote_tunnel = Mock()

        with patch.object(self.manager.local_forwarder, "get_tunnels") as mock_local:
            with patch.object(
                self.manager.remote_forwarder, "get_tunnels"
            ) as mock_remote:
                mock_local.return_value = {"local_tunnel": local_tunnel}
                mock_remote.return_value = {"remote_tunnel": remote_tunnel}

                tunnels = self.manager.get_all_tunnels()

                assert "local_tunnel" in tunnels
                assert "remote_tunnel" in tunnels
                assert tunnels["local_tunnel"] == local_tunnel
                assert tunnels["remote_tunnel"] == remote_tunnel

    def test_close_all_tunnels(self):
        """Test closing all tunnels."""
        with patch.object(self.manager.local_forwarder, "close_all") as mock_local:
            with patch.object(
                self.manager.remote_forwarder, "close_all"
            ) as mock_remote:
                self.manager.close_all_tunnels()

                mock_local.assert_called_once()
                mock_remote.assert_called_once()

    def test_handle_forwarded_connection(self):
        """Test handling forwarded connection through manager."""
        mock_channel = Mock()

        with patch.object(
            self.manager.remote_forwarder, "handle_forwarded_connection"
        ) as mock_handle:
            self.manager.handle_forwarded_connection(
                mock_channel, ("client.host", 12345), ("", 8080)
            )

            mock_handle.assert_called_once_with(
                mock_channel, ("client.host", 12345), ("", 8080)
            )


class TestSSHClientPortForwarding:
    """Test port forwarding integration with SSHClient."""

    def setup_method(self):
        """Set up test fixtures."""
        self.client = SSHClient()
        self.mock_transport = Mock(spec=Transport)
        self.mock_transport.active = True
        self.mock_transport.authenticated = True
        self.client._transport = self.mock_transport

    def test_create_local_port_forward(self):
        """Test creating local port forward through client."""
        mock_manager = Mock()
        mock_manager.create_local_tunnel.return_value = "tunnel_id"
        self.mock_transport.get_port_forwarding_manager.return_value = mock_manager

        result = self.client.create_local_port_forward(8080, "remote.host", 80)

        assert result == "tunnel_id"
        mock_manager.create_local_tunnel.assert_called_once_with(
            8080, "remote.host", 80, "127.0.0.1"
        )

    def test_create_remote_port_forward(self):
        """Test creating remote port forward through client."""
        mock_manager = Mock()
        mock_manager.create_remote_tunnel.return_value = "tunnel_id"
        self.mock_transport.get_port_forwarding_manager.return_value = mock_manager

        result = self.client.create_remote_port_forward(8080, "127.0.0.1", 80)

        assert result == "tunnel_id"
        mock_manager.create_remote_tunnel.assert_called_once_with(
            8080, "127.0.0.1", 80, ""
        )

    def test_close_port_forward(self):
        """Test closing port forward through client."""
        mock_manager = Mock()
        self.mock_transport.get_port_forwarding_manager.return_value = mock_manager

        self.client.close_port_forward("tunnel_id")

        mock_manager.close_tunnel.assert_called_once_with("tunnel_id")

    def test_get_port_forwards(self):
        """Test getting port forwards through client."""
        mock_tunnel = Mock()
        mock_tunnel.local_addr = ("127.0.0.1", 8080)
        mock_tunnel.remote_addr = ("remote.host", 80)
        mock_tunnel.tunnel_type = "local"
        mock_tunnel.active = True
        mock_tunnel.connections = {"conn1": Mock()}

        mock_manager = Mock()
        mock_manager.get_all_tunnels.return_value = {"tunnel_id": mock_tunnel}
        self.mock_transport.get_port_forwarding_manager.return_value = mock_manager

        result = self.client.get_port_forwards()

        assert "tunnel_id" in result
        tunnel_info = result["tunnel_id"]
        assert tunnel_info["local_addr"] == ("127.0.0.1", 8080)
        assert tunnel_info["remote_addr"] == ("remote.host", 80)
        assert tunnel_info["tunnel_type"] == "local"
        assert tunnel_info["active"] is True
        assert tunnel_info["connections"] == 1

    def test_port_forward_not_connected(self):
        """Test port forwarding operations when not connected."""
        self.client._transport = None

        with pytest.raises(SSHException, match="Not connected to SSH server"):
            self.client.create_local_port_forward(8080, "remote.host", 80)

        with pytest.raises(SSHException, match="Not connected to SSH server"):
            self.client.create_remote_port_forward(8080, "127.0.0.1", 80)

        with pytest.raises(SSHException, match="Not connected to SSH server"):
            self.client.close_port_forward("tunnel_id")

        with pytest.raises(SSHException, match="Not connected to SSH server"):
            self.client.get_port_forwards()

    def test_client_close_with_port_forwards(self):
        """Test client close cleans up port forwards."""
        mock_manager = Mock()
        self.mock_transport.get_port_forwarding_manager.return_value = mock_manager

        self.client.close()

        # Verify port forwarding cleanup was attempted
        mock_manager.close_all_tunnels.assert_called_once()


class TestConcurrentConnections:
    """Test concurrent connection handling."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_transport = Mock(spec=Transport)
        self.forwarder = LocalPortForwarder(self.mock_transport)

    def test_multiple_connections_same_tunnel(self):
        """Test handling multiple connections on same tunnel."""
        # This is a simplified test - in reality we'd need more complex mocking
        # to simulate actual concurrent connections

        tunnel = ForwardingTunnel(
            "test_tunnel", ("127.0.0.1", 8080), ("remote.host", 80), "local"
        )
        tunnel.active = True

        # Simulate multiple connections
        conn1 = {"client_socket": Mock(), "channel": Mock()}
        conn2 = {"client_socket": Mock(), "channel": Mock()}

        tunnel.connections["conn1"] = conn1
        tunnel.connections["conn2"] = conn2

        assert len(tunnel.connections) == 2

        # Close tunnel should close all connections
        tunnel.close()

        assert len(tunnel.connections) == 0
        assert not tunnel.active


if __name__ == "__main__":
    pytest.main([__file__])
