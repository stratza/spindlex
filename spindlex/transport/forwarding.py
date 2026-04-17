"""
SSH Port Forwarding Implementation

Provides local and remote port forwarding functionality for SSH connections.
Handles tunnel creation, data relay, and connection management.
"""

import logging
import socket
import threading
import time
from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from .channel import Channel
    from .transport import Transport

from ..exceptions import SSHException
from ..protocol.constants import CHANNEL_DIRECT_TCPIP
from ..protocol.utils import write_string, write_uint32


class ForwardingTunnel:
    """
    Represents a port forwarding tunnel.

    Manages the lifecycle of a forwarding tunnel including
    connection handling and cleanup.
    """

    def __init__(
        self,
        tunnel_id: str,
        local_addr: tuple[str, int],
        remote_addr: tuple[str, int],
        tunnel_type: str,
    ) -> None:
        """
        Initialize forwarding tunnel.

        Args:
            tunnel_id: Unique identifier for the tunnel
            local_addr: Local address (host, port)
            remote_addr: Remote address (host, port)
            tunnel_type: Type of tunnel ('local' or 'remote')
        """
        self.tunnel_id = tunnel_id
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.tunnel_type = tunnel_type
        self.active = False
        self.connections: dict[
            str, dict[str, Union[socket.socket, Channel, tuple[str, int]]]
        ] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__)

    def close(self) -> None:
        """Close tunnel and all active connections."""
        with self._lock:
            self.active = False

            # Close all active connections
            for conn_id, connection in list(self.connections.items()):
                try:
                    # connection is a dict containing 'client_socket' or 'local_socket' and 'channel'
                    for item in connection.values():
                        if isinstance(item, (socket.socket, Channel)):
                            try:
                                item.close()
                            except Exception:
                                pass
                except Exception as e:
                    self._logger.debug(f"Error closing connection {conn_id}: {e}")

            self.connections.clear()
            self._logger.debug(f"Tunnel {self.tunnel_id} closed")


class LocalPortForwarder:
    """
    Handles local port forwarding (SSH -L option).

    Listens on local port and forwards connections through SSH
    to remote destination.
    """

    def __init__(self, transport: "Transport") -> None:
        """
        Initialize local port forwarder.

        Args:
            transport: SSH transport instance
        """
        self._transport: Transport = transport
        self._tunnels: dict[str, ForwardingTunnel] = {}
        self._servers: dict[str, socket.socket] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__)

    def create_tunnel(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        local_host: str = "127.0.0.1",
    ) -> str:
        """
        Create local port forwarding tunnel.

        Args:
            local_port: Local port to listen on
            remote_host: Remote host to connect to
            remote_port: Remote port to connect to
            local_host: Local interface to bind to

        Returns:
            Tunnel ID for management

        Raises:
            SSHException: If tunnel creation fails
        """
        tunnel_id = f"local_{local_host}_{local_port}_{remote_host}_{remote_port}"
        local_addr = (local_host, local_port)
        remote_addr = (remote_host, remote_port)

        with self._lock:
            if tunnel_id in self._tunnels:
                raise SSHException(f"Tunnel already exists: {tunnel_id}")

            try:
                # Create listening socket
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(local_addr)
                server_socket.listen(socket.SOMAXCONN)

                # Create tunnel object
                tunnel = ForwardingTunnel(tunnel_id, local_addr, remote_addr, "local")
                tunnel.active = True

                # Store tunnel and server socket
                self._tunnels[tunnel_id] = tunnel
                self._servers[tunnel_id] = server_socket

                # Start accepting connections in background thread
                accept_thread = threading.Thread(
                    target=self._accept_connections,
                    args=(tunnel_id, server_socket),
                    daemon=True,
                )
                accept_thread.start()

                self._logger.info(
                    f"Local port forwarding started: {local_host}:{local_port} -> {remote_host}:{remote_port}"
                )

                return tunnel_id

            except Exception as e:
                # Cleanup on failure
                if tunnel_id in self._tunnels:
                    del self._tunnels[tunnel_id]
                if tunnel_id in self._servers:
                    try:
                        self._servers[tunnel_id].close()
                    except Exception:
                        pass
                    del self._servers[tunnel_id]

                raise SSHException(
                    f"Failed to create local port forwarding: {e}"
                ) from e

    def _accept_connections(self, tunnel_id: str, server_socket: socket.socket) -> None:
        """
        Accept incoming connections for local port forwarding.

        Args:
            tunnel_id: Tunnel identifier
            server_socket: Server socket to accept connections on
        """
        tunnel = self._tunnels.get(tunnel_id)
        if not tunnel:
            return

        self._logger.debug(f"Accepting connections for tunnel {tunnel_id}")

        while tunnel.active:
            try:
                # Accepted incoming connection
                client_socket, client_addr = server_socket.accept()

                self._logger.debug(
                    f"Accepted connection from {client_addr} for tunnel {tunnel_id}"
                )

                # Handle connection in separate thread
                conn_thread = threading.Thread(
                    target=self._handle_local_connection,
                    args=(tunnel_id, client_socket, client_addr),
                    daemon=True,
                )
                conn_thread.start()

            except OSError as e:
                if tunnel.active:
                    self._logger.error(
                        f"Error accepting connection for tunnel {tunnel_id}: {e}"
                    )
                break
            except Exception as e:
                self._logger.error(
                    f"Unexpected error in accept loop for tunnel {tunnel_id}: {e}"
                )
                break

        self._logger.debug(f"Accept loop ended for tunnel {tunnel_id}")

    def _handle_local_connection(
        self, tunnel_id: str, client_socket: socket.socket, client_addr: tuple[str, int]
    ) -> None:
        """
        Handle individual local port forwarding connection.

        Args:
            tunnel_id: Tunnel identifier
            client_socket: Client socket
            client_addr: Client address
        """
        tunnel = self._tunnels.get(tunnel_id)
        if not tunnel:
            client_socket.close()
            return

        conn_id = f"{tunnel_id}_{client_addr[0]}_{client_addr[1]}_{time.time()}"

        try:
            # Open SSH channel for forwarding
            channel = self._transport.open_channel(
                CHANNEL_DIRECT_TCPIP, dest_addr=tunnel.remote_addr
            )

            # Store connection
            with tunnel._lock:
                tunnel.connections[conn_id] = {
                    "client_socket": client_socket,
                    "channel": channel,
                    "client_addr": client_addr,
                }

            # Start data relay threads
            client_to_channel_thread = threading.Thread(
                target=self._relay_data,
                args=(client_socket, channel, f"{conn_id}_c2s"),
                daemon=True,
            )

            channel_to_client_thread = threading.Thread(
                target=self._relay_data,
                args=(channel, client_socket, f"{conn_id}_s2c"),
                daemon=True,
            )

            client_to_channel_thread.start()
            channel_to_client_thread.start()

            # Wait for threads to complete
            client_to_channel_thread.join()
            channel_to_client_thread.join()

        except Exception as e:
            self._logger.error(f"Error handling local connection {conn_id}: {e}")
        finally:
            # Cleanup connection
            try:
                client_socket.close()
            except Exception:
                pass

            with tunnel._lock:
                if conn_id in tunnel.connections:
                    chan = tunnel.connections[conn_id].get("channel")
                    if isinstance(chan, Channel):
                        try:
                            chan.close()
                        except Exception:
                            pass
                    del tunnel.connections[conn_id]

            self._logger.debug(f"Local connection {conn_id} closed")

    def _relay_data(
        self,
        source: Union[socket.socket, "Channel"],
        destination: Union[socket.socket, "Channel"],
        relay_id: str,
    ) -> None:
        """
        Relay data between source and destination.

        Args:
            source: Source to read from (socket or channel)
            destination: Destination to write to (socket or channel)
            relay_id: Identifier for logging
        """
        try:
            while True:
                # Read data from source
                if hasattr(source, "recv"):
                    data = source.recv(8192)
                else:
                    # Assume it's a socket
                    data = source.recv(8192)

                if not data:
                    break

                # Write data to destination
                if isinstance(destination, socket.socket):
                    destination.sendall(data)
                else:
                    destination.send(data)

        except (OSError, EOFError, SSHException) as e:
            self._logger.info(f"Data relay {relay_id} closed: {e}")
        except Exception as e:
            self._logger.error(f"Unexpected error in data relay {relay_id}: {e}")

    def close_tunnel(self, tunnel_id: str) -> None:
        """
        Close local port forwarding tunnel.

        Args:
            tunnel_id: Tunnel identifier
        """
        with self._lock:
            if tunnel_id not in self._tunnels:
                return

            tunnel = self._tunnels[tunnel_id]
            tunnel.close()

            # Close server socket
            if tunnel_id in self._servers:
                try:
                    self._servers[tunnel_id].close()
                except Exception:
                    pass
                del self._servers[tunnel_id]

            del self._tunnels[tunnel_id]

            self._logger.info(f"Local port forwarding tunnel closed: {tunnel_id}")

    def get_tunnels(self) -> dict[str, ForwardingTunnel]:
        """
        Get all active tunnels.

        Returns:
            Dictionary of tunnel ID to tunnel objects
        """
        with self._lock:
            return self._tunnels.copy()

    def close_all(self) -> None:
        """Close all local port forwarding tunnels."""
        with self._lock:
            for tunnel_id in list(self._tunnels.keys()):
                self.close_tunnel(tunnel_id)


class RemotePortForwarder:
    """
    Handles remote port forwarding (SSH -R option).

    Requests remote server to listen on port and forward
    connections back through SSH to local destination.
    """

    def __init__(self, transport: "Transport") -> None:
        """
        Initialize remote port forwarder.

        Args:
            transport: SSH transport instance
        """
        self._transport: Transport = transport
        self._tunnels: dict[str, ForwardingTunnel] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__)

    def create_tunnel(
        self, remote_port: int, local_host: str, local_port: int, remote_host: str = ""
    ) -> str:
        """
        Create remote port forwarding tunnel.

        Args:
            remote_port: Remote port to listen on
            local_host: Local host to connect to
            local_port: Local port to connect to
            remote_host: Remote interface to bind to (empty for all interfaces)

        Returns:
            Tunnel ID for management

        Raises:
            SSHException: If tunnel creation fails
        """
        tunnel_id = f"remote_{remote_host}_{remote_port}_{local_host}_{local_port}"
        remote_addr = (remote_host, remote_port)
        local_addr = (local_host, local_port)

        with self._lock:
            if tunnel_id in self._tunnels:
                raise SSHException(f"Tunnel already exists: {tunnel_id}")

            try:
                # Send global request for remote port forwarding
                success = self._send_tcpip_forward_request(remote_host, remote_port)

                if not success:
                    raise SSHException(
                        "Remote port forwarding request denied by server"
                    )

                # Create tunnel object
                tunnel = ForwardingTunnel(tunnel_id, local_addr, remote_addr, "remote")
                tunnel.active = True

                # Store tunnel
                self._tunnels[tunnel_id] = tunnel

                self._logger.info(
                    f"Remote port forwarding started: {remote_host}:{remote_port} -> {local_host}:{local_port}"
                )

                return tunnel_id

            except Exception as e:
                # Cleanup on failure
                if tunnel_id in self._tunnels:
                    del self._tunnels[tunnel_id]

                raise SSHException(
                    f"Failed to create remote port forwarding: {e}"
                ) from e

    def _send_tcpip_forward_request(self, bind_address: str, bind_port: int) -> bool:
        """
        Send tcpip-forward global request.

        Args:
            bind_address: Address to bind on remote server
            bind_port: Port to bind on remote server

        Returns:
            True if request was accepted, False otherwise
        """
        try:
            # Build request data
            request_data = bytearray()
            request_data.extend(write_string(bind_address))
            request_data.extend(write_uint32(bind_port))

            # Send global request through transport
            return bool(
                self._transport._send_global_request(
                    "tcpip-forward", True, bytes(request_data)
                )
            )

        except Exception as e:
            self._logger.error(f"Error sending tcpip-forward request: {e}")
            return False

    def handle_forwarded_connection(
        self,
        channel: "Channel",
        origin_addr: tuple[str, int],
        dest_addr: tuple[str, int],
    ) -> None:
        """
        Handle incoming forwarded connection from remote server.

        Args:
            channel: SSH channel for the forwarded connection
            origin_addr: Origin address of the connection
            dest_addr: Destination address (should match our tunnel)
        """
        # Find matching tunnel
        tunnel = None
        for t in self._tunnels.values():
            if t.remote_addr[1] == dest_addr[1]:  # Match by port
                tunnel = t
                break

        if not tunnel or not tunnel.active:
            self._logger.warning(
                f"No active tunnel found for forwarded connection to {dest_addr}"
            )
            channel.close()
            return

        conn_id = f"{tunnel.tunnel_id}_{origin_addr[0]}_{origin_addr[1]}_{time.time()}"

        try:
            # Connect to local destination
            local_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            local_socket.connect(tunnel.local_addr)

            # Store connection
            with tunnel._lock:
                tunnel.connections[conn_id] = {
                    "local_socket": local_socket,
                    "channel": channel,
                    "origin_addr": origin_addr,
                }

            # Start data relay threads
            local_to_channel_thread = threading.Thread(
                target=self._relay_data,
                args=(local_socket, channel, f"{conn_id}_l2s"),
                daemon=True,
            )

            channel_to_local_thread = threading.Thread(
                target=self._relay_data,
                args=(channel, local_socket, f"{conn_id}_s2l"),
                daemon=True,
            )

            local_to_channel_thread.start()
            channel_to_local_thread.start()

            # Wait for threads to complete
            local_to_channel_thread.join()
            channel_to_local_thread.join()

        except Exception as e:
            self._logger.error(
                f"Error handling remote forwarded connection {conn_id}: {e}"
            )
        finally:
            # Cleanup connection
            try:
                local_socket.close()
            except Exception:
                pass

            with tunnel._lock:
                if conn_id in tunnel.connections:
                    del tunnel.connections[conn_id]

            self._logger.debug(f"Remote forwarded connection {conn_id} closed")

    def _relay_data(
        self,
        source: Union[socket.socket, "Channel"],
        destination: Union[socket.socket, "Channel"],
        relay_id: str,
    ) -> None:
        """
        Relay data between source and destination.

        Args:
            source: Source to read from (socket or channel)
            destination: Destination to write to (socket or channel)
            relay_id: Identifier for logging
        """
        try:
            while True:
                # Read data from source
                if hasattr(source, "recv"):
                    data = source.recv(8192)
                else:
                    # Assume it's a socket
                    data = source.recv(8192)

                if not data:
                    break

                # Write data to destination
                if isinstance(destination, socket.socket):
                    destination.sendall(data)
                else:
                    destination.send(data)

        except (OSError, EOFError, SSHException) as e:
            self._logger.info(f"Data relay {relay_id} closed: {e}")
        except Exception as e:
            self._logger.error(f"Unexpected error in data relay {relay_id}: {e}")

    def close_tunnel(self, tunnel_id: str) -> None:
        """
        Close remote port forwarding tunnel.

        Args:
            tunnel_id: Tunnel identifier
        """
        with self._lock:
            if tunnel_id not in self._tunnels:
                return

            tunnel = self._tunnels[tunnel_id]

            # Send cancel request to server
            try:
                self._send_cancel_tcpip_forward_request(
                    tunnel.remote_addr[0], tunnel.remote_addr[1]
                )
            except Exception as e:
                self._logger.warning(
                    f"Error sending cancel request for tunnel {tunnel_id}: {e}"
                )

            tunnel.close()
            del self._tunnels[tunnel_id]

            self._logger.info(f"Remote port forwarding tunnel closed: {tunnel_id}")

    def _send_cancel_tcpip_forward_request(
        self, bind_address: str, bind_port: int
    ) -> bool:
        """
        Send cancel-tcpip-forward global request.

        Args:
            bind_address: Address that was bound on remote server
            bind_port: Port that was bound on remote server

        Returns:
            True if request was accepted, False otherwise
        """
        try:
            # Build request data
            request_data = bytearray()
            request_data.extend(write_string(bind_address))
            request_data.extend(write_uint32(bind_port))

            # Send global request through transport
            return bool(
                self._transport._send_global_request(
                    "cancel-tcpip-forward", True, bytes(request_data)
                )
            )

        except Exception as e:
            self._logger.error(f"Error sending cancel-tcpip-forward request: {e}")
            return False

    def get_tunnels(self) -> dict[str, ForwardingTunnel]:
        """
        Get all active tunnels.

        Returns:
            Dictionary of tunnel ID to tunnel objects
        """
        with self._lock:
            return self._tunnels.copy()

    def close_all(self) -> None:
        """Close all remote port forwarding tunnels."""
        with self._lock:
            for tunnel_id in list(self._tunnels.keys()):
                self.close_tunnel(tunnel_id)


class PortForwardingManager:
    """
    Manages both local and remote port forwarding.

    Provides unified interface for creating and managing
    port forwarding tunnels.
    """

    def __init__(self, transport: "Transport") -> None:
        """
        Initialize port forwarding manager.

        Args:
            transport: SSH transport instance
        """
        self._transport: Transport = transport
        self.local_forwarder = LocalPortForwarder(transport)
        self.remote_forwarder = RemotePortForwarder(transport)
        self._logger = logging.getLogger(__name__)

    def create_local_tunnel(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        local_host: str = "127.0.0.1",
    ) -> str:
        """
        Create local port forwarding tunnel.

        Args:
            local_port: Local port to listen on
            remote_host: Remote host to connect to
            remote_port: Remote port to connect to
            local_host: Local interface to bind to

        Returns:
            Tunnel ID for management
        """
        return self.local_forwarder.create_tunnel(
            local_port, remote_host, remote_port, local_host
        )

    def create_remote_tunnel(
        self, remote_port: int, local_host: str, local_port: int, remote_host: str = ""
    ) -> str:
        """
        Create remote port forwarding tunnel.

        Args:
            remote_port: Remote port to listen on
            local_host: Local host to connect to
            local_port: Local port to connect to
            remote_host: Remote interface to bind to

        Returns:
            Tunnel ID for management
        """
        return self.remote_forwarder.create_tunnel(
            remote_port, local_host, local_port, remote_host
        )

    def close_tunnel(self, tunnel_id: str) -> None:
        """
        Close port forwarding tunnel.

        Args:
            tunnel_id: Tunnel identifier
        """
        # Try local forwarder first
        if tunnel_id in self.local_forwarder.get_tunnels():
            self.local_forwarder.close_tunnel(tunnel_id)
        elif tunnel_id in self.remote_forwarder.get_tunnels():
            self.remote_forwarder.close_tunnel(tunnel_id)
        else:
            self._logger.warning(f"Tunnel not found: {tunnel_id}")

    def get_all_tunnels(self) -> dict[str, ForwardingTunnel]:
        """
        Get all active tunnels (local and remote).

        Returns:
            Dictionary of tunnel ID to tunnel objects
        """
        tunnels = {}
        tunnels.update(self.local_forwarder.get_tunnels())
        tunnels.update(self.remote_forwarder.get_tunnels())
        return tunnels

    def close_all_tunnels(self) -> None:
        """Close all port forwarding tunnels."""
        self.local_forwarder.close_all()
        self.remote_forwarder.close_all()

    def handle_forwarded_connection(
        self,
        channel: "Channel",
        origin_addr: tuple[str, int],
        dest_addr: tuple[str, int],
    ) -> None:
        """
        Handle incoming forwarded connection from remote server.

        Args:
            channel: SSH channel for the forwarded connection
            origin_addr: Origin address of the connection
            dest_addr: Destination address
        """
        self.remote_forwarder.handle_forwarded_connection(
            channel, origin_addr, dest_addr
        )
