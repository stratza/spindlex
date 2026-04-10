"""
SSH Server Implementation

Base class for SSH server implementations providing client authentication,
channel management, and server-side SSH operations.
"""

import socket
import threading
import time
from typing import Any, Dict, List, Optional

from ..crypto.pkey import PKey
from ..exceptions import AuthenticationException, SSHException, TransportException
from ..protocol.constants import (
    AUTH_FAILED,
    AUTH_PARTIAL,
    AUTH_SUCCESSFUL,
    CHANNEL_SESSION,
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
)
from ..transport.channel import Channel
from ..transport.transport import Transport


class SSHServer:
    """
    Base SSH server implementation.

    Provides hooks for authentication, authorization, and channel management
    that can be overridden to implement custom SSH server behavior.
    """

    def __init__(self) -> None:
        """Initialize SSH server with default settings."""
        self._server_key: Optional[PKey] = None
        self._transport: Optional[Transport] = None
        self._authenticated_users: Dict[str, bool] = {}
        self._lock = threading.Lock()

    def set_server_key(self, server_key: PKey) -> None:
        """
        Set the server's host key.

        Args:
            server_key: Server's private key for host authentication
        """
        self._server_key = server_key

    def get_server_key(self) -> Optional[PKey]:
        """
        Get the server's host key.

        Returns:
            Server's private key or None if not set
        """
        return self._server_key

    def start_server(
        self, sock: socket.socket, timeout: Optional[float] = None
    ) -> Transport:
        """
        Start server-side transport and handshake handling.

        Args:
            sock: Connected client socket
            timeout: Handshake timeout in seconds

        Returns:
            Transport instance for the connection

        Raises:
            TransportException: If server key not set or handshake fails
        """
        if self._server_key is None:
            raise TransportException("Server key must be set before starting server")

        # Create transport for this connection
        transport = Transport(sock)

        # Start server-side transport
        transport.start_server(self._server_key, timeout)

        # Set server interface for authentication callbacks
        transport.set_server_interface(self)

        self._transport = transport
        return transport

    def check_auth_password(self, username: str, password: str) -> int:
        """
        Check password authentication.

        Override this method to implement custom password authentication logic.
        Default implementation rejects all password authentication attempts.

        Args:
            username: Username attempting authentication
            password: Password provided for authentication

        Returns:
            Authentication result code:
            - AUTH_SUCCESSFUL: Authentication successful
            - AUTH_FAILED: Authentication failed
            - AUTH_PARTIAL: Partial authentication (more methods required)
        """
        # Default implementation rejects all password authentication
        return AUTH_FAILED

    def check_auth_publickey(self, username: str, key: PKey) -> int:
        """
        Check public key authentication.

        Override this method to implement custom public key authentication logic.
        Default implementation rejects all public key authentication attempts.

        Args:
            username: Username attempting authentication
            key: Public key for authentication

        Returns:
            Authentication result code:
            - AUTH_SUCCESSFUL: Authentication successful
            - AUTH_FAILED: Authentication failed
            - AUTH_PARTIAL: Partial authentication (more methods required)
        """
        # Default implementation rejects all public key authentication
        return AUTH_FAILED

    def check_auth_keyboard_interactive(self, username: str, submethods: str) -> int:
        """
        Check keyboard-interactive authentication.

        Override this method to implement custom keyboard-interactive authentication.
        Default implementation rejects all keyboard-interactive authentication attempts.

        Args:
            username: Username attempting authentication
            submethods: Comma-separated list of submethods

        Returns:
            Authentication result code:
            - AUTH_SUCCESSFUL: Authentication successful
            - AUTH_FAILED: Authentication failed
            - AUTH_PARTIAL: Partial authentication (more methods required)
        """
        # Default implementation rejects all keyboard-interactive authentication
        return AUTH_FAILED

    def get_allowed_auths(self, username: str) -> List[str]:
        """
        Get list of allowed authentication methods for a user.

        Override this method to customize allowed authentication methods per user.
        Default implementation allows password and publickey authentication.

        Args:
            username: Username requesting authentication methods

        Returns:
            List of allowed authentication method names
        """
        return ["password", "publickey"]

    def check_auth_gssapi_with_mic(
        self, username: str, gss_authenticated: int, cc_file: str
    ) -> int:
        """
        Check GSSAPI authentication with MIC.

        Override this method to implement GSSAPI authentication.
        Default implementation rejects all GSSAPI authentication attempts.

        Args:
            username: Username attempting authentication
            gss_authenticated: GSSAPI authentication status
            cc_file: Credentials cache file

        Returns:
            Authentication result code
        """
        # Default implementation rejects GSSAPI authentication
        return AUTH_FAILED

    def check_channel_request(self, kind: str, chanid: int) -> int:
        """
        Check channel creation request.

        Override this method to implement custom channel authorization logic.
        Default implementation allows session channels and rejects others.

        Args:
            kind: Type of channel requested (e.g., "session", "direct-tcpip")
            chanid: Channel ID for the request

        Returns:
            SSH channel open result code:
            - 0: Success (SSH_OPEN_CONNECT_SUCCESS)
            - 1: Administratively prohibited
            - 2: Connect failed
            - 3: Unknown channel type
            - 4: Resource shortage
        """
        # Default implementation allows session channels
        if kind == CHANNEL_SESSION:
            return 0  # SSH_OPEN_CONNECT_SUCCESS
        else:
            return SSH_OPEN_UNKNOWN_CHANNEL_TYPE

    def check_channel_exec_request(self, channel: Channel, command: bytes) -> bool:
        """
        Check command execution request.

        Override this method to implement custom command execution authorization.
        Default implementation rejects all command execution requests.

        Args:
            channel: Channel for command execution
            command: Command to be executed

        Returns:
            True if command execution is allowed, False otherwise
        """
        # Default implementation rejects all command execution
        return False

    def check_channel_shell_request(self, channel: Channel) -> bool:
        """
        Check shell access request.

        Override this method to implement custom shell access authorization.
        Default implementation rejects all shell access requests.

        Args:
            channel: Channel for shell access

        Returns:
            True if shell access is allowed, False otherwise
        """
        # Default implementation rejects all shell access
        return False

    def check_channel_subsystem_request(self, channel: Channel, name: str) -> bool:
        """
        Check subsystem request.

        Override this method to implement custom subsystem authorization.
        Default implementation rejects all subsystem requests.

        Args:
            channel: Channel for subsystem
            name: Name of the subsystem (e.g., "sftp")

        Returns:
            True if subsystem access is allowed, False otherwise
        """
        # Default implementation rejects all subsystem requests
        return False

    def check_channel_pty_request(
        self,
        channel: Channel,
        term: str,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
        modes: bytes,
    ) -> bool:
        """
        Check PTY allocation request.

        Override this method to implement custom PTY allocation authorization.
        Default implementation allows PTY allocation.

        Args:
            channel: Channel requesting PTY
            term: Terminal type (e.g., "xterm")
            width: Terminal width in characters
            height: Terminal height in characters
            pixelwidth: Terminal width in pixels
            pixelheight: Terminal height in pixels
            modes: Terminal modes

        Returns:
            True if PTY allocation is allowed, False otherwise
        """
        # Default implementation allows PTY allocation
        return True

    def check_channel_window_change_request(
        self,
        channel: Channel,
        width: int,
        height: int,
        pixelwidth: int,
        pixelheight: int,
    ) -> bool:
        """
        Check window change request.

        Override this method to implement custom window change authorization.
        Default implementation allows window changes.

        Args:
            channel: Channel requesting window change
            width: New terminal width in characters
            height: New terminal height in characters
            pixelwidth: New terminal width in pixels
            pixelheight: New terminal height in pixels

        Returns:
            True if window change is allowed, False otherwise
        """
        # Default implementation allows window changes
        return True

    def check_channel_x11_request(
        self,
        channel: Channel,
        single_connection: bool,
        auth_protocol: str,
        auth_cookie: bytes,
        screen_number: int,
    ) -> bool:
        """
        Check X11 forwarding request.

        Override this method to implement custom X11 forwarding authorization.
        Default implementation rejects X11 forwarding.

        Args:
            channel: Channel requesting X11 forwarding
            single_connection: Whether to allow only single connection
            auth_protocol: X11 authentication protocol
            auth_cookie: X11 authentication cookie
            screen_number: X11 screen number

        Returns:
            True if X11 forwarding is allowed, False otherwise
        """
        # Default implementation rejects X11 forwarding
        return False

    def check_channel_env_request(
        self, channel: Channel, name: str, value: str
    ) -> bool:
        """
        Check environment variable setting request.

        Override this method to implement custom environment variable authorization.
        Default implementation rejects environment variable setting.

        Args:
            channel: Channel requesting environment variable
            name: Environment variable name
            value: Environment variable value

        Returns:
            True if environment variable setting is allowed, False otherwise
        """
        # Default implementation rejects environment variable setting
        return False

    def get_banner(self) -> Optional[str]:
        """
        Get authentication banner message.

        Override this method to provide a custom banner message displayed
        to clients before authentication.

        Returns:
            Banner message string or None for no banner
        """
        return None

    def check_global_request(self, kind: str, msg: Any) -> bool:
        """
        Check global request.

        Override this method to implement custom global request handling.
        Default implementation rejects all global requests.

        Args:
            kind: Type of global request
            msg: Request message data

        Returns:
            True if global request is allowed, False otherwise
        """
        # Default implementation rejects all global requests
        return False

    # Server-side channel management methods

    def get_active_channels(self) -> List[Channel]:
        """
        Get list of active channels.

        Returns:
            List of active Channel instances
        """
        if self._transport is None:
            return []

        with self._lock:
            return list(self._transport._channels.values())

    def get_channel_count(self) -> int:
        """
        Get number of active channels.

        Returns:
            Number of active channels
        """
        if self._transport is None:
            return 0

        with self._lock:
            return len(self._transport._channels)

    def close_channel(self, channel: Channel) -> None:
        """
        Close a specific channel.

        Args:
            channel: Channel to close
        """
        try:
            channel.close()
        except Exception:
            # Ignore errors during channel close
            pass

    def close_all_channels(self) -> None:
        """Close all active channels."""
        channels = self.get_active_channels()
        for channel in channels:
            self.close_channel(channel)

    def is_channel_authorized(self, channel: Channel, username: str) -> bool:
        """
        Check if a channel is authorized for a specific user.

        Override this method to implement custom channel authorization logic.
        Default implementation allows all channels for authenticated users.

        Args:
            channel: Channel to check
            username: Username to check authorization for

        Returns:
            True if channel is authorized for the user
        """
        # Default implementation allows all channels for authenticated users
        return (
            username in self._authenticated_users
            and self._authenticated_users[username]
        )

    def on_channel_opened(self, channel: Channel) -> None:
        """
        Called when a new channel is opened.

        Override this method to implement custom channel open handling.

        Args:
            channel: Newly opened channel
        """
        # Default implementation does nothing
        pass

    def on_channel_closed(self, channel: Channel) -> None:
        """
        Called when a channel is closed.

        Override this method to implement custom channel close handling.

        Args:
            channel: Closed channel
        """
        # Default implementation does nothing
        pass

    def on_authentication_successful(self, username: str, method: str) -> None:
        """
        Called when authentication is successful.

        Override this method to implement custom authentication success handling.

        Args:
            username: Successfully authenticated username
            method: Authentication method used
        """
        with self._lock:
            self._authenticated_users[username] = True

    def on_authentication_failed(self, username: str, method: str) -> None:
        """
        Called when authentication fails.

        Override this method to implement custom authentication failure handling.

        Args:
            username: Username that failed authentication
            method: Authentication method that failed
        """
        # Default implementation does nothing
        pass


class SSHServerManager:
    """
    SSH Server Manager for handling multiple client connections.

    Manages server lifecycle, multi-client connections, and resource cleanup.
    """

    def __init__(
        self,
        server_interface: SSHServer,
        server_key: PKey,
        bind_address: str = "0.0.0.0",
        port: int = 22,
    ) -> None:
        """
        Initialize SSH server manager.

        Args:
            server_interface: SSHServer instance for handling client requests
            server_key: Server's private key for host authentication
            bind_address: Address to bind server socket
            port: Port to bind server socket
        """
        self._server_interface = server_interface
        self._server_key = server_key
        self._bind_address = bind_address
        self._port = port

        self._server_socket: Optional[socket.socket] = None
        self._running = False
        self._connections: Dict[str, Transport] = {}  # connection_id -> transport
        self._connection_threads: Dict[str, threading.Thread] = {}
        self._lock = threading.RLock()
        self._accept_thread: Optional[threading.Thread] = None

        # Connection limits and timeouts
        self._max_connections = 100
        self._connection_timeout = 30.0
        self._auth_timeout = 30.0

        # Statistics
        self._total_connections = 0
        self._active_connections = 0
        self._failed_connections = 0

    def set_max_connections(self, max_connections: int) -> None:
        """
        Set maximum number of concurrent connections.

        Args:
            max_connections: Maximum number of concurrent connections
        """
        self._max_connections = max_connections

    def set_connection_timeout(self, timeout: float) -> None:
        """
        Set connection timeout.

        Args:
            timeout: Connection timeout in seconds
        """
        self._connection_timeout = timeout

    def set_auth_timeout(self, timeout: float) -> None:
        """
        Set authentication timeout.

        Args:
            timeout: Authentication timeout in seconds
        """
        self._auth_timeout = timeout

    def start_server(self) -> None:
        """
        Start SSH server and begin accepting connections.

        Raises:
            TransportException: If server fails to start
        """
        with self._lock:
            if self._running:
                raise TransportException("Server is already running")

            try:
                # Create and bind server socket
                self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_socket.setsockopt(
                    socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
                )
                self._server_socket.bind((self._bind_address, self._port))
                self._server_socket.listen(5)

                self._running = True

                # Start accept thread
                self._accept_thread = threading.Thread(
                    target=self._accept_connections,
                    name="SSHServer-Accept",
                    daemon=True,
                )
                self._accept_thread.start()

            except Exception as e:
                self._cleanup_server_socket()
                raise TransportException(f"Failed to start SSH server: {e}")

    def stop_server(self) -> None:
        """
        Stop SSH server and close all connections.
        """
        with self._lock:
            if not self._running:
                return

            self._running = False

        # Close server socket to stop accepting new connections
        self._cleanup_server_socket()

        # Wait for accept thread to finish
        if self._accept_thread and self._accept_thread.is_alive():
            self._accept_thread.join(timeout=5.0)

        # Close all active connections
        self._close_all_connections()

    def _accept_connections(self) -> None:
        """Accept incoming connections in a loop."""
        while self._running:
            try:
                if self._server_socket is None:
                    break

                # Accept new connection
                client_socket, client_address = self._server_socket.accept()

                # Check connection limits
                with self._lock:
                    if len(self._connections) >= self._max_connections:
                        client_socket.close()
                        continue

                    self._total_connections += 1
                    connection_id = f"{client_address[0]}:{client_address[1]}:{self._total_connections}"

                # Handle connection in separate thread
                connection_thread = threading.Thread(
                    target=self._handle_connection,
                    args=(client_socket, client_address, connection_id),
                    name=f"SSHServer-{connection_id}",
                    daemon=True,
                )

                with self._lock:
                    self._connection_threads[connection_id] = connection_thread

                connection_thread.start()

            except Exception as e:
                if self._running:
                    # Log error but continue accepting connections
                    pass
                else:
                    # Server is shutting down
                    break

    def _handle_connection(
        self, client_socket: socket.socket, client_address: tuple, connection_id: str
    ) -> None:
        """
        Handle individual client connection.

        Args:
            client_socket: Client socket
            client_address: Client address tuple
            connection_id: Unique connection identifier
        """
        transport = None
        try:
            with self._lock:
                self._active_connections += 1

            # Set socket timeout
            client_socket.settimeout(self._connection_timeout)

            # Start server transport
            transport = self._server_interface.start_server(
                client_socket, self._auth_timeout
            )

            with self._lock:
                self._connections[connection_id] = transport

            # Keep connection alive until it's closed
            while transport.active:
                time.sleep(0.1)

        except Exception as e:
            with self._lock:
                self._failed_connections += 1

        finally:
            # Cleanup connection
            self._cleanup_connection(connection_id, transport, client_socket)

    def _cleanup_connection(
        self,
        connection_id: str,
        transport: Optional[Transport],
        client_socket: socket.socket,
    ) -> None:
        """
        Clean up connection resources.

        Args:
            connection_id: Connection identifier
            transport: Transport instance (may be None)
            client_socket: Client socket
        """
        try:
            # Close transport
            if transport:
                transport.close()

            # Close socket
            client_socket.close()

        except Exception:
            # Ignore cleanup errors
            pass

        finally:
            with self._lock:
                # Remove from active connections
                self._connections.pop(connection_id, None)
                self._connection_threads.pop(connection_id, None)
                self._active_connections = max(0, self._active_connections - 1)

    def _close_all_connections(self) -> None:
        """Close all active connections."""
        connections_to_close = []

        with self._lock:
            connections_to_close = list(self._connections.items())

        # Close connections outside of lock to avoid deadlock
        for connection_id, transport in connections_to_close:
            try:
                transport.close()
            except Exception:
                pass

        # Wait for connection threads to finish
        threads_to_join = []
        with self._lock:
            threads_to_join = list(self._connection_threads.values())

        for thread in threads_to_join:
            if thread.is_alive():
                thread.join(timeout=5.0)

        with self._lock:
            self._connections.clear()
            self._connection_threads.clear()
            self._active_connections = 0

    def _cleanup_server_socket(self) -> None:
        """Clean up server socket."""
        if self._server_socket:
            try:
                self._server_socket.close()
            except Exception:
                pass
            finally:
                self._server_socket = None

    def is_running(self) -> bool:
        """
        Check if server is running.

        Returns:
            True if server is running
        """
        return self._running

    def get_connection_count(self) -> int:
        """
        Get number of active connections.

        Returns:
            Number of active connections
        """
        with self._lock:
            return len(self._connections)

    def get_connection_stats(self) -> Dict[str, int]:
        """
        Get connection statistics.

        Returns:
            Dictionary with connection statistics
        """
        with self._lock:
            return {
                "total_connections": self._total_connections,
                "active_connections": self._active_connections,
                "failed_connections": self._failed_connections,
                "max_connections": self._max_connections,
            }

    def get_active_connections(self) -> List[str]:
        """
        Get list of active connection IDs.

        Returns:
            List of active connection identifiers
        """
        with self._lock:
            return list(self._connections.keys())

    def close_connection(self, connection_id: str) -> bool:
        """
        Close a specific connection.

        Args:
            connection_id: Connection identifier to close

        Returns:
            True if connection was found and closed
        """
        with self._lock:
            transport = self._connections.get(connection_id)
            if transport:
                try:
                    transport.close()
                    return True
                except Exception:
                    pass

        return False
