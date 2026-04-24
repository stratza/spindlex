"""
SSH Client Implementation

High-level SSH client for establishing connections, executing commands,
and managing SSH sessions with comprehensive authentication support.
"""

import logging
import socket
from typing import TYPE_CHECKING, Any, Callable, Optional, Union

if TYPE_CHECKING:
    from .sftp_client import SFTPClient

from ..auth.keyboard_interactive import console_handler
from ..crypto.pkey import PKey
from ..exceptions import (
    AuthenticationException,
    BadHostKeyException,
    SSHException,
)
from ..hostkeys.policy import MissingHostKeyPolicy, RejectPolicy
from ..hostkeys.storage import HostKeyStorage
from ..transport.channel import Channel
from ..transport.transport import Transport


class ChannelFile:
    """
    File-like object for SSH channel streams.

    Provides file-like interface for reading from and writing to SSH channels.
    """

    def __init__(self, channel: Channel, mode: str = "r") -> None:
        """
        Initialize channel file.

        Args:
            channel: SSH channel instance
            mode: File mode ('r' for read, 'w' for write, 'stderr' for stderr)
        """
        self._channel = channel
        self._mode = mode
        self._closed = False

    def read(self, size: int = -1) -> bytes:
        """
        Read data from channel.

        Args:
            size: Number of bytes to read (-1 for all until EOF)

        Returns:
            Read data
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if size > 0:
            if self._mode == "stderr":
                return self._channel.recv_stderr(size)
            elif self._mode == "r":
                return self._channel.recv(size)
            else:
                raise ValueError("File not opened for reading")
        else:
            # Read until EOF
            result = bytearray()
            while True:
                try:
                    chunk = (
                        self._channel.recv(8192)
                        if self._mode == "r"
                        else self._channel.recv_stderr(8192)
                    )
                    if not chunk:
                        break
                    result.extend(chunk)
                except Exception as e:
                    # If we have some data, return it. Otherwise, raise the exception.
                    # Also return if the channel is closed.
                    if ("Timeout" in str(e) or "closed" in str(e).lower()) and result:
                        return bytes(result)
                    if "closed" in str(e).lower() and not result:
                        return b""
                    raise
            return bytes(result)

    def write(self, data: Union[str, bytes]) -> int:
        """
        Write data to channel.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if self._mode != "w":
            raise ValueError("File not opened for writing")

        if isinstance(data, str):
            data = data.encode("utf-8")

        return self._channel.send(data)

    def get_exit_status(self) -> int:
        """
        Get command exit status.

        Returns:
            Exit status code, or -1 if not available
        """
        return self._channel.get_exit_status()

    def recv_exit_status(self) -> int:
        """
        Wait for and return command exit status.

        Returns:
            Exit status code
        """
        return self._channel.recv_exit_status()

    def __iter__(self) -> "ChannelFile":
        """
        Make object iterable for line-by-line reading.

        Returns:
            Self as iterator
        """
        return self

    def __next__(self) -> str:
        """
        Read next line from channel.

        Returns:
            Next line of data

        Raises:
            StopIteration: If EOF reached
        """
        line = self.readline()
        if not line:
            raise StopIteration
        return line

    def readline(self) -> str:
        """
        Read a single line from the channel.

        Returns:
            Read line
        """
        result = bytearray()
        while True:
            char = self.read(1)
            if not char:
                break
            result.extend(char)
            if char == b"\n":
                break
        return result.decode("utf-8", errors="replace")

    @property
    def channel(self) -> "Channel":
        """Get underlying SSH channel."""
        return self._channel

    def close(self) -> None:
        """Close the file."""
        self._closed = True

    def __enter__(self) -> "ChannelFile":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()


class SSHClient:
    """
    High-level SSH client interface.

    Provides convenient methods for SSH operations including connection
    establishment, command execution, shell access, and SFTP operations.
    """

    def __init__(self) -> None:
        """Initialize SSH client with default settings."""
        self._transport: Optional[Transport] = None
        self._hostname: Optional[str] = None
        self._port: int = 22
        self._host_key_policy: MissingHostKeyPolicy = RejectPolicy()
        self._host_key_storage = HostKeyStorage()
        self._logger = logging.getLogger(__name__)

    def set_missing_host_key_policy(self, policy: MissingHostKeyPolicy) -> None:
        """
        Set policy for handling unknown host keys.

        Args:
            policy: Host key policy to use for unknown hosts
        """
        self._host_key_policy = policy

    def set_host_key_storage(self, storage: HostKeyStorage) -> None:
        """
        Set host key storage instance.

        Args:
            storage: Host key storage to use
        """
        self._host_key_storage = storage

    def get_host_key_storage(self) -> HostKeyStorage:
        """
        Get host key storage instance.

        Returns:
            Current host key storage
        """
        return self._host_key_storage

    def connect(
        self,
        hostname: str,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        pkey: Optional[PKey] = None,
        key_filename: Optional[str] = None,
        key_password: Optional[str] = None,
        timeout: Optional[float] = None,
        compress: bool = False,
        sock: Optional[socket.socket] = None,
        gss_auth: bool = False,
        gss_kex: bool = False,
        gss_deleg_creds: bool = True,
        gss_host: Optional[str] = None,
        rekey_bytes_limit: Optional[int] = None,
        rekey_time_limit: Optional[float] = None,
    ) -> None:
        """
        Connect to SSH server and authenticate.

        Args:
            hostname: Server hostname or IP address
            port: Server port (default 22)
            username: Username for authentication
            password: Password for authentication
            pkey: Private key for authentication
            key_filename: Path to private key file
            timeout: Connection timeout in seconds
            compress: Whether to enable compression
            sock: Optional existing socket to use
            gss_auth: Whether to use GSSAPI authentication
            gss_kex: Whether to use GSSAPI key exchange
            gss_deleg_creds: Whether to delegate GSSAPI credentials
            gss_host: GSSAPI hostname override
            rekey_bytes_limit: Number of bytes before rekeying (default: 1GB)
            rekey_time_limit: Seconds before rekeying (default: 1 hour)

        Raises:
            SSHException: If connection or authentication fails
        """
        if self._transport and self._transport.active:
            raise SSHException("Already connected")

        self._hostname = hostname
        self._port = port

        try:
            if sock is None:
                # Create socket connection — create_connection resolves IPv4 and IPv6
                self._logger.debug(f"Connecting to {hostname}:{port}")
                try:
                    sock = socket.create_connection(
                        (hostname, port),
                        timeout=timeout if timeout else None,
                    )
                except OSError as e:
                    raise SSHException(f"Connection failed: {e}") from e

                # Enable TCP_NODELAY to reduce latency (Nagle's algorithm)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Create transport
            self._transport = Transport(
                sock,
                rekey_bytes_limit=rekey_bytes_limit,
                rekey_time_limit=rekey_time_limit,
            )

            # Set permanent timeout on transport
            if timeout:
                self._transport.set_timeout(timeout)

            # Start client transport (handshake and key exchange)
            self._transport.start_client(timeout)

            # Verify host key
            self._verify_host_key()

            # Authenticate if credentials provided
            if username:
                self._authenticate(
                    username,
                    password,
                    pkey,
                    key_filename,
                    key_password,
                    gss_auth,
                    gss_host,
                    gss_deleg_creds,
                )

            self._logger.info(f"Successfully connected to {hostname}:{port}")

        except Exception as e:
            # Cleanup on failure
            if self._transport:
                self._transport.close()
                self._transport = None

            if isinstance(
                e, (SSHException, AuthenticationException, BadHostKeyException)
            ):
                raise
            raise SSHException(f"Connection failed: {e}") from e

    def _verify_host_key(self) -> None:
        """
        Verify server host key according to policy.

        Raises:
            BadHostKeyException: If host key verification fails
        """
        if not self._transport:
            raise SSHException("No transport available")

        hostname = self._hostname or "unknown"

        try:
            # Get actual server host key from transport
            server_key = self._transport.get_server_host_key()

            if server_key is None:
                raise SSHException("No host key received from server")

            # Check if we have any known host keys for this hostname
            known_keys = self._host_key_storage.get_all(hostname)

            if not known_keys:
                # No known key - apply missing host key policy
                self._logger.debug(f"No known host key for {hostname}")

                try:
                    self._host_key_policy.missing_host_key(self, hostname, server_key)
                except (BadHostKeyException, SSHException):
                    raise
                except Exception as e:
                    # Policy had an unexpected error - fail closed
                    raise SSHException(f"Host key policy error: {e}") from e
            else:
                # Check if server key matches ANY stored key for this host
                self._logger.debug(f"Found known host key(s) for {hostname}")
                server_key_bytes = server_key.get_public_key_bytes()
                if not any(
                    k.get_public_key_bytes() == server_key_bytes for k in known_keys
                ):
                    raise BadHostKeyException(hostname, server_key, known_keys[0])

        except (BadHostKeyException, SSHException):
            raise
        except Exception as e:
            self._logger.error(f"Host key verification error: {e}")
            raise SSHException(f"Host key verification failed: {e}") from e

    def auth_password(self, username: str, password: str) -> None:
        """
        Authenticate using password.

        Args:
            username: Username for authentication
            password: Password for authentication

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise SSHException("No transport available")

        if not self._transport.auth_password(username, password):
            raise AuthenticationException("Password authentication failed")

    def auth_publickey(
        self,
        username: str,
        pkey: Optional[PKey] = None,
        key_filename: Optional[str] = None,
        password: Optional[str] = None,
    ) -> None:
        """
        Authenticate using public key.

        Args:
            username: Username for authentication
            pkey: Private key instance
            key_filename: Path to private key file
            password: Optional password for encrypted private keys

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise SSHException("No transport available")

        if key_filename:
            pkey = PKey.from_private_key_file(key_filename, password)

        if pkey is None:
            raise AuthenticationException("No private key provided")

        if not self._transport.auth_publickey(username, pkey):
            raise AuthenticationException("Public key authentication failed")

    def auth_keyboard_interactive(
        self,
        username: str,
        handler: Optional[
            Callable[[str, str, list[tuple[str, bool]]], list[str]]
        ] = None,
    ) -> None:
        """
        Authenticate using keyboard-interactive method.

        Args:
            username: Username for authentication
            handler: Callback function to handle prompts.
                     If None, uses console_handler (terminal prompts).

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise SSHException("No transport available")

        if handler is None:
            handler = console_handler

        if not self._transport.auth_keyboard_interactive(username, handler):
            raise AuthenticationException("Keyboard-interactive authentication failed")

    def auth_gssapi(
        self,
        username: str,
        gss_host: Optional[str] = None,
        gss_deleg_creds: bool = False,
    ) -> None:
        """
        Authenticate using GSSAPI (Kerberos).

        Args:
            username: Username for authentication
            gss_host: GSSAPI hostname (optional)
            gss_deleg_creds: Whether to delegate credentials

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise SSHException("No transport available")

        if not self._transport.auth_gssapi(username, gss_host, gss_deleg_creds):
            raise AuthenticationException("GSSAPI authentication failed")

    def _authenticate(
        self,
        username: str,
        password: Optional[str] = None,
        pkey: Optional[PKey] = None,
        key_filename: Optional[str] = None,
        key_password: Optional[str] = None,
        gss_auth: bool = False,
        gss_host: Optional[str] = None,
        gss_deleg_creds: bool = False,
    ) -> None:
        """
        Authenticate with the server.

        Args:
            username: Username for authentication
            password: Password for authentication
            pkey: Private key for authentication
            key_filename: Path to private key file
            key_password: Password for private key file
            gss_auth: Whether to use GSSAPI authentication
            gss_host: GSSAPI hostname override
            gss_deleg_creds: Whether to delegate GSSAPI credentials

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise AuthenticationException("No transport available")

        authenticated = False

        # Try GSSAPI if requested
        if gss_auth and not authenticated:
            try:
                self.auth_gssapi(username, gss_host, gss_deleg_creds)
                authenticated = True
            except Exception as e:
                self._logger.debug(f"GSSAPI authentication failed: {e}")

        # Load key from file if provided
        if key_filename and not pkey and not authenticated:
            try:
                from ..crypto.pkey import PKey

                # Use key_password if provided, otherwise fall back to password
                # (backward compatibility for when password was used for both)
                effective_key_password = (
                    key_password if key_password is not None else password
                )
                pkey = PKey.from_private_key_file(key_filename, effective_key_password)
            except Exception as e:
                self._logger.debug(f"Failed to load key from {key_filename}: {e}")

        # Try public key authentication first if key provided
        if pkey and not authenticated:
            try:
                self._logger.debug(
                    f"Attempting public key authentication for {username}"
                )
                authenticated = self._transport.auth_publickey(username, pkey)
                if authenticated:
                    self._logger.info(
                        f"Public key authentication successful for {username}"
                    )
            except Exception as e:
                self._logger.debug(f"Public key authentication failed: {e}")

        # Try password authentication if password provided and not yet authenticated
        if password and not authenticated:
            try:
                self._logger.debug(f"Attempting password authentication for {username}")
                authenticated = self._transport.auth_password(username, password)
                if authenticated:
                    self._logger.info(
                        f"Password authentication successful for {username}"
                    )
            except Exception as e:
                self._logger.debug(f"Password authentication failed: {e}")

        if not authenticated:
            auth_methods = []
            if pkey:
                auth_methods.append("publickey")
            if password:
                auth_methods.append("password")

            raise AuthenticationException(
                f"Authentication failed for {username} using methods: {', '.join(auth_methods) if auth_methods else 'none'}"
            )

    def exec_command(
        self, command: str, bufsize: int = -1
    ) -> tuple[ChannelFile, ChannelFile, ChannelFile]:
        """
        Execute command on remote server.

        Args:
            command: Command to execute
            bufsize: Buffer size for streams (unused, kept for compatibility)

        Returns:
            Tuple of (stdin, stdout, stderr) file-like objects

        Raises:
            SSHException: If command execution fails
        """
        if not self.is_connected():
            raise SSHException("Not connected to server")

        if not command.strip():
            raise SSHException("Command cannot be empty")

        try:
            if self._transport is None:
                raise SSHException("No transport available")
            # Open a new session channel
            channel = self._transport.open_channel("session")

            # Execute the command
            channel.exec_command(command)

            # Create file-like objects for the streams
            stdin = ChannelFile(channel, "w")
            stdout = ChannelFile(channel, "r")
            stderr = ChannelFile(channel, "stderr")

            self._logger.debug(f"Command executed: {command}")

            return stdin, stdout, stderr

        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to execute command '{command}': {e}") from e

    def invoke_shell(self) -> Channel:
        """
        Start interactive shell session.

        Returns:
            Channel object for shell interaction

        Raises:
            SSHException: If shell invocation fails
        """
        if not self.is_connected():
            raise SSHException("Not connected to server")

        try:
            if self._transport is None:
                raise SSHException("No transport available")
            # Open a new session channel
            channel = self._transport.open_channel("session")

            # Request a pseudo-terminal (usually needed for shell)
            channel.request_pty()

            # Invoke shell
            channel.invoke_shell()

            self._logger.debug("Interactive shell session started")

            return channel

        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to invoke shell: {e}") from e

    def open_sftp(self) -> "SFTPClient":
        """
        Open SFTP session.

        Returns:
            SFTPClient instance for file operations

        Raises:
            SSHException: If SFTP session creation fails
        """
        if not self.is_connected():
            raise SSHException("Not connected to SSH server")

        try:
            from .sftp_client import SFTPClient

            if self._transport is None:
                raise SSHException("No transport available")
            return SFTPClient(self._transport)
        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to open SFTP session: {e}") from e

    def close(self) -> None:
        """Close SSH connection and cleanup resources."""
        try:
            if self._transport:
                self._logger.debug(
                    f"Closing connection to {self._hostname}:{self._port}"
                )

                # Close all port forwarding tunnels
                try:
                    forwarding_manager = self._transport.get_port_forwarding_manager()
                    forwarding_manager.close_all_tunnels()
                except Exception as e:
                    self._logger.warning(f"Error closing port forwarding tunnels: {e}")

                self._transport.close()
                self._transport = None
                self._logger.info(f"Connection closed to {self._hostname}:{self._port}")
        except Exception as e:
            self._logger.warning(f"Error during connection cleanup: {e}")
        finally:
            self._transport = None
            self._hostname = None
            self._port = 22

    def is_connected(self) -> bool:
        """
        Check if client is connected and authenticated.

        Returns:
            True if connected and authenticated, False otherwise
        """
        return (
            self._transport is not None
            and self._transport.active
            and self._transport.authenticated
        )

    def get_transport(self) -> Optional[Transport]:
        """
        Get underlying transport object.

        Returns:
            Transport instance or None if not connected
        """
        return self._transport

    def create_local_port_forward(
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
        if not self.is_connected():
            raise SSHException("Not connected to SSH server")

        try:
            if self._transport is None:
                raise SSHException("No transport available")
            forwarding_manager = self._transport.get_port_forwarding_manager()
            return forwarding_manager.create_local_tunnel(
                local_port, remote_host, remote_port, local_host
            )
        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to create local port forwarding: {e}") from e

    def create_remote_port_forward(
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

        Raises:
            SSHException: If tunnel creation fails
        """
        if not self.is_connected():
            raise SSHException("Not connected to SSH server")

        try:
            if self._transport is None:
                raise SSHException("No transport available")
            forwarding_manager = self._transport.get_port_forwarding_manager()
            return forwarding_manager.create_remote_tunnel(
                remote_port, local_host, local_port, remote_host
            )
        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to create remote port forwarding: {e}") from e

    def close_port_forward(self, tunnel_id: str) -> None:
        """
        Close port forwarding tunnel.

        Args:
            tunnel_id: Tunnel identifier returned by create_*_port_forward

        Raises:
            SSHException: If tunnel closure fails
        """
        if not self.is_connected():
            raise SSHException("Not connected to SSH server")

        try:
            if self._transport is None:
                raise SSHException("No transport available")
            forwarding_manager = self._transport.get_port_forwarding_manager()
            forwarding_manager.close_tunnel(tunnel_id)
        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to close port forwarding tunnel: {e}") from e

    def get_port_forwards(self) -> dict[str, Any]:
        """
        Get all active port forwarding tunnels.

        Returns:
            Dictionary of tunnel ID to tunnel information

        Raises:
            SSHException: If operation fails
        """
        if not self.is_connected():
            raise SSHException("Not connected to SSH server")

        try:
            if self._transport is None:
                raise SSHException("No transport available")
            forwarding_manager = self._transport.get_port_forwarding_manager()
            tunnels = forwarding_manager.get_all_tunnels()

            # Convert to serializable format
            result = {}
            for tunnel_id, tunnel in tunnels.items():
                result[tunnel_id] = {
                    "local_addr": tunnel.local_addr,
                    "remote_addr": tunnel.remote_addr,
                    "tunnel_type": tunnel.tunnel_type,
                    "active": tunnel.active,
                    "connections": len(tunnel.connections),
                }

            return result
        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to get port forwarding tunnels: {e}") from e

    @property
    def is_active(self) -> bool:
        """Check if SSH connection is active."""
        return self._transport is not None and self._transport.active

    def get_host_keys(self) -> HostKeyStorage:
        """Get host key storage instance."""
        return self._host_key_storage

    def __enter__(self) -> "SSHClient":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit with cleanup."""
        self.close()
