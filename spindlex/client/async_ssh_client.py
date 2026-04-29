"""
Async SSH Client Implementation

Provides asynchronous SSH client functionality for high-concurrency applications.
"""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import TYPE_CHECKING, Any, Callable

if TYPE_CHECKING:
    pass

from ..exceptions import AuthenticationException, BadHostKeyException, SSHException
from ..hostkeys.policy import MissingHostKeyPolicy, RejectPolicy
from ..hostkeys.storage import HostKeyStorage
from ..transport.async_transport import AsyncTransport
from .async_sftp_client import AsyncSFTPClient


class AsyncSSHClient:
    """
    Async SSH client for establishing SSH connections and executing commands.

    Provides asynchronous versions of all SSH client operations for use
    in async/await applications and high-concurrency scenarios.
    """

    def __init__(self) -> None:
        """Initialize async SSH client."""
        self._transport: AsyncTransport | None = None
        self._hostname: str | None = None
        self._port: int = 22
        self._username: str | None = None
        self._host_key_policy: MissingHostKeyPolicy = RejectPolicy()
        self._host_key_storage = HostKeyStorage()
        self._logger = logging.getLogger(__name__)
        self._connected = False

    async def connect(
        self,
        hostname: str,
        port: int = 22,
        username: str | None = None,
        password: str | None = None,
        pkey: Any | None = None,
        key_filename: str | list[str] | None = None,
        timeout: float | None = None,
        compress: bool = False,
        sock: Any | None = None,
        gss_auth: bool = False,
        gss_kex: bool = False,
        gss_deleg_creds: bool = True,
        gss_host: str | None = None,
        rekey_bytes_limit: int | None = None,
        rekey_time_limit: int | None = None,
    ) -> None:
        """
        Connect to SSH server asynchronously.

        Args:
            hostname: Server hostname or IP address
            port: Server port (default: 22)
            username: Username for authentication
            password: Password for authentication
            pkey: Private key for authentication
            key_filename: Path to private key file(s)
            timeout: Connection timeout in seconds
            compress: Enable compression
            sock: Optional existing socket or channel to use
            rekey_bytes_limit: Number of bytes before rekeying (default: 1GB)
            rekey_time_limit: Seconds before rekeying (default: 1 hour)
            gss_auth: Use GSSAPI authentication
            gss_kex: Use GSSAPI key exchange
            gss_deleg_creds: Delegate GSSAPI credentials
            gss_host: GSSAPI hostname override

        Raises:
            SSHException: If connection fails
            AuthenticationException: If authentication fails
        """
        if self._connected:
            raise SSHException("Already connected")

        # Validate port
        if not (0 < port <= 65535):
            raise SSHException(f"Invalid port number: {port}")

        try:
            if sock is None:
                # Create socket connection
                sock, reader, writer = await self._create_connection(
                    hostname, port, timeout
                )
            else:
                # If sock is provided, we need to wrap it if it's a raw socket
                # In asyncio, we usually need reader/writer.
                # If it's a SpindleX Channel, it might need special handling.
                if hasattr(sock, "makefile"):  # Likely a socket-like object
                    reader, writer = await asyncio.open_connection(sock=sock)
                else:
                    # Assume it's already a pair or handled by transport
                    reader, writer = None, None

            # Create async transport
            self._transport = AsyncTransport(
                sock,
                rekey_bytes_limit=rekey_bytes_limit,
                rekey_time_limit=rekey_time_limit,
            )

            # Use connect_existing helper to set reader/writer safely
            if reader and writer:
                await self._transport.connect_existing(reader, writer)

            # Start client transport
            await self._transport.start_client(timeout)

            # Store connection info before host key verification so hostname is available
            self._hostname = hostname
            self._port = port
            self._username = username
            self._connected = True

            # Verify host key
            self._verify_host_key()

            # Perform authentication if credentials provided
            if username:
                await self._authenticate(
                    username,
                    password=password,
                    pkey=pkey,
                    key_filename=key_filename,
                    gss_auth=gss_auth,
                    gss_host=gss_host,
                    gss_deleg_creds=gss_deleg_creds,
                )

        except Exception as e:
            if self._transport:
                await self._transport.close()
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
        server_key = None

        try:
            # Get actual server host key from transport
            server_key = self._transport.get_server_host_key()

            if server_key is None:
                raise SSHException("No server host key received")

            # Check all stored keys for this hostname (MED-12)
            known_keys = self._host_key_storage.get_all(hostname)

            if not known_keys:
                # No known key - apply missing host key policy
                self._logger.debug(f"No known host key for {hostname}")

                try:
                    self._host_key_policy.missing_host_key(self, hostname, server_key)
                except BadHostKeyException:
                    # Policy rejected the key
                    raise
                except Exception as e:
                    # Policy had an error but didn't reject
                    self._logger.warning(f"Host key policy error: {e}")
            else:
                # We have known keys - check if any match the server key
                self._logger.debug(f"Found known host key(s) for {hostname}")

                server_key_bytes = server_key.get_public_key_bytes()
                for known_key in known_keys:
                    if known_key.get_public_key_bytes() == server_key_bytes:
                        return  # Matched one of the stored keys

                # No match found — key mismatch
                raise BadHostKeyException(hostname, server_key, known_keys[0])

        except BadHostKeyException:
            raise
        except SSHException:
            raise
        except Exception as e:
            self._logger.error(f"Host key verification error: {e}")
            raise BadHostKeyException(hostname, server_key)

    async def _create_connection(
        self, hostname: str, port: int, timeout: float | None
    ) -> tuple[socket.socket, asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Create socket connection to SSH server.

        Args:
            hostname: Server hostname
            port: Server port
            timeout: Connection timeout

        Returns:
            Tuple of (socket, reader, writer)
        """
        try:
            # Use asyncio to create connection
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port), timeout=timeout
            )

            # Get the underlying socket
            sock = writer.get_extra_info("socket")

            return sock, reader, writer

        except asyncio.TimeoutError as e:
            raise SSHException(f"Connection timeout to {hostname}:{port}") from e
        except Exception as e:
            raise SSHException(f"Failed to connect to {hostname}:{port}: {e}") from e

    async def exec_command(
        self, command: str, bufsize: int = -1, timeout: float | None = None
    ) -> tuple[Any, Any, Any]:
        """
        Execute command on remote server asynchronously.

        Args:
            command: Command to execute
            bufsize: Buffer size for streams
            timeout: Command timeout in seconds

        Returns:
            Tuple of (stdin, stdout, stderr) streams

        Raises:
            SSHException: If command execution fails
        """
        if not self._connected or not self._transport:
            raise SSHException("Not connected")

        try:
            # Open channel
            channel = await self._transport.open_channel("session")

            # Execute command
            await channel.exec_command(command)

            # Return channel file objects
            return (
                channel.makefile("wb", bufsize),
                channel.makefile("rb", bufsize),
                channel.makefile_stderr("rb", bufsize),
            )

        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Command execution failed: {e}") from e

    async def invoke_shell(self) -> Any:
        """
        Start interactive shell asynchronously.

        Returns:
            Channel for shell interaction

        Raises:
            SSHException: If shell invocation fails
        """
        if not self._connected or not self._transport:
            raise SSHException("Not connected")

        try:
            # Open channel
            channel = await self._transport.open_channel("session")

            # Invoke shell
            await channel.invoke_shell()

            return channel

        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Shell invocation failed: {e}") from e

    async def open_sftp(self) -> AsyncSFTPClient:
        """
        Open SFTP client asynchronously.

        Returns:
            Async SFTP client instance

        Raises:
            SSHException: If SFTP open fails
        """
        if not self._connected or not self._transport:
            raise SSHException("Not connected")

        try:
            # Open SFTP subsystem channel
            channel = await self._transport.open_channel("session")
            await channel.invoke_subsystem("sftp")

            # Create async SFTP client
            sftp_client = AsyncSFTPClient(channel)
            await sftp_client._initialize()

            return sftp_client

        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"SFTP open failed: {e}") from e

    async def auth_password(self, username: str, password: str) -> None:
        """
        Authenticate using password asynchronously.

        Args:
            username: Username for authentication
            password: Password for authentication

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise SSHException("No transport available")

        if not await self._transport.auth_password(username, password):
            raise AuthenticationException("Password authentication failed")

    async def auth_publickey(
        self,
        username: str,
        pkey: Any | None = None,
        key_filename: str | list[str] | None = None,
        password: str | None = None,
    ) -> None:
        """
        Authenticate using public key asynchronously.

        Args:
            username: Username for authentication
            pkey: Private key instance
            key_filename: Path to private key file(s)
            password: Optional password for encrypted private keys

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise SSHException("No transport available")

        # Load key(s) from file if provided
        if key_filename:
            from ..crypto.pkey import PKey

            filenames = (
                [key_filename] if isinstance(key_filename, str) else key_filename
            )
            for filename in filenames:
                try:
                    # Run in thread as it does I/O
                    pkey = await asyncio.to_thread(
                        PKey.from_private_key_file, filename, password
                    )
                    if await self._transport.auth_publickey(username, pkey):
                        return
                except Exception as e:
                    self._logger.debug(
                        f"Failed to authenticate with key {filename}: {e}"
                    )

            if not pkey:
                raise AuthenticationException(
                    f"Failed to load keys from {key_filename}"
                )

        if pkey is None:
            raise AuthenticationException("No private key provided")

        if not await self._transport.auth_publickey(username, pkey):
            raise AuthenticationException("Public key authentication failed")

    async def auth_keyboard_interactive(
        self,
        username: str,
        handler: Callable[[str, str, list[tuple[str, bool]]], Any] | None = None,
    ) -> None:
        """Authenticate using keyboard-interactive method asynchronously."""
        if not self._transport:
            raise SSHException("No transport available")

        # Use console_handler by default
        from ..auth.keyboard_interactive import console_handler

        handler = handler or console_handler

        if not await self._transport.auth_keyboard_interactive(username, handler):
            raise AuthenticationException("Keyboard-interactive authentication failed")

    async def auth_gssapi(
        self,
        username: str,
        gss_host: str | None = None,
        gss_deleg_creds: bool = False,
    ) -> None:
        """Authenticate using GSSAPI (Kerberos) asynchronously."""
        if not self._transport:
            raise SSHException("No transport available")

        if not await self._transport.auth_gssapi(username, gss_host, gss_deleg_creds):
            raise AuthenticationException("GSSAPI authentication failed")

    async def _authenticate(
        self,
        username: str,
        password: str | None = None,
        pkey: Any | None = None,
        key_filename: str | list[str] | None = None,
        gss_auth: bool = False,
        gss_host: str | None = None,
        gss_deleg_creds: bool = False,
    ) -> None:
        """Internal helper to guide authentication flow."""
        if not self._transport:
            raise SSHException("No transport available")

        authenticated = False

        # Try GSSAPI if requested
        if gss_auth and not authenticated:
            try:
                await self.auth_gssapi(username, gss_host, gss_deleg_creds)
                authenticated = True
            except Exception as e:
                self._logger.debug(f"GSSAPI authentication failed: {e}")

        # Try Public Key
        if (pkey or key_filename) and not authenticated:
            try:
                await self.auth_publickey(
                    username, pkey=pkey, key_filename=key_filename, password=password
                )
                authenticated = True
            except Exception as e:
                self._logger.debug(f"Public key authentication failed: {e}")

        # Try Password
        if password and not authenticated:
            try:
                await self.auth_password(username, password)
                authenticated = True
            except Exception as e:
                self._logger.debug(f"Password authentication failed: {e}")

        # Try Keyboard-Interactive if nothing else worked
        if not authenticated:
            try:
                await self.auth_keyboard_interactive(username)
                authenticated = True
            except Exception as e:
                self._logger.debug(f"Keyboard-interactive authentication failed: {e}")

        if not authenticated:
            raise AuthenticationException(f"Authentication failed for user {username}")

    async def create_local_port_forward(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        local_host: str = "127.0.0.1",
    ) -> str:
        """
        Create local port forwarding tunnel asynchronously.

        Args:
            local_port: Local port to listen on
            remote_host: Remote host to connect to
            remote_port: Remote port to connect to
            local_host: Local interface to bind to

        Returns:
            Tunnel ID for management
        """
        if not self._connected or not self._transport:
            raise SSHException("Not connected")

        manager = self._transport.get_port_forwarding_manager()
        return await manager.create_local_tunnel(
            local_port, remote_host, remote_port, local_host
        )

    async def create_remote_port_forward(
        self,
        remote_port: int,
        local_host: str,
        local_port: int,
        remote_host: str = "",
    ) -> str:
        """
        Create remote port forwarding tunnel asynchronously.

        Args:
            remote_port: Remote port to listen on
            local_host: Local host to connect to
            local_port: Local port to connect to
            remote_host: Remote interface to bind to

        Returns:
            Tunnel ID for management
        """
        if not self._connected or not self._transport:
            raise SSHException("Not connected")

        manager = self._transport.get_port_forwarding_manager()
        return await manager.create_remote_tunnel(
            remote_port, local_host, local_port, remote_host
        )

    async def close_port_forward(self, tunnel_id: str) -> None:
        """
        Close port forwarding tunnel asynchronously.

        Args:
            tunnel_id: Tunnel identifier
        """
        if self._transport:
            manager = self._transport.get_port_forwarding_manager()
            await manager.close_tunnel(tunnel_id)

    def get_port_forwards(self) -> dict[str, Any]:
        """
        Get all active port forwarding tunnels.

        Returns:
            Dictionary mapping tunnel IDs to tunnel objects
        """
        if self._transport:
            manager = self._transport.get_port_forwarding_manager()
            return manager.get_all_tunnels()
        return {}

    def set_missing_host_key_policy(self, policy: MissingHostKeyPolicy) -> None:
        """
        Set policy for handling unknown host keys.

        Args:
            policy: Host key policy instance
        """
        self._host_key_policy = policy

    def set_host_key_storage(self, storage: HostKeyStorage) -> None:
        """
        Set host key storage instance.

        Args:
            storage: Host key storage to use
        """
        self._host_key_storage = storage

    async def load_host_keys(self, filename: str) -> None:
        """
        Load host keys from a file.

        Args:
            filename: Path to known_hosts file
        """
        if not self._host_key_storage:
            self._host_key_storage = HostKeyStorage(filename)
        else:
            await asyncio.to_thread(self._host_key_storage.load, filename)

    async def load_system_host_keys(self) -> None:
        """
        Load host keys from system default locations.
        """
        # Common locations
        import os
        paths = [
            os.path.expanduser("~/.ssh/known_hosts"),
            os.path.expanduser("~/.ssh/known_hosts2"),
            "/etc/ssh/ssh_known_hosts",
            "/etc/ssh/ssh_known_hosts2",
        ]
        for path in paths:
            if await asyncio.to_thread(os.path.exists, path):
                await self.load_host_keys(path)

    async def save_host_keys(self, filename: str) -> None:
        """
        Save host keys to a file.

        Args:
            filename: Path to save known_hosts
        """
        if not self._host_key_storage or self._host_key_storage._filename != filename:
            old_storage = self._host_key_storage
            self._host_key_storage = HostKeyStorage(filename)
            if old_storage:
                self._host_key_storage._keys = old_storage._keys

        # save() is sync, run in thread
        await asyncio.to_thread(self._host_key_storage.save)

    def get_host_key_storage(self) -> HostKeyStorage:
        """
        Get host key storage instance.

        Returns:
            Current host key storage
        """
        return self._host_key_storage

    async def close(self) -> None:
        """Close SSH connection and cleanup resources."""
        if self._transport:
            await self._transport.close()
            self._transport = None

        self._connected = False
        self._hostname = None
        self._port = 22
        self._username = None

    async def __aenter__(self) -> AsyncSSHClient:
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    @property
    def connected(self) -> bool:
        """Check if client is connected."""
        return self._connected and self._transport is not None

    @property
    def hostname(self) -> str | None:
        """Get connected hostname."""
        return self._hostname

    @property
    def port(self) -> int:
        """Get connected port."""
        return self._port

    @property
    def username(self) -> str | None:
        """Get authenticated username."""
        return self._username
