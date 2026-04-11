"""
Async SSH Client Implementation

Provides asynchronous SSH client functionality for high-concurrency applications.
"""

import asyncio
import socket
from typing import Any, Optional

from ..exceptions import AuthenticationException, SSHException
from ..hostkeys.policy import AutoAddPolicy, MissingHostKeyPolicy
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
        self._transport: Optional[AsyncTransport] = None
        self._hostname: Optional[str] = None
        self._port: int = 22
        self._username: Optional[str] = None
        self._host_key_policy: MissingHostKeyPolicy = AutoAddPolicy()
        self._connected = False

    async def connect(
        self,
        hostname: str,
        port: int = 22,
        username: Optional[str] = None,
        password: Optional[str] = None,
        pkey: Optional[Any] = None,
        timeout: Optional[float] = None,
        compress: bool = False,
        gss_auth: bool = False,
        gss_kex: bool = False,
        gss_deleg_creds: bool = True,
        gss_host: Optional[str] = None,
    ) -> None:
        """
        Connect to SSH server asynchronously.

        Args:
            hostname: Server hostname or IP address
            port: Server port (default: 22)
            username: Username for authentication
            password: Password for authentication
            pkey: Private key for authentication
            timeout: Connection timeout in seconds
            compress: Enable compression
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

        try:
            # Create socket connection
            sock, reader, writer = await self._create_connection(
                hostname, port, timeout
            )

            # Create async transport
            self._transport = AsyncTransport(sock)

            # Use connect_existing helper to set reader/writer safely
            await self._transport.connect_existing(reader, writer)

            # Start client transport
            await self._transport.start_client(timeout)

            # Authenticate if credentials provided
            if username:
                # Authenticate
                if password:
                    await self.auth_password(username, password)
                elif pkey:
                    await self.auth_publickey(username, pkey)
                else:
                    raise AuthenticationException("No authentication credentials provided")


            # Store connection info
            self._hostname = hostname
            self._port = port
            self._username = username
            self._connected = True

        except Exception as e:
            if self._transport:
                await self._transport.close()
                self._transport = None

            if isinstance(e, (SSHException, AuthenticationException)):
                raise
            raise SSHException(f"Connection failed: {e}") from e

    async def _create_connection(
        self, hostname: str, port: int, timeout: Optional[float]
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
        self, command: str, bufsize: int = -1, timeout: Optional[float] = None
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

    async def auth_publickey(self, username: str, pkey: Any) -> None:
        """
        Authenticate using public key asynchronously.

        Args:
            username: Username for authentication
            pkey: Private key instance

        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise SSHException("No transport available")
        
        if not await self._transport.auth_publickey(username, pkey):
            raise AuthenticationException("Public key authentication failed")

    def set_missing_host_key_policy(self, policy: MissingHostKeyPolicy) -> None:

        """
        Set policy for handling missing host keys.

        Args:
            policy: Host key policy instance
        """
        self._host_key_policy = policy

    async def close(self) -> None:
        """Close SSH connection and cleanup resources."""
        if self._transport:
            await self._transport.close()
            self._transport = None

        self._connected = False
        self._hostname = None
        self._port = 22
        self._username = None

    async def __aenter__(self) -> "AsyncSSHClient":
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
    def hostname(self) -> Optional[str]:
        """Get connected hostname."""
        return self._hostname

    @property
    def port(self) -> int:
        """Get connected port."""
        return self._port

    @property
    def username(self) -> Optional[str]:
        """Get authenticated username."""
        return self._username
