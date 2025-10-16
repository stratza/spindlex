"""
SSH Client Implementation

High-level SSH client for establishing connections, executing commands,
and managing SSH sessions with comprehensive authentication support.
"""

from typing import Optional, Tuple, Union, Any, IO
import socket
import logging
import io
from ..exceptions import SSHException, AuthenticationException, BadHostKeyException, TransportException
from ..transport.transport import Transport
from ..transport.channel import Channel
from ..hostkeys.policy import MissingHostKeyPolicy, RejectPolicy
from ..hostkeys.storage import HostKeyStorage
from ..crypto.pkey import PKey


class ChannelFile:
    """
    File-like object for SSH channel streams.
    
    Provides file-like interface for reading from and writing to SSH channels.
    """
    
    def __init__(self, channel: Channel, mode: str = 'r') -> None:
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
            size: Number of bytes to read (-1 for all available)
            
        Returns:
            Read data
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")
        
        if self._mode == 'stderr':
            return self._channel.recv_stderr(size if size > 0 else 8192)
        elif self._mode == 'r':
            return self._channel.recv(size if size > 0 else 8192)
        else:
            raise ValueError("File not opened for reading")
    
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
        
        if self._mode != 'w':
            raise ValueError("File not opened for writing")
        
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        return self._channel.send(data)
    
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
        timeout: Optional[float] = None
    ) -> None:
        """
        Connect to SSH server and authenticate.
        
        Args:
            hostname: Server hostname or IP address
            port: Server port (default 22)
            username: Username for authentication
            password: Password for authentication
            pkey: Private key for authentication
            timeout: Connection timeout in seconds
            
        Raises:
            SSHException: If connection or authentication fails
        """
        if self._transport and self._transport.active:
            raise SSHException("Already connected")
        
        self._hostname = hostname
        self._port = port
        
        try:
            # Create socket connection
            self._logger.debug(f"Connecting to {hostname}:{port}")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            if timeout:
                sock.settimeout(timeout)
            
            try:
                sock.connect((hostname, port))
            except socket.error as e:
                sock.close()
                raise SSHException(f"Connection failed: {e}")
            
            # Create transport
            self._transport = Transport(sock)
            
            # Start client transport (handshake and key exchange)
            self._transport.start_client(timeout)
            
            # Verify host key
            self._verify_host_key()
            
            # Authenticate if credentials provided
            if username:
                self._authenticate(username, password, pkey)
            
            self._logger.info(f"Successfully connected to {hostname}:{port}")
            
        except Exception as e:
            # Cleanup on failure
            if self._transport:
                self._transport.close()
                self._transport = None
            
            if isinstance(e, (SSHException, AuthenticationException, BadHostKeyException)):
                raise
            raise SSHException(f"Connection failed: {e}")
    
    def _verify_host_key(self) -> None:
        """
        Verify server host key according to policy.
        
        Raises:
            BadHostKeyException: If host key verification fails
        """
        if not self._transport:
            raise SSHException("No transport available")
        
        # For now, we'll implement a placeholder since the transport
        # doesn't yet provide a method to get the server's host key
        # This will be enhanced when the transport layer provides host key access
        
        hostname = self._hostname or "unknown"
        
        try:
            # TODO: Get actual server host key from transport
            # server_key = self._transport.get_server_host_key()
            
            # For now, we'll simulate the host key verification process
            # Check if we have a known host key for this hostname
            known_key = self._host_key_storage.get(hostname)
            
            if known_key is None:
                # No known key - apply missing host key policy
                self._logger.debug(f"No known host key for {hostname}")
                
                # Create a placeholder key for policy handling
                # In real implementation, this would be the actual server key
                server_key = None  # Placeholder
                
                try:
                    self._host_key_policy.missing_host_key(self, hostname, server_key)
                except BadHostKeyException:
                    # Policy rejected the key
                    raise
                except Exception as e:
                    # Policy had an error but didn't reject
                    self._logger.warning(f"Host key policy error: {e}")
            else:
                # We have a known key - in real implementation we would compare
                # with the actual server key
                self._logger.debug(f"Found known host key for {hostname}")
                
                # TODO: Compare known_key with actual server_key
                # if not known_key == server_key:
                #     raise BadHostKeyException(hostname, server_key, known_key)
            
        except BadHostKeyException:
            raise
        except Exception as e:
            self._logger.error(f"Host key verification error: {e}")
            raise BadHostKeyException(hostname, None)
    
    def _authenticate(self, username: str, password: Optional[str] = None, pkey: Optional[PKey] = None) -> None:
        """
        Authenticate with the server.
        
        Args:
            username: Username for authentication
            password: Password for authentication
            pkey: Private key for authentication
            
        Raises:
            AuthenticationException: If authentication fails
        """
        if not self._transport:
            raise AuthenticationException("No transport available")
        
        authenticated = False
        
        # Try public key authentication first if key provided
        if pkey and not authenticated:
            try:
                self._logger.debug(f"Attempting public key authentication for {username}")
                authenticated = self._transport.auth_publickey(username, pkey)
                if authenticated:
                    self._logger.info(f"Public key authentication successful for {username}")
            except Exception as e:
                self._logger.debug(f"Public key authentication failed: {e}")
        
        # Try password authentication if password provided and not yet authenticated
        if password and not authenticated:
            try:
                self._logger.debug(f"Attempting password authentication for {username}")
                authenticated = self._transport.auth_password(username, password)
                if authenticated:
                    self._logger.info(f"Password authentication successful for {username}")
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
        self, 
        command: str, 
        bufsize: int = -1
    ) -> Tuple[ChannelFile, ChannelFile, ChannelFile]:
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
            # Open a new session channel
            channel = self._transport.open_channel("session")
            
            # Execute the command
            channel.exec_command(command)
            
            # Create file-like objects for the streams
            stdin = ChannelFile(channel, 'w')
            stdout = ChannelFile(channel, 'r')
            stderr = ChannelFile(channel, 'stderr')
            
            self._logger.debug(f"Command executed: {command}")
            
            return stdin, stdout, stderr
            
        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to execute command '{command}': {e}")
    
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
            raise SSHException(f"Failed to invoke shell: {e}")
    
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
            return SFTPClient(self._transport)
        except Exception as e:
            if isinstance(e, SSHException):
                raise
            raise SSHException(f"Failed to open SFTP session: {e}")
    
    def close(self) -> None:
        """Close SSH connection and cleanup resources."""
        try:
            if self._transport:
                self._logger.debug(f"Closing connection to {self._hostname}:{self._port}")
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
        return (self._transport is not None and 
                self._transport.active and 
                self._transport.authenticated)
    
    def get_transport(self) -> Optional[Transport]:
        """
        Get underlying transport object.
        
        Returns:
            Transport instance or None if not connected
        """
        return self._transport
    
    def __enter__(self) -> "SSHClient":
        """Context manager entry."""
        return self
    
    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit with cleanup."""
        self.close()