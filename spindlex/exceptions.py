"""
SSH Library Exception Hierarchy

Defines all exceptions used throughout the SSH library with a unified hierarchy
for consistent error handling and reporting.
"""

from typing import Any, Optional


class SSHException(Exception):
    """
    Base exception for all SSH-related errors.

    All SSH library exceptions inherit from this base class to provide
    a unified exception hierarchy for error handling.
    """

    def __init__(self, message: str, error_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.message = message
        self.error_code = error_code

    def __str__(self) -> str:
        if self.error_code is not None:
            return f"[{self.error_code}] {self.message}"
        return self.message


class AuthenticationException(SSHException):
    """
    Authentication failed.

    Raised when SSH authentication fails for any reason including
    invalid credentials, unsupported auth methods, or auth timeouts.
    """

    def __init__(self, message: str, allowed_methods: Optional[list] = None) -> None:
        super().__init__(message)
        self.allowed_methods = allowed_methods or []


class BadHostKeyException(SSHException):
    """
    Host key verification failed.

    Raised when the server's host key doesn't match expected values
    or when host key verification fails according to the configured policy.
    """

    def __init__(
        self, hostname: str, key: Any, expected_key: Optional[Any] = None
    ) -> None:
        message = f"Host key verification failed for {hostname}"
        if expected_key:
            message += f" (expected {expected_key.get_name()}, got {key.get_name()})"
        super().__init__(message)
        self.hostname = hostname
        self.key = key
        self.expected_key = expected_key


class ChannelException(SSHException):
    """
    Channel operation failed.

    Raised when SSH channel operations fail including channel creation,
    data transmission, or channel state management errors.
    """

    def __init__(self, message: str, channel_id: Optional[int] = None) -> None:
        super().__init__(message)
        self.channel_id = channel_id


class SFTPError(SSHException):
    """
    SFTP operation failed.

    Raised when SFTP file operations fail. Includes SFTP-specific
    error codes matching the SFTP specification.
    """

    # SFTP error codes from RFC 4254
    SSH_FX_OK = 0
    SSH_FX_EOF = 1
    SSH_FX_NO_SUCH_FILE = 2
    SSH_FX_PERMISSION_DENIED = 3
    SSH_FX_FAILURE = 4
    SSH_FX_BAD_MESSAGE = 5
    SSH_FX_NO_CONNECTION = 6
    SSH_FX_CONNECTION_LOST = 7
    SSH_FX_OP_UNSUPPORTED = 8

    def __init__(
        self,
        message: str,
        sftp_code: Optional[int] = None,
        filename: Optional[str] = None,
    ) -> None:
        super().__init__(message, sftp_code)
        self.sftp_code = sftp_code
        self.status_code = sftp_code  # Alias for compatibility
        self.filename = filename

    @classmethod
    def from_status(
        cls, status_code: int, message: str = "", filename: Optional[str] = None
    ) -> "SFTPError":
        """
        Create SFTPError from SFTP status code.

        Args:
            status_code: SFTP status code
            message: Optional error message
            filename: Optional filename context

        Returns:
            SFTPError instance with appropriate message
        """
        from .protocol.sftp_constants import get_status_message

        if not message:
            message = get_status_message(status_code)

        if filename:
            message = f"{message}: {filename}"

        return cls(message, status_code, filename)


class TransportException(SSHException):
    """
    Transport layer error.

    Raised when SSH transport layer operations fail including
    connection establishment, protocol negotiation, or packet handling.
    """

    def __init__(self, message: str, disconnect_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.disconnect_code = disconnect_code


class ProtocolException(SSHException):
    """
    SSH protocol violation.

    Raised when SSH protocol violations are detected including
    malformed messages, invalid state transitions, or unsupported operations.
    """

    def __init__(self, message: str, protocol_version: Optional[str] = None) -> None:
        super().__init__(message)
        self.protocol_version = protocol_version


class CryptoException(SSHException):
    """
    Cryptographic operation failed.

    Raised when cryptographic operations fail including key generation,
    encryption/decryption, or signature verification.
    """

    def __init__(self, message: str, algorithm: Optional[str] = None) -> None:
        super().__init__(message)
        self.algorithm = algorithm


class TimeoutException(SSHException):
    """
    Operation timed out.

    Raised when SSH operations exceed configured timeout values.
    """

    def __init__(self, message: str, timeout_value: Optional[float] = None) -> None:
        super().__init__(message)
        self.timeout_value = timeout_value


class ConfigurationException(SSHException):
    """
    Configuration error.

    Raised when SSH library configuration is invalid or incomplete.
    """

    pass


class IncompatiblePeer(SSHException):
    """
    Incompatible SSH peer.

    Raised when the remote SSH peer is incompatible with this implementation.
    """

    def __init__(self, message: str, peer_version: Optional[str] = None) -> None:
        super().__init__(message)
        self.peer_version = peer_version
