"""
SpindleX - A pure-Python SSH client/server library.

A secure, high-performance SSH and SFTP implementation without GPL/LGPL dependencies.
Provides modern cryptographic standards and comprehensive RFC 4251-4254 compliance.
"""

from ._version import __version__, __version_info__, get_version, get_version_info

__author__ = "SpindleX Team"
__license__ = "MIT"

from .client.sftp_client import SFTPClient

# Core client imports
from .client.ssh_client import SSHClient

# Async client imports (optional)
try:
    from .client.async_sftp_client import AsyncSFTPClient  # noqa: F401
    from .client.async_ssh_client import AsyncSSHClient  # noqa: F401

    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

# Authentication imports
from .auth.password import PasswordAuth
from .auth.publickey import PublicKeyAuth

# Exception imports
from .exceptions import (
    AuthenticationException,
    BadHostKeyException,
    ChannelException,
    ProtocolException,
    SFTPError,
    SSHException,
    TransportException,
)

# Host key policy imports
from .hostkeys.policy import (
    AutoAddPolicy,
    MissingHostKeyPolicy,
    RejectPolicy,
    WarningPolicy,
)

# Logging imports
from .logging import (
    SSHLogger,
    configure_logging,
    get_logger,
    get_performance_monitor,
    get_protocol_analyzer,
)

# SFTP imports
from .protocol.sftp_messages import SFTPAttributes
from .server.sftp_server import SFTPServer

# Core server imports
from .server.ssh_server import SSHServer
from .transport.channel import Channel
from .transport.forwarding import ForwardingTunnel, PortForwardingManager

# Transport layer imports
from .transport.transport import Transport

__all__ = [
    # Version info
    "__version__",
    "__version_info__",
    "get_version",
    "get_version_info",
    "__author__",
    "__license__",
    # Client classes
    "SSHClient",
    "SFTPClient",
    # SFTP classes
    "SFTPAttributes",
    # Server classes
    "SSHServer",
    "SFTPServer",
    # Transport classes
    "Transport",
    "Channel",
    "PortForwardingManager",
    "ForwardingTunnel",
    # Authentication classes
    "PasswordAuth",
    "PublicKeyAuth",
    # Host key policies
    "MissingHostKeyPolicy",
    "AutoAddPolicy",
    "RejectPolicy",
    "WarningPolicy",
    # Exceptions
    "SSHException",
    "AuthenticationException",
    "BadHostKeyException",
    "ChannelException",
    "SFTPError",
    "TransportException",
    "ProtocolException",
    # Logging
    "SSHLogger",
    "get_logger",
    "configure_logging",
    "get_performance_monitor",
    "get_protocol_analyzer",
]

# Add async classes if available
if ASYNC_AVAILABLE:
    __all__.extend(
        [
            "AsyncSSHClient",
            "AsyncSFTPClient",
        ]
    )
