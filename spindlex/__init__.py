"""
SpindleX SSH Library
~~~~~~~~~~~~~~~~~~~~

Modern, high-performance SSH and SFTP library for Python.
"""

from ._version import __version__
from .client.async_sftp_client import AsyncSFTPClient
from .client.async_ssh_client import AsyncSSHClient
from .client.sftp_client import SFTPClient
from .client.ssh_client import SSHClient
from .exceptions import (
    AuthenticationException,
    BadHostKeyException,
    ChannelException,
    ConfigurationException,
    CryptoException,
    IncompatiblePeer,
    ProtocolException,
    SFTPError,
    SSHException,
    TimeoutException,
    TransportException,
)
from .server.sftp_server import SFTPServer
from .server.ssh_server import SSHServer, SSHServerManager
from .transport.transport import Transport

__all__ = [
    "__version__",
    "SSHClient",
    "SFTPClient",
    "AsyncSSHClient",
    "AsyncSFTPClient",
    "SSHServer",
    "SFTPServer",
    "SSHServerManager",
    "Transport",
    "SSHException",
    "AuthenticationException",
    "BadHostKeyException",
    "ChannelException",
    "SFTPError",
    "TransportException",
    "ProtocolException",
    "CryptoException",
    "TimeoutException",
    "ConfigurationException",
    "IncompatiblePeer",
]
