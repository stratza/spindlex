"""
SSH Client Module

Provides high-level SSH client functionality including connection management,
command execution, shell access, and SFTP file operations.
"""

from .sftp_client import SFTPClient
from .ssh_client import SSHClient

# Async client classes (optional)
try:
    from .async_sftp_client import AsyncSFTPClient
    from .async_ssh_client import AsyncSSHClient

    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

__all__ = [
    "SSHClient",
    "SFTPClient",
]

if ASYNC_AVAILABLE:
    __all__.extend(["AsyncSSHClient", "AsyncSFTPClient"])
