"""
SSH Client Module

Provides high-level SSH client functionality including connection management,
command execution, shell access, and SFTP file operations.
"""

from .ssh_client import SSHClient
from .sftp_client import SFTPClient

__all__ = [
    "SSHClient",
    "SFTPClient",
]