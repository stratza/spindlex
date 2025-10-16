"""
Spindle - A pure-Python SSHv2 client/server library.

Spindle provides secure, high-performance SSH and SFTP operations without
GPL/LGPL dependencies.
"""

__version__ = "0.1.0"
__author__ = "Spindle Team"
__email__ = "team@spindle.org"
__license__ = "MIT"

# Core imports for convenience
from .client.ssh_client import SSHClient
from .exceptions import (
    SSHException,
    AuthenticationException,
    BadHostKeyException,
    ChannelException,
    SFTPError,
)

# Host key policies
from .hostkeys.policy import (
    AutoAddPolicy,
    RejectPolicy,
    WarningPolicy,
)

__all__ = [
    # Version info
    "__version__",
    "__author__",
    "__email__",
    "__license__",
    
    # Core classes
    "SSHClient",
    
    # Exceptions
    "SSHException",
    "AuthenticationException", 
    "BadHostKeyException",
    "ChannelException",
    "SFTPError",
    
    # Host key policies
    "AutoAddPolicy",
    "RejectPolicy", 
    "WarningPolicy",
]