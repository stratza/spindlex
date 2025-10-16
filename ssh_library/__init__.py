"""
Python SSHv2 Library - A pure-Python SSH client/server library.

A secure, high-performance SSH and SFTP implementation without GPL/LGPL dependencies.
Provides modern cryptographic standards and comprehensive RFC 4251-4254 compliance.
"""

__version__ = "0.1.0"
__author__ = "SSH Library Team"
__license__ = "Apache-2.0"

# Core client imports
from .client.ssh_client import SSHClient
from .client.sftp_client import SFTPClient

# SFTP imports
from .protocol.sftp_messages import SFTPAttributes

# Core server imports  
from .server.ssh_server import SSHServer
from .server.sftp_server import SFTPServer

# Transport layer imports
from .transport.transport import Transport
from .transport.channel import Channel
from .transport.forwarding import PortForwardingManager, ForwardingTunnel

# Authentication imports
from .auth.password import PasswordAuth
from .auth.publickey import PublicKeyAuth

# Host key policy imports
from .hostkeys.policy import (
    MissingHostKeyPolicy,
    AutoAddPolicy, 
    RejectPolicy,
    WarningPolicy
)

# Exception imports
from .exceptions import (
    SSHException,
    AuthenticationException,
    BadHostKeyException,
    ChannelException,
    SFTPError,
    TransportException,
    ProtocolException
)

__all__ = [
    # Version info
    "__version__",
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
]