"""
SpindleX - A pure-Python SSHv2 client/server library.

SpindleX provides secure, high-performance SSH and SFTP operations without
GPL/LGPL dependencies.
"""

__version__ = "0.1.0"
__author__ = "SpindleX Team"
__email__ = "team@spindlex.org"
__license__ = "MIT"


# For now, we'll create placeholder classes until the full implementation is ready
class SSHClient:
    """Placeholder SSH client class."""

    pass


class SSHException(Exception):
    """Base SSH exception."""

    pass


class AuthenticationException(SSHException):
    """Authentication failed exception."""

    pass


class BadHostKeyException(SSHException):
    """Bad host key exception."""

    pass


class ChannelException(SSHException):
    """Channel operation exception."""

    pass


class SFTPError(SSHException):
    """SFTP operation exception."""

    pass


class AutoAddPolicy:
    """Automatically add unknown host keys."""

    pass


class RejectPolicy:
    """Reject unknown host keys."""

    pass


class WarningPolicy:
    """Warn about unknown host keys."""

    pass


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
