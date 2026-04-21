"""
SpindleX SSH Library
~~~~~~~~~~~~~~~~~~~~

Modern, high-performance SSH and SFTP library for Python.
"""

from __future__ import annotations

import logging as _stdlib_logging

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
from .logging.sanitizer import LogSanitizer as _LogSanitizer
from .logging.sanitizer import SanitizingFilter as _SanitizingFilter
from .server.sftp_server import SFTPServer
from .server.ssh_server import SSHServer, SSHServerManager
from .transport.transport import Transport

# Install the sanitizing filter on the spindlex root logger AND wrap the
# LogRecord factory so child loggers (e.g. spindlex.transport.transport)
# are also scrubbed — Python's logging framework does NOT apply ancestor
# logger filters to propagated records, only ancestor handlers.
_stdlib_logging.getLogger("spindlex").addFilter(_SanitizingFilter())

_original_record_factory = _stdlib_logging.getLogRecordFactory()


def _spindlex_record_factory(
    *args: object, **kwargs: object
) -> _stdlib_logging.LogRecord:
    record = _original_record_factory(*args, **kwargs)
    # Only scrub records emitted from this package; leave other loggers alone.
    # `logging.makeLogRecord` creates a placeholder record with name=None
    # before copying attributes over, so guard against that.
    name = record.name or ""
    if name == "spindlex" or name.startswith("spindlex."):
        try:
            record.msg = _LogSanitizer.sanitize_message(str(record.msg))
            if record.args:
                if isinstance(record.args, dict):
                    record.args = _LogSanitizer.sanitize_dict(record.args)
                else:
                    record.args = tuple(
                        (
                            _LogSanitizer.sanitize_message(str(a))
                            if isinstance(a, str)
                            else a
                        )
                        for a in record.args
                    )
        except Exception:
            # Never let sanitization break logging itself.
            pass
    return record


_stdlib_logging.setLogRecordFactory(_spindlex_record_factory)

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
