"""
SSH Transport Module

Provides core SSH transport layer functionality including protocol handshake,
key exchange, channel management, and packet handling.
"""

from .channel import Channel
from .kex import KeyExchange
from .transport import Transport

# Async transport classes (optional)
try:
    from .async_channel import AsyncChannel
    from .async_transport import AsyncTransport

    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False

__all__ = [
    "Transport",
    "Channel",
    "KeyExchange",
]

if ASYNC_AVAILABLE:
    __all__.extend(["AsyncTransport", "AsyncChannel"])
