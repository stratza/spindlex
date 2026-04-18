"""
Host Key Policy Implementation

Provides host key verification policies for secure host authentication
and protection against man-in-the-middle attacks.
"""

import logging
from abc import ABC, abstractmethod
from typing import Any

from ..exceptions import BadHostKeyException


class MissingHostKeyPolicy(ABC):
    """
    Abstract base class for host key policies.

    Defines the interface for handling unknown host keys during
    SSH connection establishment.
    """

    @abstractmethod
    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        """
        Handle unknown host key.

        Args:
            client: SSH client instance
            hostname: Server hostname
            key: Server's host key

        Raises:
            BadHostKeyException: If host key should be rejected
        """
        pass


class AutoAddPolicy(MissingHostKeyPolicy):
    """
    Automatically add unknown host keys.

    WARNING: This policy is insecure and should only be used
    in trusted environments or for testing purposes.
    """

    def __init__(self) -> None:
        """Initialize auto-add policy with logger."""
        self._logger = logging.getLogger(__name__)

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        """
        Automatically accept and store unknown host key.

        Args:
            client: SSH client instance
            hostname: Server hostname
            key: Server's host key
        """
        try:
            # Get host key storage from client
            storage = getattr(client, "_host_key_storage", None)
            if storage:
                storage.add(hostname, key)
                storage.save()
            else:
                self._logger.debug("No host key storage available on client")

            self._logger.warning(
                f"Automatically added host key for {hostname}: {key.algorithm_name} "
                f"{key.get_fingerprint()}"
            )
        except Exception as e:
            self._logger.error(f"Failed to add/save host key for {hostname}: {e}")
            raise SSHException(f"Failed to persist new host key for {hostname}: {e}") from e


class RejectPolicy(MissingHostKeyPolicy):
    """
    Reject all unknown host keys.

    This is the secure default policy that rejects any unknown
    host keys to prevent man-in-the-middle attacks.
    """

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        """
        Reject unknown host key.

        Args:
            client: SSH client instance
            hostname: Server hostname
            key: Server's host key

        Raises:
            BadHostKeyException: Always raised for unknown keys
        """
        raise BadHostKeyException(hostname, key)


class WarningPolicy(MissingHostKeyPolicy):
    """
    Log warning but accept unknown host keys.

    This policy logs a warning about unknown host keys but
    allows the connection to proceed. Use with caution.
    """

    def __init__(self) -> None:
        """Initialize warning policy with logger."""
        self._logger = logging.getLogger(__name__)

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        """
        Log warning and accept unknown host key.

        Args:
            client: SSH client instance
            hostname: Server hostname
            key: Server's host key
        """
        self._logger.warning(
            f"Unknown host key for {hostname}: {key.get_name()} {key.get_fingerprint()}"
        )
