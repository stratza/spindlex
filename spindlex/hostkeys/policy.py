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
    in trusted environments or for testing purposes. It trusts
    every first-seen host key and disables MITM protection.
    """

    def __init__(self, accept_risk: bool = False) -> None:
        """
        Initialize auto-add policy.

        Args:
            accept_risk: Must be True to acknowledge security risks
        """
        self._logger = logging.getLogger(__name__)
        if not accept_risk:
            import warnings

            self._logger.warning(
                "AutoAddPolicy is insecure and disables MITM protection. "
                "Pass accept_risk=True to silence this warning."
            )
            warnings.warn(
                "AutoAddPolicy is insecure and disables MITM protection. "
                "In future versions, accept_risk=True will be mandatory.",
                UserWarning,
                stacklevel=2,
            )
        self._accept_risk = accept_risk

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
            from ..exceptions import SSHException

            raise SSHException(
                f"Failed to persist new host key for {hostname}: {e}"
            ) from e


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
    Warn and persist unknown host keys (Trust On First Use).

    Logs a warning about unknown host keys and persists them to storage
    so subsequent connections are verified. This is TOFU behavior: the
    first connection is trusted unconditionally, with no MITM protection
    for that initial handshake. Use with caution in untrusted networks.
    """

    def __init__(self) -> None:
        """Initialize warning policy with logger."""
        self._logger = logging.getLogger(__name__)

    def missing_host_key(self, client: Any, hostname: str, key: Any) -> None:
        """
        Log warning and accept unknown host key (TOFU - stores on first use).

        Args:
            client: SSH client instance
            hostname: Server hostname
            key: Server's host key
        """
        self._logger.warning(
            f"Unknown host key for {hostname}: {key.algorithm_name} {key.get_fingerprint()}"
        )
        storage = getattr(client, "_host_key_storage", None)
        if storage:
            storage.add(hostname, key)
            storage.save()
