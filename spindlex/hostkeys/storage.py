"""
Host Key Storage Implementation

Provides host key storage and retrieval functionality for
maintaining known host keys and verification.
"""

import base64
import fnmatch
import hashlib
import hmac
import logging
import os
from typing import Optional

from ..crypto.pkey import PKey
from ..exceptions import SSHException


def host_token(hostname: str, port: int = 22) -> str:
    """OpenSSH known_hosts host token: ``host`` for port 22, ``[host]:port``
    otherwise. DNS names are case-insensitive so the host part is lowercased."""
    host = hostname.lower()
    if port and port != 22:
        return f"[{host}]:{port}"
    return host


def _key_type(key: PKey) -> str:
    """The key format name as written in known_hosts (e.g. ``ssh-rsa``).

    This is the first field of the public key blob, which for RSA differs
    from ``algorithm_name`` (a signature algorithm such as ``rsa-sha2-256``).
    """
    blob = key.get_public_key_bytes()
    length = int.from_bytes(blob[:4], "big")
    return blob[4 : 4 + length].decode("ascii")


def _normalised_blob(blob: bytes) -> bytes:
    """Public key blob in canonical form (old SpindleX versions wrote RSA keys
    with an ``rsa-sha2-*`` type name)."""
    return PKey.from_string(blob).get_public_key_bytes()


def _hashed_token_matches(token: str, host: str) -> bool:
    """Whether a hashed ``|1|salt|hash`` known_hosts token names ``host``."""
    try:
        _, _, salt_b64, hash_b64 = token.split("|")
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
    except (ValueError, TypeError):
        return False
    digest = hmac.new(salt, host.encode("utf-8"), hashlib.sha1).digest()
    return hmac.compare_digest(digest, expected)


def _pattern_matches(patterns: str, host: str) -> bool:
    """OpenSSH host-pattern list match (``*``/``?`` wildcards, ``!`` negation,
    hashed entries)."""
    matched = False
    for pattern in patterns.split(","):
        pattern = pattern.strip()
        if not pattern:
            continue
        negate = pattern.startswith("!")
        if negate:
            pattern = pattern[1:]
        if pattern.startswith("|1|"):
            hit = _hashed_token_matches(pattern, host)
        else:
            hit = fnmatch.fnmatchcase(host, pattern.lower())
        if hit and negate:
            return False
        matched = matched or hit
    return matched


class HostKeyStorage:
    """
    Host key storage implementation.

    Manages storage and retrieval of known host keys for
    host verification and security policy enforcement.
    """

    def __init__(self, filename: Optional[str] = None) -> None:
        """
        Initialize host key storage.

        Args:
            filename: Path to known_hosts file (optional)
        """
        self._filename = filename or os.path.expanduser("~/.ssh/known_hosts")
        self._keys: dict[str, list[PKey]] = {}
        # Hashed (|1|salt|hash) entries, which cannot be keyed by hostname.
        # Each item is (salt_bytes, host_hash_bytes, PKey).
        self._hashed_entries: list[tuple[bytes, bytes, PKey]] = []
        # @revoked entries: (host patterns, key). A revoked key is never
        # accepted for a matching host, whatever the missing-key policy.
        self._revoked: list[tuple[str, PKey]] = []
        # Keys removed with remove(): (host token, key or None for all keys).
        # save() drops them from the file, since it otherwise only appends.
        self._removed: list[tuple[str, Optional[bytes]]] = []
        self._logger = logging.getLogger(__name__)

        # Try to load existing keys
        try:
            self.load()
        except FileNotFoundError:
            pass  # normal - known_hosts file not yet created
        except Exception as e:
            self._logger.warning(f"Could not load host keys from {self._filename}: {e}")

    def load(self, filename: Optional[str] = None) -> None:
        """
        Load host keys from storage file.

        Args:
            filename: Path to file (defaults to storage's filename)

        Raises:
            SSHException: If loading fails
        """
        target_file = filename or self._filename
        if not os.path.exists(target_file):
            self._logger.debug(f"Host key file {target_file} does not exist")
            return

        try:
            with open(target_file, encoding="utf-8") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()

                    # Skip empty lines and comments
                    if not line or line.startswith("#"):
                        continue

                    try:
                        self._parse_host_key_line(line)
                    except Exception as e:
                        self._logger.warning(
                            f"Error parsing line {line_num} in {target_file}: {e}"
                        )

        except Exception as e:
            raise SSHException(
                f"Failed to load host keys from {target_file}: {e}"
            ) from e

    def _parse_host_key_line(self, line: str) -> None:
        """
        Parse a single host key line from known_hosts format.

        Args:
            line: Line to parse
        """
        parts = line.split()
        if len(parts) < 3:
            return  # Invalid line format

        if parts[0] == "@revoked":
            if len(parts) >= 4:
                key = self._create_key_from_type_and_data(
                    parts[2], base64.b64decode(parts[3])
                )
                if key is not None:
                    self._revoked.append((parts[1], key))
            return

        # Other markers (@cert-authority) are not evaluated here; they are
        # preserved on disk by save().
        if parts[0].startswith("@"):
            return

        hostnames_part = parts[0]
        key_type = parts[1]
        key_data = parts[2]

        try:
            # Decode base64 key data
            key_bytes = base64.b64decode(key_data)

            # Create appropriate key object based on type
            key = self._create_key_from_type_and_data(key_type, key_bytes)
            if not key:
                return

            for token in hostnames_part.split(","):
                token = token.strip()
                if token.startswith("|1|"):
                    # Hashed host: |1|<b64 salt>|<b64 HMAC-SHA1(salt, host)>.
                    # Case-sensitive, so never lowercase it.
                    try:
                        _, _, salt_b64, hash_b64 = token.split("|")
                        self._hashed_entries.append(
                            (
                                base64.b64decode(salt_b64),
                                base64.b64decode(hash_b64),
                                key,
                            )
                        )
                    except (ValueError, Exception) as e:
                        self._logger.debug(f"Bad hashed host entry: {e}")
                    continue
                # Plain or [host]:port token - DNS names are case-insensitive.
                hostname = token.lower()
                if hostname not in self._keys:
                    self._keys[hostname] = []
                self._keys[hostname].append(key)

        except Exception as e:
            self._logger.debug(f"Failed to parse key data: {e}")

    def _create_key_from_type_and_data(
        self, key_type: str, key_data: bytes
    ) -> Optional[PKey]:
        """
        Create PKey instance from key type and data.

        Args:
            key_type: SSH key type string
            key_data: Key data bytes

        Returns:
            PKey instance or None if unsupported
        """
        try:
            # Import key classes
            from ..crypto.pkey import ECDSAKey, Ed25519Key, RSAKey

            pkey: PKey
            if key_type == "ssh-ed25519":
                pkey = Ed25519Key()
                pkey.load_public_key(key_data)
                return pkey
            elif key_type.startswith("ecdsa-sha2-"):
                pkey = ECDSAKey()
                pkey.load_public_key(key_data)
                return pkey
            elif key_type.startswith("ssh-rsa") or key_type.startswith("rsa-sha2-"):
                pkey = RSAKey()
                pkey.load_public_key(key_data)
                return pkey
            else:
                self._logger.debug(f"Unsupported key type: {key_type}")
                return None

        except Exception as e:
            self._logger.debug(f"Failed to create key from type {key_type}: {e}")
            return None

    def _existing_file_index(self) -> tuple[list[str], set]:
        """Read the current file verbatim and index the (host, key) pairs it holds.

        Returns (raw_lines, present) where raw_lines are the file's exact lines
        (each with its trailing newline) and present is a set of
        ``(hostname_token, base64_key)`` tuples already recorded, so save() can
        skip re-adding them. Lines that cannot be parsed (comments, markers like
        ``@revoked``, hashed ``|1|`` entries, unsupported key types) are kept in
        raw_lines but simply not indexed.
        """
        raw_lines: list[str] = []
        present: set = set()
        if not os.path.exists(self._filename):
            return raw_lines, present
        with open(self._filename, encoding="utf-8") as f:
            for line in f:
                raw_lines.append(line if line.endswith("\n") else line + "\n")
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("@"):
                    continue
                parts = stripped.split()
                if len(parts) < 3:
                    continue
                for host_token in parts[0].split(","):
                    present.add((host_token.strip().lower(), parts[2]))
        return raw_lines, present

    def save(self) -> None:
        """
        Persist host keys: append new entries and drop removed ones.

        Existing lines - including comments, ``@cert-authority``/``@revoked``
        markers, hashed ``|1|`` host entries and key types SpindleX does not
        parse - are preserved byte for byte, except host/key pairs deleted
        with remove(). Keys held in memory that are not already present in the
        file are appended.

        Raises:
            SSHException: If saving fails
        """
        temp_filename = self._filename + ".tmp"
        try:
            dirname = os.path.dirname(self._filename)
            if dirname:
                os.makedirs(dirname, exist_ok=True)

            raw_lines, present = self._existing_file_index()
            if self._removed:
                # Entries deleted with remove() must not survive on disk; the
                # rest of the file is preserved byte for byte.
                filtered = [self._line_without_removed(line) for line in raw_lines]
                raw_lines = [line for line in filtered if line is not None]
                present = {
                    (host, data)
                    for host, data in present
                    if not any(
                        host == removed_host
                        and (
                            removed_blob is None
                            or base64.b64encode(removed_blob).decode("ascii") == data
                        )
                        for removed_host, removed_blob in self._removed
                    )
                }

            new_lines: list[str] = []
            for hostname, keys in self._keys.items():
                for key in keys:
                    try:
                        key_data = base64.b64encode(key.get_public_key_bytes()).decode(
                            "ascii"
                        )
                    except Exception as e:
                        self._logger.warning(f"Failed to save key for {hostname}: {e}")
                        continue
                    if (hostname, key_data) in present:
                        continue
                    present.add((hostname, key_data))
                    new_lines.append(f"{hostname} {_key_type(key)} {key_data}\n")

            file_exists = os.path.exists(self._filename)
            if not raw_lines and not new_lines and not (file_exists and self._removed):
                return  # nothing to write and no existing file to preserve

            # If we are creating the file fresh, add a short header; when
            # appending to an existing file leave its content untouched.
            header: list[str] = []
            if not file_exists:
                header = ["# SSH known hosts file\n", "# Managed by spindlex\n", "\n"]
            # Ensure the preserved content ends with a newline before appending.
            if raw_lines and not raw_lines[-1].endswith("\n"):
                raw_lines[-1] += "\n"

            with open(temp_filename, "w", encoding="utf-8") as f:
                f.writelines(header)
                f.writelines(raw_lines)
                f.writelines(new_lines)

            os.replace(temp_filename, self._filename)

        except Exception as e:
            if os.path.exists(temp_filename):
                try:
                    os.remove(temp_filename)
                except OSError:
                    pass  # Ignore errors if file already gone or inaccessible
            raise SSHException(
                f"Failed to save host keys to {self._filename}: {e}"
            ) from e

    def add(self, hostname: str, key: PKey) -> None:
        """
        Add host key to storage.

        Args:
            hostname: Server hostname
            key: Host key to store
        """
        hostname = hostname.lower()
        if hostname not in self._keys:
            self._keys[hostname] = []

        # Check if key already exists
        for existing_key in self._keys[hostname]:
            if existing_key == key:
                return  # Key already exists

        # Add new key
        self._keys[hostname].append(key)
        self._logger.debug(f"Added host key for {hostname}: {key.algorithm_name}")

    def get(self, hostname: str, key_type: Optional[str] = None) -> Optional[PKey]:
        """
        Get host key for hostname.

        Args:
            hostname: Server hostname
            key_type: Optional algorithm name to filter by

        Returns:
            Host key if found, None otherwise
        """
        hostname = hostname.lower()
        if hostname in self._keys and self._keys[hostname]:
            if key_type:
                # Find matching key type
                for key in self._keys[hostname]:
                    if key.algorithm_name == key_type:
                        return key
                return None
            # Return the first key (most recent or preferred)
            return self._keys[hostname][0]
        return None

    def get_all(self, hostname: str) -> list[PKey]:
        """
        Get all host keys for hostname.

        Args:
            hostname: Server hostname

        Returns:
            List of host keys
        """
        return self._keys.get(hostname.lower(), [])

    def is_revoked(self, hostname: str, port: int, key: PKey) -> bool:
        """Whether ``key`` is marked ``@revoked`` for (hostname, port)."""
        token = host_token(hostname, port)
        blob = key.get_public_key_bytes()
        return any(
            hmac.compare_digest(revoked.get_public_key_bytes(), blob)
            and _pattern_matches(patterns, token)
            for patterns, revoked in self._revoked
        )

    def lookup(self, hostname: str, port: int = 22) -> list[PKey]:
        """Return all known keys for (hostname, port).

        Matches plain-hostname entries, OpenSSH ``[host]:port`` entries for
        non-standard ports, and hashed ``|1|salt|hash`` entries - so a
        ``known_hosts`` written by OpenSSH (which hashes by default on many
        distros, and brackets non-22 ports) is actually honoured rather than
        silently treated as "unknown host".
        """
        token = host_token(hostname, port)
        results: list[PKey] = list(self._keys.get(token, []))
        # When connecting on port 22, also accept a bare-host entry (already the
        # token) - nothing extra needed. For completeness also try the bare host
        # if a bracketed form was requested and vice versa is NOT done (ports
        # must match). Now add any hashed entries that match this token.
        token_bytes = token.encode("utf-8")
        for salt, host_hash, key in self._hashed_entries:
            # salt/host_hash are validated bytes (decoded at parse time), so the
            # HMAC never raises here. known_hosts hashing uses HMAC-SHA1 by spec.
            digest = hmac.new(salt, token_bytes, hashlib.sha1).digest()
            if hmac.compare_digest(digest, host_hash):
                results.append(key)
        return results

    def copy_from(self, other: "HostKeyStorage") -> None:
        """
        Merge all keys from another storage instance into this one.

        Args:
            other: Source storage whose keys are merged into self
        """
        for hostname, keys in other._keys.items():
            if hostname not in self._keys:
                self._keys[hostname] = []
            for key in keys:
                if key not in self._keys[hostname]:
                    self._keys[hostname].append(key)
        self._hashed_entries.extend(
            entry
            for entry in other._hashed_entries
            if entry not in self._hashed_entries
        )
        self._revoked.extend(
            entry for entry in other._revoked if entry not in self._revoked
        )
        self._removed.extend(other._removed)

    def remove(self, hostname: str, key: Optional[PKey] = None) -> bool:
        """
        Remove host key(s) for hostname.

        Args:
            hostname: Server hostname
            key: Specific key to remove (if None, removes all keys for hostname)

        Returns:
            True if any keys were removed
        """
        # DNS hostnames are case-insensitive; keys are stored lowercase.
        hostname = hostname.lower()
        blob = key.get_public_key_bytes() if key is not None else None
        removed = False

        if hostname in self._keys:
            if key is None:
                del self._keys[hostname]
                removed = True
            elif key in self._keys[hostname]:
                self._keys[hostname].remove(key)
                if not self._keys[hostname]:
                    del self._keys[hostname]
                removed = True

        # Hashed entries for this host.
        kept = []
        for salt, host_hash, entry_key in self._hashed_entries:
            digest = hmac.new(salt, hostname.encode("utf-8"), hashlib.sha1).digest()
            if hmac.compare_digest(digest, host_hash) and (
                blob is None or entry_key.get_public_key_bytes() == blob
            ):
                removed = True
                continue
            kept.append((salt, host_hash, entry_key))
        self._hashed_entries = kept

        if removed:
            # Remember it so save() deletes it from the file too.
            self._removed.append((hostname, blob))
        return removed

    def _line_without_removed(self, line: str) -> Optional[str]:
        """Return ``line`` with removed host/key pairs taken out, or None to
        drop the line entirely."""
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("@"):
            return line
        parts = stripped.split()
        if len(parts) < 3:
            return line
        try:
            line_blob: Optional[bytes] = base64.b64decode(parts[2])
        except (ValueError, TypeError):
            line_blob = None
        tokens = parts[0].split(",")
        remaining = []
        for token in tokens:
            drop = False
            for host, blob in self._removed:
                if blob is not None and line_blob is not None:
                    try:
                        same_key = _normalised_blob(line_blob) == _normalised_blob(blob)
                    except SSHException:
                        same_key = False
                    if not same_key:
                        continue
                if token.startswith("|1|"):
                    hit = _hashed_token_matches(token, host)
                else:
                    hit = token.lower() == host
                if hit:
                    drop = True
                    break
            if not drop:
                remaining.append(token)
        if len(remaining) == len(tokens):
            return line
        if not remaining:
            return None
        rest = stripped[len(parts[0]) :]
        return ",".join(remaining) + rest + "\n"
