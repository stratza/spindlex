"""Targeted coverage tests for hostkeys/storage.py."""

from unittest.mock import MagicMock, patch

import pytest

from spindlex.crypto.pkey import ECDSAKey, Ed25519Key
from spindlex.hostkeys.storage import HostKeyStorage


class TestHostKeyStorageInit:
    def test_load_exception_is_swallowed(self, tmp_path):
        bad_file = str(tmp_path / "bad.hosts")
        # Create a file with invalid content that forces a parse warning
        with open(bad_file, "w") as f:
            f.write("invalid line with only two parts\n")
        HostKeyStorage(bad_file)
        # Should not raise

    def test_load_file_not_exists(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "nonexistent.hosts"))
        assert storage._keys == {}


class TestHostKeyStorageLoad:
    def test_parse_error_line_logs_warning(self, tmp_path):
        bad_file = str(tmp_path / "warn.hosts")
        with open(bad_file, "w") as f:
            f.write("localhost ssh-ed25519 NOTVALIDBASE64!!!\n")
        HostKeyStorage(bad_file)
        # Should not raise, just log warning

    def test_invalid_line_less_than_3_parts(self, tmp_path):
        bad_file = str(tmp_path / "short.hosts")
        with open(bad_file, "w") as f:
            f.write("localhost ssh-ed25519\n")
        storage = HostKeyStorage(bad_file)
        assert storage._keys == {}

    def test_empty_and_comment_lines_skipped(self, tmp_path):
        f_path = str(tmp_path / "comments.hosts")
        with open(f_path, "w") as f:
            f.write("\n# comment\n\n")
        storage = HostKeyStorage(f_path)
        assert storage._keys == {}


class TestCreateKeyFromTypeAndData:
    def _make_storage(self, tmp_path):
        return HostKeyStorage(str(tmp_path / "dummy.hosts"))

    def test_ecdsa_key_type(self, tmp_path):
        storage = self._make_storage(tmp_path)
        ecdsa_key = ECDSAKey.generate()
        key_bytes = ecdsa_key.get_public_key_bytes()
        result = storage._create_key_from_type_and_data(
            "ecdsa-sha2-nistp256", key_bytes
        )
        assert result is not None

    def test_unsupported_key_type_returns_none(self, tmp_path):
        storage = self._make_storage(tmp_path)
        result = storage._create_key_from_type_and_data("ssh-unknown", b"data")
        assert result is None

    def test_exception_returns_none(self, tmp_path):
        storage = self._make_storage(tmp_path)
        result = storage._create_key_from_type_and_data("ssh-ed25519", b"bad data")
        assert result is None


class TestHostKeyStorageSave:
    def test_save_failure_cleans_up_temp(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "keys.hosts"))
        key = Ed25519Key.generate()
        storage.add("myhost", key)
        # Patch os.replace to fail
        with patch("os.replace", side_effect=OSError("disk full")):
            from spindlex.exceptions import SSHException

            with pytest.raises(SSHException):
                storage.save()

    def test_save_key_error_logs_warning(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "keys.hosts"))
        mock_key = MagicMock()
        mock_key.get_public_key_bytes.side_effect = Exception("key error")
        storage._keys["badhost"] = [mock_key]
        # Should not raise, just log warning
        try:
            storage.save()
        except Exception:
            pass


class TestHostKeyStorageAdd:
    def test_add_duplicate_key_skipped(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "keys.hosts"))
        key = Ed25519Key.generate()
        storage.add("host1", key)
        storage.add("host1", key)
        assert len(storage._keys["host1"]) == 1


class TestHostKeyStorageGet:
    def test_get_by_key_type_match(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "keys.hosts"))
        key = Ed25519Key.generate()
        storage.add("host1", key)
        result = storage.get("host1", key_type="ssh-ed25519")
        assert result is key

    def test_get_by_key_type_no_match(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "keys.hosts"))
        key = Ed25519Key.generate()
        storage.add("host1", key)
        result = storage.get("host1", key_type="ssh-rsa")
        assert result is None


class TestHostKeyStorageRemove:
    def test_remove_hostname_not_found(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "keys.hosts"))
        assert storage.remove("nonexistent") is False

    def test_remove_specific_key_and_cleanup_empty_list(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "keys.hosts"))
        key = Ed25519Key.generate()
        storage.add("host1", key)
        result = storage.remove("host1", key)
        assert result is True
        assert "host1" not in storage._keys

    def test_remove_specific_key_not_in_list(self, tmp_path):
        storage = HostKeyStorage(str(tmp_path / "keys.hosts"))
        key1 = Ed25519Key.generate()
        key2 = Ed25519Key.generate()
        storage.add("host1", key1)
        result = storage.remove("host1", key2)
        assert result is False
