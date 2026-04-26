"""
Unit tests for spindlex/client/sftp_client.py

All tests use mocks — no real SSH/SFTP server required.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from spindlex.client.sftp_client import SFTPClient, SFTPFile
from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import (
    SSH_FX_EOF,
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
    SSH_FX_PERMISSION_DENIED,
    SSH_FXF_CREAT,
    SSH_FXF_READ,
    SSH_FXF_TRUNC,
    SSH_FXF_WRITE,
)
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPDataMessage,
    SFTPHandleMessage,
    SFTPNameMessage,
    SFTPStatusMessage,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ok_status(request_id: int = 1) -> SFTPStatusMessage:
    return SFTPStatusMessage(request_id, SSH_FX_OK, "Success")


def _make_err_status(
    request_id: int = 1, code: int = SSH_FX_NO_SUCH_FILE, msg: str = "no such file"
) -> SFTPStatusMessage:
    return SFTPStatusMessage(request_id, code, msg)


def _make_handle_msg(
    request_id: int = 1, handle: bytes = b"handle1"
) -> SFTPHandleMessage:
    return SFTPHandleMessage(request_id, handle)


def _make_attrs_msg(request_id: int = 1) -> SFTPAttrsMessage:
    attrs = SFTPAttributes()
    attrs.size = 1024
    attrs.permissions = 0o644
    return SFTPAttrsMessage(request_id, attrs)


def _make_name_msg(
    request_id: int = 1,
    names: list[tuple[str, str, SFTPAttributes]] | None = None,
) -> SFTPNameMessage:
    if names is None:
        names = [("/home/user", "/home/user", SFTPAttributes())]
    return SFTPNameMessage(request_id, names)


def _make_data_msg(
    request_id: int = 1, data: bytes = b"hello world"
) -> SFTPDataMessage:
    return SFTPDataMessage(request_id, data)


def _make_sftp_client() -> tuple[SFTPClient, MagicMock]:
    """
    Create an SFTPClient that bypasses __init__ (which does I/O) and
    instead pre-populates the required instance attributes.
    """
    channel = MagicMock()
    client = SFTPClient.__new__(SFTPClient)
    import logging

    client._transport = MagicMock()
    client._channel = channel
    client._request_id = 0
    client._request_lock = threading.Lock()
    client._logger = logging.getLogger("test.sftp_client")
    client._server_version = 3
    client._server_extensions = {}
    return client, channel


# ---------------------------------------------------------------------------
# SFTPFile tests
# ---------------------------------------------------------------------------


class TestSFTPFile:
    def _make_file(
        self, handle: bytes = b"fh", mode: str = "r"
    ) -> tuple[SFTPFile, SFTPClient]:
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        f = SFTPFile(client, handle, mode)
        return f, client

    # --- __init__ ---

    def test_init_attributes(self):
        client, _ = _make_sftp_client()
        f = SFTPFile(client, b"myhandle", "rb")
        assert f._handle == b"myhandle"
        assert f._mode == "rb"
        assert f._offset == 0
        assert f._closed is False
        assert f._client is client

    # --- read: closed guard ---

    def test_read_raises_when_closed(self):
        f, _ = self._make_file()
        f._closed = True
        with pytest.raises(SFTPError, match="closed"):
            f.read(10)

    # --- read: partial (size > 0) ---

    def test_read_partial_data_response(self):
        f, client = self._make_file()
        data_resp = _make_data_msg(data=b"abcde")
        client._send_request_and_wait_response.return_value = data_resp
        result = f.read(5)
        assert result == b"abcde"
        assert f._offset == 5

    def test_read_partial_eof_returns_empty(self):
        f, client = self._make_file()
        eof_resp = _make_err_status(code=SSH_FX_EOF, msg="EOF")
        client._send_request_and_wait_response.return_value = eof_resp
        result = f.read(100)
        assert result == b""

    def test_read_partial_error_raises(self):
        f, client = self._make_file()
        err_resp = _make_err_status(code=SSH_FX_PERMISSION_DENIED, msg="denied")
        client._send_request_and_wait_response.return_value = err_resp
        with pytest.raises(SFTPError):
            f.read(10)

    def test_read_unexpected_response_raises(self):
        f, client = self._make_file()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            f.read(10)

    # --- read: full (size = -1) ---

    def test_read_all_reads_until_eof(self):
        f, client = self._make_file()
        responses = [
            _make_data_msg(data=b"chunk1"),
            _make_data_msg(data=b"chunk2"),
            SFTPStatusMessage(1, SSH_FX_EOF, "EOF"),
        ]
        client._send_request_and_wait_response.side_effect = responses
        result = f.read(-1)
        assert result == b"chunk1chunk2"
        assert f._offset == 12

    def test_read_all_empty_file(self):
        f, client = self._make_file()
        client._send_request_and_wait_response.return_value = SFTPStatusMessage(
            1, SSH_FX_EOF, "EOF"
        )
        result = f.read(-1)
        assert result == b""

    # --- write ---

    def test_write_raises_when_closed(self):
        f, _ = self._make_file(mode="w")
        f._closed = True
        with pytest.raises(SFTPError, match="closed"):
            f.write(b"data")

    def test_write_success_advances_offset(self):
        f, client = self._make_file(mode="w")
        client._send_request_and_wait_response.return_value = _make_ok_status()
        result = f.write(b"hello")
        assert result == 5
        assert f._offset == 5

    def test_write_error_raises(self):
        f, client = self._make_file(mode="w")
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            f.write(b"data")

    def test_write_unexpected_response_raises(self):
        f, client = self._make_file(mode="w")
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            f.write(b"data")

    # --- close ---

    def test_close_sends_close_request(self):
        f, client = self._make_file()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        f.close()
        assert f._closed is True
        client._send_request_and_wait_response.assert_called_once()

    def test_close_idempotent(self):
        f, client = self._make_file()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        f.close()
        f.close()
        # Should only send one close request
        assert client._send_request_and_wait_response.call_count == 1

    # --- context manager ---

    def test_context_manager_closes_on_exit(self):
        f, client = self._make_file()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        with f:
            assert f._closed is False
        assert f._closed is True

    def test_context_manager_closes_on_exception(self):
        f, client = self._make_file()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        with pytest.raises(ValueError):
            with f:
                raise ValueError("test")
        assert f._closed is True


# ---------------------------------------------------------------------------
# SFTPClient._get_next_request_id
# ---------------------------------------------------------------------------


class TestGetNextRequestId:
    def test_increments_sequentially(self):
        client, _ = _make_sftp_client()
        assert client._get_next_request_id() == 1
        assert client._get_next_request_id() == 2
        assert client._get_next_request_id() == 3

    def test_thread_safety(self):
        """Multiple threads should each get a unique ID."""
        client, _ = _make_sftp_client()
        ids = []

        def collect():
            for _ in range(50):
                ids.append(client._get_next_request_id())

        threads = [threading.Thread(target=collect) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(ids) == len(set(ids)), "Duplicate request IDs detected"


# ---------------------------------------------------------------------------
# SFTPClient.open
# ---------------------------------------------------------------------------


class TestSFTPClientOpen:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_open_read_mode_returns_sftp_file(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg(
            handle=b"fh_read"
        )
        f = client.open("/remote/file.txt", "r")
        assert isinstance(f, SFTPFile)
        assert f._handle == b"fh_read"

    def test_open_write_mode(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg(
            handle=b"fh_write"
        )
        f = client.open("/remote/file.txt", "w")
        assert isinstance(f, SFTPFile)

    def test_open_append_mode(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg(
            handle=b"fh_append"
        )
        f = client.open("/remote/file.txt", "a")
        assert isinstance(f, SFTPFile)

    def test_open_status_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED, msg="permission denied"
        )
        with pytest.raises(SFTPError):
            client.open("/remote/file.txt", "r")

    def test_open_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_attrs_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.open("/remote/file.txt", "r")


# ---------------------------------------------------------------------------
# SFTPClient._mode_to_flags
# ---------------------------------------------------------------------------


class TestModeToFlags:
    def test_read_flag(self):
        client, _ = _make_sftp_client()
        flags = client._mode_to_flags("r")
        assert flags & SSH_FXF_READ
        assert not (flags & SSH_FXF_WRITE)

    def test_write_flags(self):
        client, _ = _make_sftp_client()
        flags = client._mode_to_flags("w")
        assert flags & SSH_FXF_WRITE
        assert flags & SSH_FXF_CREAT
        assert flags & SSH_FXF_TRUNC

    def test_append_flags(self):
        client, _ = _make_sftp_client()
        flags = client._mode_to_flags("a")
        assert flags & SSH_FXF_WRITE
        assert flags & SSH_FXF_CREAT
        assert not (flags & SSH_FXF_TRUNC)


# ---------------------------------------------------------------------------
# SFTPClient.get
# ---------------------------------------------------------------------------


class TestSFTPClientGet:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_get_success(self, tmp_path):
        client = self._client()
        local = str(tmp_path / "downloaded.txt")
        responses = [
            _make_handle_msg(handle=b"dl_handle"),  # open
            _make_data_msg(data=b"file content"),  # read chunk 1
            SFTPStatusMessage(1, SSH_FX_EOF, "EOF"),  # EOF
            _make_ok_status(),  # close
        ]
        client._send_request_and_wait_response.side_effect = responses
        client.get("/remote/file.txt", local)
        with open(local, "rb") as fh:
            assert fh.read() == b"file content"

    def test_get_open_fails_raises(self, tmp_path):
        client = self._client()
        local = str(tmp_path / "dl.txt")
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            client.get("/nonexistent.txt", local)

    def test_get_read_error_raises(self, tmp_path):
        client = self._client()
        local = str(tmp_path / "dl.txt")
        responses = [
            _make_handle_msg(handle=b"dl_handle"),
            _make_err_status(code=SSH_FX_FAILURE, msg="failure"),
            _make_ok_status(),  # close
        ]
        client._send_request_and_wait_response.side_effect = responses
        with pytest.raises(SFTPError):
            client.get("/remote/file.txt", local)

    def test_get_unexpected_open_response_raises(self, tmp_path):
        client = self._client()
        local = str(tmp_path / "dl.txt")
        # SFTPStatusMessage with SSH_FX_OK as the open response triggers special case
        client._send_request_and_wait_response.return_value = _make_ok_status()
        with pytest.raises(SFTPError):
            client.get("/remote/file.txt", local)


# ---------------------------------------------------------------------------
# SFTPClient.put
# ---------------------------------------------------------------------------


class TestSFTPClientPut:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_put_success(self, tmp_path):
        client = self._client()
        local = tmp_path / "upload.txt"
        local.write_bytes(b"upload data")
        responses = [
            _make_handle_msg(handle=b"ul_handle"),  # open
            _make_ok_status(),  # write
            _make_ok_status(),  # close
        ]
        client._send_request_and_wait_response.side_effect = responses
        client.put(str(local), "/remote/upload.txt")

    def test_put_open_fails_raises(self, tmp_path):
        client = self._client()
        local = tmp_path / "upload.txt"
        local.write_bytes(b"data")
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            client.put(str(local), "/remote/upload.txt")

    def test_put_write_error_raises(self, tmp_path):
        client = self._client()
        local = tmp_path / "upload.txt"
        local.write_bytes(b"data")
        responses = [
            _make_handle_msg(handle=b"ul_handle"),
            _make_err_status(code=SSH_FX_FAILURE),
            _make_ok_status(),  # close
        ]
        client._send_request_and_wait_response.side_effect = responses
        with pytest.raises(SFTPError):
            client.put(str(local), "/remote/upload.txt")

    def test_put_open_unexpected_response_raises(self, tmp_path):
        client = self._client()
        local = tmp_path / "upload.txt"
        local.write_bytes(b"data")
        client._send_request_and_wait_response.return_value = _make_ok_status()
        with pytest.raises(SFTPError):
            client.put(str(local), "/remote/upload.txt")


# ---------------------------------------------------------------------------
# SFTPClient.listdir
# ---------------------------------------------------------------------------


class TestSFTPClientListdir:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_listdir_returns_names(self):
        client = self._client()
        attrs = SFTPAttributes()
        names = [
            (".", ".", attrs),
            ("..", "..", attrs),
            ("file1.txt", "file1.txt", attrs),
            ("file2.txt", "file2.txt", attrs),
        ]
        responses = [
            _make_handle_msg(handle=b"dir_handle"),
            SFTPNameMessage(1, names),
            SFTPStatusMessage(1, SSH_FX_EOF, "EOF"),
            _make_ok_status(),  # close
        ]
        client._send_request_and_wait_response.side_effect = responses
        result = client.listdir("/some/dir")
        assert result == ["file1.txt", "file2.txt"]

    def test_listdir_empty_directory(self):
        client = self._client()
        responses = [
            _make_handle_msg(handle=b"dir_handle"),
            SFTPStatusMessage(1, SSH_FX_EOF, "EOF"),
            _make_ok_status(),
        ]
        client._send_request_and_wait_response.side_effect = responses
        result = client.listdir("/empty/dir")
        assert result == []

    def test_listdir_opendir_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            client.listdir("/nonexistent")

    def test_listdir_readdir_error_raises(self):
        client = self._client()
        responses = [
            _make_handle_msg(handle=b"dir_handle"),
            _make_err_status(code=SSH_FX_FAILURE),
            _make_ok_status(),
        ]
        client._send_request_and_wait_response.side_effect = responses
        with pytest.raises(SFTPError):
            client.listdir("/some/dir")

    def test_listdir_unexpected_name_response_raises(self):
        client = self._client()
        responses = [
            _make_handle_msg(handle=b"dir_handle"),
            _make_attrs_msg(),  # not a name message
            _make_ok_status(),
        ]
        client._send_request_and_wait_response.side_effect = responses
        with pytest.raises(SFTPError, match="Unexpected"):
            client.listdir("/some/dir")


# ---------------------------------------------------------------------------
# SFTPClient.stat / lstat
# ---------------------------------------------------------------------------


class TestSFTPClientStat:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_stat_success(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_attrs_msg()
        result = client.stat("/some/file.txt")
        assert isinstance(result, SFTPAttributes)

    def test_stat_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            client.stat("/nonexistent.txt")

    def test_stat_ok_status_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.stat("/some/file.txt")

    def test_stat_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.stat("/some/file.txt")

    def test_lstat_success(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_attrs_msg()
        result = client.lstat("/some/link.txt")
        assert isinstance(result, SFTPAttributes)

    def test_lstat_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            client.lstat("/forbidden")

    def test_lstat_ok_status_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.lstat("/some/file.txt")

    def test_lstat_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.lstat("/some/file.txt")


# ---------------------------------------------------------------------------
# SFTPClient.mkdir / rmdir
# ---------------------------------------------------------------------------


class TestSFTPClientMkdirRmdir:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_mkdir_success(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        client.mkdir("/new/dir")  # should not raise

    def test_mkdir_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            client.mkdir("/forbidden/dir")

    def test_mkdir_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.mkdir("/new/dir")

    def test_rmdir_success(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        client.rmdir("/old/dir")  # should not raise

    def test_rmdir_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            client.rmdir("/nonexistent/dir")

    def test_rmdir_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.rmdir("/old/dir")


# ---------------------------------------------------------------------------
# SFTPClient.remove
# ---------------------------------------------------------------------------


class TestSFTPClientRemove:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_remove_success(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        client.remove("/file.txt")  # should not raise

    def test_remove_not_found_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            client.remove("/nonexistent.txt")

    def test_remove_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.remove("/file.txt")


# ---------------------------------------------------------------------------
# SFTPClient.rename
# ---------------------------------------------------------------------------


class TestSFTPClientRename:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_rename_success(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        client.rename("/old.txt", "/new.txt")

    def test_rename_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            client.rename("/old.txt", "/new.txt")

    def test_rename_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.rename("/old.txt", "/new.txt")


# ---------------------------------------------------------------------------
# SFTPClient.chmod
# ---------------------------------------------------------------------------


class TestSFTPClientChmod:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_chmod_success(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        client.chmod("/file.txt", 0o755)

    def test_chmod_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            client.chmod("/file.txt", 0o755)

    def test_chmod_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.chmod("/file.txt", 0o755)


# ---------------------------------------------------------------------------
# SFTPClient.getcwd / normalize
# ---------------------------------------------------------------------------


class TestSFTPClientGetcwdNormalize:
    def _client(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock()
        return client

    def test_getcwd_returns_path(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_name_msg(
            names=[("/home/user", "/home/user", SFTPAttributes())]
        )
        result = client.getcwd()
        assert result == "/home/user"

    def test_getcwd_empty_names_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = SFTPNameMessage(1, [])
        with pytest.raises(SFTPError, match="Empty"):
            client.getcwd()

    def test_getcwd_error_status_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_FAILURE
        )
        with pytest.raises(SFTPError):
            client.getcwd()

    def test_getcwd_ok_status_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.getcwd()

    def test_getcwd_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.getcwd()

    def test_normalize_returns_path(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_name_msg(
            names=[("/abs/path", "/abs/path", SFTPAttributes())]
        )
        result = client.normalize("./rel/../path")
        assert result == "/abs/path"

    def test_normalize_error_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            client.normalize("/nonexistent")

    def test_normalize_empty_names_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = SFTPNameMessage(1, [])
        with pytest.raises(SFTPError, match="Empty"):
            client.normalize("/some/path")

    def test_normalize_ok_status_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_ok_status()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.normalize("/some/path")

    def test_normalize_unexpected_response_raises(self):
        client = self._client()
        client._send_request_and_wait_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            client.normalize("/some/path")


# ---------------------------------------------------------------------------
# SFTPClient.close / context manager
# ---------------------------------------------------------------------------


class TestSFTPClientClose:
    def test_close_closes_channel(self):
        client, channel = _make_sftp_client()
        client.close()
        channel.close.assert_called_once()
        assert client._channel is None

    def test_close_idempotent(self):
        client, channel = _make_sftp_client()
        client.close()
        client.close()  # should not raise
        channel.close.assert_called_once()

    def test_close_channel_error_is_swallowed(self):
        client, channel = _make_sftp_client()
        channel.close.side_effect = OSError("already closed")
        client.close()  # should not raise
        assert client._channel is None

    def test_context_manager_closes_on_exit(self):
        client, channel = _make_sftp_client()
        with client:
            pass
        channel.close.assert_called_once()

    def test_context_manager_closes_on_exception(self):
        client, channel = _make_sftp_client()
        with pytest.raises(RuntimeError):
            with client:
                raise RuntimeError("test error")
        channel.close.assert_called_once()


# ---------------------------------------------------------------------------
# SFTPClient._initialize_sftp (via __init__ with mocked transport)
# ---------------------------------------------------------------------------


class TestSFTPClientInitialize:
    def test_initialize_sftp_success(self):
        from spindlex.protocol.sftp_messages import SFTPVersionMessage

        transport = MagicMock()
        channel = MagicMock()
        transport.open_channel.return_value = channel

        version_msg = SFTPVersionMessage(3, {})
        channel.recv_exactly.side_effect = [
            # First 4 bytes: length of version message
            (lambda d: d[:4])(version_msg.pack()),
            # Remaining bytes: content
            (lambda d: d[4:])(version_msg.pack()),
        ]

        client = SFTPClient(transport)
        assert client._server_version == 3
        transport.open_channel.assert_called_once_with("session")
        channel.invoke_subsystem.assert_called_once()

    def test_initialize_sftp_channel_none_raises(self):
        transport = MagicMock()
        transport.open_channel.return_value = None
        with pytest.raises(SFTPError):
            SFTPClient(transport)

    def test_initialize_sftp_wrong_response_raises(self):
        transport = MagicMock()
        channel = MagicMock()
        transport.open_channel.return_value = channel

        # Return a status message instead of version
        status_msg = SFTPStatusMessage(0, SSH_FX_FAILURE, "fail")
        channel.recv_exactly.side_effect = [
            status_msg.pack()[:4],
            status_msg.pack()[4:],
        ]

        with pytest.raises(SFTPError):
            SFTPClient(transport)
