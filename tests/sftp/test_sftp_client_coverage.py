"""
Additional coverage tests for spindlex/client/sftp_client.py.

Covers missed lines:
- SFTPFile.read closed guard + pipelined read error paths (97, 108-112)
- SFTPFile.write pipeline full + error paths (169-175)
- SFTPClient.get / put / get_recursive / put_recursive (260, 274, 293, etc.)
- SFTPClient.listdir unexpected response (339, 343, 345-348, 363-365)
- SFTPClient.stat unexpected (391)
- SFTPClient.lstat unexpected (416)
- SFTPClient.chmod unexpected (428-432)
- SFTPClient.mkdir / rmdir / remove / rename unexpected
- SFTPClient.getcwd / normalize / symlink / readlink
- SFTPClient._send_message / _receive_message no-channel paths
- SFTPClient._receive_message_for_id timeout
"""

from __future__ import annotations

import os
import tempfile
import threading
from unittest.mock import MagicMock, patch

import pytest

from spindlex.client.sftp_client import SFTPClient, SFTPFile
from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import (
    SSH_FX_EOF,
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
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
    names: list | None = None,
) -> SFTPNameMessage:
    if names is None:
        names = [("/home/user", "/home/user", SFTPAttributes())]
    return SFTPNameMessage(request_id, names)


def _make_data_msg(
    request_id: int = 1, data: bytes = b"hello world"
) -> SFTPDataMessage:
    return SFTPDataMessage(request_id, data)


def _make_sftp_client() -> tuple[SFTPClient, MagicMock]:
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
    client._pending_responses = {}
    client._max_write_len = 64512  # _DEFAULT_MAX_WRITE fallback
    return client, channel


def _make_sftp_file(
    handle: bytes = b"fh", mode: str = "r", pipeline_depth: int = 1
) -> tuple[SFTPFile, SFTPClient]:
    client, _ = _make_sftp_client()
    client._send_request_and_wait_response = MagicMock()
    client._send_message = MagicMock()
    client._receive_message_for_id = MagicMock()
    f = SFTPFile(client, handle, mode)
    f._PIPELINE_DEPTH = pipeline_depth
    return f, client


# ---------------------------------------------------------------------------
# SFTPFile - pipelined read error/unexpected paths
# ---------------------------------------------------------------------------


class TestSFTPFilePipelinedReadErrors:
    def test_pipelined_read_error_status_raises(self):
        """In pipelined read, a non-EOF status raises SFTPError."""
        f, client = _make_sftp_file(pipeline_depth=1)
        client._receive_message_for_id.return_value = _make_err_status(
            code=SSH_FX_FAILURE, msg="IO error"
        )
        with pytest.raises(SFTPError):
            f.read(-1)

    def test_pipelined_read_unexpected_response_raises(self):
        """In pipelined read, unexpected message type raises SFTPError."""
        f, client = _make_sftp_file(pipeline_depth=1)
        client._receive_message_for_id.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            f.read(-1)


# ---------------------------------------------------------------------------
# SFTPFile - write pipeline full drain error
# ---------------------------------------------------------------------------


class TestSFTPFileWritePipelineDrain:
    def test_write_pipeline_drain_unexpected_raises(self):
        """Write pipeline drain: unexpected response raises SFTPError."""
        f, client = _make_sftp_file(pipeline_depth=1)
        f._write_queue.append((99, 5))
        client._receive_message_for_id.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            f.write(b"data")

    def test_flush_write_queue_unexpected_raises(self):
        """_flush_write_queue: unexpected response raises SFTPError."""
        f, client = _make_sftp_file(pipeline_depth=32)
        f._write_queue = [(1, 5)]
        client._receive_message_for_id.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            f._flush_write_queue()

    def test_flush_write_queue_error_status_raises(self):
        """_flush_write_queue: error status raises SFTPError."""
        f, client = _make_sftp_file(pipeline_depth=32)
        f._write_queue = [(1, 5)]
        client._receive_message_for_id.return_value = _make_err_status(
            code=SSH_FX_FAILURE, msg="disk full"
        )
        with pytest.raises(SFTPError):
            f._flush_write_queue()

    def test_flush_write_queue_success(self):
        """_flush_write_queue drains queue successfully."""
        f, client = _make_sftp_file(pipeline_depth=32)
        f._offset = 0
        f._write_queue = [(1, 10), (2, 5)]
        client._receive_message_for_id.return_value = _make_ok_status()
        f._flush_write_queue()
        assert f._offset == 15
        assert len(f._write_queue) == 0


# ---------------------------------------------------------------------------
# SFTPClient._send_message / _receive_message - no channel
# ---------------------------------------------------------------------------


class TestSFTPClientChannelGuards:
    def test_send_message_no_channel_raises(self):
        client, _ = _make_sftp_client()
        client._channel = None
        with pytest.raises(SFTPError, match="channel not available"):
            client._send_message(MagicMock())

    def test_receive_message_no_channel_raises(self):
        client, _ = _make_sftp_client()
        client._channel = None
        with pytest.raises(SFTPError, match="channel not available"):
            client._receive_message()

    def test_send_message_channel_error_raises(self):
        client, channel = _make_sftp_client()
        channel.sendall.side_effect = OSError("broken pipe")
        mock_msg = MagicMock()
        mock_msg.pack.return_value = b"\x00" * 10
        with pytest.raises(SFTPError, match="Failed to send"):
            client._send_message(mock_msg)

    def test_receive_message_channel_error_raises(self):
        client, channel = _make_sftp_client()
        channel.recv_exactly.side_effect = OSError("connection reset")
        with pytest.raises(SFTPError, match="Failed to receive"):
            client._receive_message()


# ---------------------------------------------------------------------------
# SFTPClient._receive_message_for_id - timeout
# ---------------------------------------------------------------------------


class TestSFTPClientReceiveTimeout:
    def test_receive_timeout_raises(self):
        client, channel = _make_sftp_client()

        def slow_recv(n):
            # Simulate always returning wrong IDs
            raise SFTPError("Timeout", SSH_FX_FAILURE)

        client._receive_message = slow_recv  # type: ignore[assignment]

        # Set a very small deadline
        with patch("spindlex.client.sftp_client.time") as mock_time:
            mock_time.monotonic.side_effect = [
                0.0,
                1000.0,
            ]  # deadline immediately passed
            with pytest.raises(SFTPError, match="Timeout"):
                client._receive_message_for_id(999, timeout=1.0)


# ---------------------------------------------------------------------------
# SFTPClient.get
# ---------------------------------------------------------------------------


class TestSFTPClientGet:
    def test_get_success(self):
        client, _ = _make_sftp_client()
        handle = b"get_handle"

        # _send_request_and_wait_response is called for: open, close
        # _receive_message_for_id is called for each pipelined read
        # With _DEPTH=32, up to 32 reads are pipelined. Return EOF for all.
        sarwr_responses = [
            _make_handle_msg(handle=handle),  # open
            _make_ok_status(3),  # close
        ]
        sarwr_idx = [0]

        recv_call = [0]

        def fake_sarwr(req):
            r = sarwr_responses[sarwr_idx[0]]
            sarwr_idx[0] += 1
            return r

        def fake_send_msg(msg):
            pass

        def fake_recv_for_id(target_id, timeout=60.0):
            recv_call[0] += 1
            if recv_call[0] == 1:
                return _make_data_msg(target_id, b"chunk data")
            # EOF for all subsequent reads
            return _make_err_status(target_id, SSH_FX_EOF)

        client._send_request_and_wait_response = fake_sarwr
        client._send_message = fake_send_msg
        client._receive_message_for_id = fake_recv_for_id

        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp = f.name
        try:
            client.get("/remote/file.txt", tmp)
            with open(tmp, "rb") as f:
                content = f.read()
            assert b"chunk data" in content
        finally:
            os.unlink(tmp)

    def test_get_open_status_ok_raises(self):
        """get(): open returning SSH_FX_OK status raises."""
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp = f.name
        try:
            with pytest.raises(SFTPError):
                client.get("/remote/file.txt", tmp)
        finally:
            os.unlink(tmp)

    def test_get_open_unexpected_raises(self):
        """get(): open returning unexpected type raises."""
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_attrs_msg()
        )
        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp = f.name
        try:
            with pytest.raises(SFTPError):
                client.get("/remote/file.txt", tmp)
        finally:
            os.unlink(tmp)

    def test_get_read_unexpected_raises(self):
        """get(): unexpected response during read raises."""
        client, _ = _make_sftp_client()

        call_count = [0]

        def fake_sarwr(req):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_handle_msg(handle=b"h")
            return _make_ok_status()  # close

        call2 = [0]

        def fake_recv_id(target_id, timeout=60.0):
            call2[0] += 1
            return _make_handle_msg()  # unexpected during read

        client._send_request_and_wait_response = fake_sarwr
        client._send_message = MagicMock()
        client._receive_message_for_id = fake_recv_id

        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp = f.name
        try:
            with pytest.raises(SFTPError):
                client.get("/remote/file.txt", tmp)
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# SFTPClient.put
# ---------------------------------------------------------------------------


class TestSFTPClientPut:
    def test_put_open_status_ok_raises(self):
        """put(): open returning SSH_FX_OK status raises."""
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"data")
            tmp = f.name
        try:
            with pytest.raises(SFTPError):
                client.put(tmp, "/remote/file.txt")
        finally:
            os.unlink(tmp)

    def test_put_open_unexpected_raises(self):
        """put(): open returning unexpected type raises."""
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_attrs_msg()
        )
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"data")
            tmp = f.name
        try:
            with pytest.raises(SFTPError):
                client.put(tmp, "/remote/file.txt")
        finally:
            os.unlink(tmp)

    def test_put_write_unexpected_raises(self):
        """put(): unexpected response during write ACK raises."""
        client, _ = _make_sftp_client()

        call_count = [0]

        def fake_sarwr(req):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_handle_msg(handle=b"h")
            return _make_ok_status()

        client._send_request_and_wait_response = fake_sarwr
        client._send_message = MagicMock()
        client._receive_message_for_id = MagicMock(return_value=_make_handle_msg())

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"data")
            tmp = f.name
        try:
            with pytest.raises(SFTPError):
                client.put(tmp, "/remote/file.txt")
        finally:
            os.unlink(tmp)


# ---------------------------------------------------------------------------
# SFTPClient.get_recursive / put_recursive
# ---------------------------------------------------------------------------


class TestSFTPClientRecursive:
    def test_get_recursive_file(self):
        """get_recursive with plain file calls get."""
        client, _ = _make_sftp_client()
        attrs = SFTPAttributes()
        attrs.st_mode = 0o100644  # regular file
        client.stat = MagicMock(return_value=attrs)
        client.get = MagicMock()

        with tempfile.TemporaryDirectory() as tmp:
            client.get_recursive("/remote/file.txt", os.path.join(tmp, "file.txt"))
        client.get.assert_called_once()

    def test_get_recursive_directory(self):
        """get_recursive with directory calls listdir."""
        import stat as stat_module

        client, _ = _make_sftp_client()
        dir_attrs = SFTPAttributes()
        dir_attrs.st_mode = stat_module.S_IFDIR | 0o755

        call_count = [0]

        def mock_stat(path):
            call_count[0] += 1
            if call_count[0] == 1:
                return dir_attrs
            a = SFTPAttributes()
            a.st_mode = 0o100644
            return a

        client.stat = mock_stat
        client.listdir = MagicMock(return_value=["file.txt"])
        client.get = MagicMock()

        with tempfile.TemporaryDirectory() as tmp:
            local_dir = os.path.join(tmp, "subdir")
            client.get_recursive("/remote/dir", local_dir)

        client.listdir.assert_called_once()

    def test_put_recursive_file(self):
        """put_recursive with plain file calls put."""
        client, _ = _make_sftp_client()
        client.put = MagicMock()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )

        with tempfile.NamedTemporaryFile(delete=False) as f:
            tmp = f.name
        try:
            client.put_recursive(tmp, "/remote/file.txt")
            client.put.assert_called_once()
        finally:
            os.unlink(tmp)

    def test_put_recursive_directory(self):
        """put_recursive with directory calls mkdir and recurses."""
        client, _ = _make_sftp_client()
        client.mkdir = MagicMock()
        client.put = MagicMock()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "f.txt"), "w") as f:
                f.write("data")
            client.put_recursive(tmp, "/remote/dir")

        client.mkdir.assert_called()

    def test_put_recursive_mkdir_failure_ignored(self):
        """put_recursive ignores SSH_FX_FAILURE from mkdir (directory already exists)."""
        client, _ = _make_sftp_client()
        client.mkdir = MagicMock(
            side_effect=SFTPError.from_status(SFTPError.SSH_FX_FAILURE, "exists")
        )
        client.put = MagicMock()

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "f.txt"), "w") as f:
                f.write("x")
            client.put_recursive(tmp, "/remote/existing")

        client.put.assert_called()

    def test_put_recursive_mkdir_permission_denied_raises(self):
        """put_recursive re-raises non-FAILURE SFTPErrors like permission denied."""
        client, _ = _make_sftp_client()
        client.mkdir = MagicMock(
            side_effect=SFTPError.from_status(SFTPError.SSH_FX_PERMISSION_DENIED)
        )
        client.put = MagicMock()

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "f.txt"), "w") as f:
                f.write("x")
            with pytest.raises(SFTPError):
                client.put_recursive(tmp, "/remote/existing")


# ---------------------------------------------------------------------------
# SFTPClient.listdir - error paths
# ---------------------------------------------------------------------------


class TestSFTPClientListdirErrors:
    def test_listdir_opendir_status_ok_raises(self):
        """listdir: OK status from opendir raises."""
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )
        with pytest.raises(SFTPError):
            client.listdir("/path")

    def test_listdir_opendir_unexpected_raises(self):
        """listdir: unexpected response from opendir raises."""
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.listdir("/path")

    def test_listdir_readdir_error_raises(self):
        """listdir: non-EOF error from readdir raises."""
        client, _ = _make_sftp_client()
        call_count = [0]

        def fake_sarwr(req):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_handle_msg(handle=b"dh")
            if call_count[0] == 2:
                return _make_err_status(code=SSH_FX_FAILURE)
            return _make_ok_status()  # close

        client._send_request_and_wait_response = fake_sarwr
        with pytest.raises(SFTPError):
            client.listdir("/path")

    def test_listdir_readdir_unexpected_raises(self):
        """listdir: unexpected response from readdir raises."""
        client, _ = _make_sftp_client()
        call_count = [0]

        def fake_sarwr(req):
            call_count[0] += 1
            if call_count[0] == 1:
                return _make_handle_msg(handle=b"dh")
            if call_count[0] == 2:
                return _make_attrs_msg()  # unexpected
            return _make_ok_status()

        client._send_request_and_wait_response = fake_sarwr
        with pytest.raises(SFTPError):
            client.listdir("/path")


# ---------------------------------------------------------------------------
# SFTPClient.stat / lstat / chmod - unexpected paths
# ---------------------------------------------------------------------------


class TestSFTPClientStatChmodUnexpected:
    def test_stat_status_ok_raises(self):
        """stat: status OK raises (unexpected)."""
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )
        with pytest.raises(SFTPError):
            client.stat("/path")

    def test_stat_unexpected_type_raises(self):
        """stat: unexpected message type raises."""
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.stat("/path")

    def test_lstat_status_ok_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )
        with pytest.raises(SFTPError):
            client.lstat("/path")

    def test_lstat_unexpected_type_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.lstat("/path")

    def test_chmod_unexpected_response_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.chmod("/path", 0o755)


# ---------------------------------------------------------------------------
# SFTPClient.mkdir / rmdir / remove / rename - unexpected
# ---------------------------------------------------------------------------


class TestSFTPClientOpsUnexpected:
    def test_mkdir_unexpected_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.mkdir("/new/dir")

    def test_rmdir_unexpected_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.rmdir("/old/dir")

    def test_remove_unexpected_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.remove("/file.txt")

    def test_rename_unexpected_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.rename("/old.txt", "/new.txt")

    def test_symlink_unexpected_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.symlink("/target", "/link")


# ---------------------------------------------------------------------------
# SFTPClient.getcwd / normalize / readlink - unexpected and empty paths
# ---------------------------------------------------------------------------


class TestSFTPClientPathOps:
    def test_getcwd_status_ok_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )
        with pytest.raises(SFTPError):
            client.getcwd()

    def test_getcwd_empty_names_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=SFTPNameMessage(1, [])
        )
        with pytest.raises(SFTPError, match="Empty"):
            client.getcwd()

    def test_getcwd_unexpected_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.getcwd()

    def test_normalize_status_ok_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )
        with pytest.raises(SFTPError):
            client.normalize("/path")

    def test_normalize_empty_names_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=SFTPNameMessage(1, [])
        )
        with pytest.raises(SFTPError, match="Empty"):
            client.normalize("/path")

    def test_normalize_unexpected_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.normalize("/path")

    def test_readlink_status_ok_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_ok_status()
        )
        with pytest.raises(SFTPError):
            client.readlink("/link")

    def test_readlink_empty_names_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=SFTPNameMessage(1, [])
        )
        with pytest.raises(SFTPError, match="Empty"):
            client.readlink("/link")

    def test_readlink_unexpected_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.readlink("/link")


# ---------------------------------------------------------------------------
# SFTPClient.open - unexpected path
# ---------------------------------------------------------------------------


class TestSFTPClientOpenUnexpected:
    def test_open_unexpected_response_raises(self):
        client, _ = _make_sftp_client()
        client._send_request_and_wait_response = MagicMock(
            return_value=_make_data_msg()
        )
        with pytest.raises(SFTPError):
            client.open("/file.txt", "r")
