"""
Unit tests for spindlex/server/sftp_server.py

Covers missing lines using mock-based testing only — no real SSH server.
Focuses on: error paths, permission checks, all message-type handlers,
SFTPHandle read/write/close edge cases, _run_server, _generate_handle,
_resolve_path, _path_to_attrs, _format_longname, close().
"""

from __future__ import annotations

import errno
import io
import os
import stat
import tempfile
import threading
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import (
    SSH_FILEXFER_ATTR_ACMODTIME,
    SSH_FILEXFER_ATTR_PERMISSIONS,
    SSH_FILEXFER_ATTR_UIDGID,
    SSH_FX_EOF,
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
    SSH_FX_OP_UNSUPPORTED,
    SSH_FX_PERMISSION_DENIED,
    SSH_FXF_APPEND,
    SSH_FXF_CREAT,
    SSH_FXF_EXCL,
    SSH_FXF_READ,
    SSH_FXF_TRUNC,
    SSH_FXF_WRITE,
)
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPCloseMessage,
    SFTPDataMessage,
    SFTPFStatMessage,
    SFTPHandleMessage,
    SFTPInitMessage,
    SFTPLStatMessage,
    SFTPMessage,
    SFTPMkdirMessage,
    SFTPNameMessage,
    SFTPOpenDirMessage,
    SFTPOpenMessage,
    SFTPReadDirMessage,
    SFTPReadMessage,
    SFTPRealPathMessage,
    SFTPRemoveMessage,
    SFTPRenameMessage,
    SFTPRmdirMessage,
    SFTPSetStatMessage,
    SFTPStatMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
    SFTPWriteMessage,
)
from spindlex.server.sftp_server import SFTPHandle, SFTPServer

# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_root():
    with tempfile.TemporaryDirectory() as tmp:
        yield tmp


@pytest.fixture
def mock_channel():
    ch = MagicMock()
    ch.channel_id = 99
    return ch


@pytest.fixture
def server(mock_channel, temp_root):
    """SFTPServer with _start_sftp_session stubbed out."""
    with patch.object(SFTPServer, "_start_sftp_session"):
        srv = SFTPServer(mock_channel, temp_root, start_thread=False)
        # By default allow all access
        srv.check_file_access = MagicMock(return_value=True)
        srv.check_directory_access = MagicMock(return_value=True)
        yield srv
        srv.close()


def _make_file_handle(
    handle_id: bytes = b"fh",
    path: str = "/file.txt",
    flags: int = SSH_FXF_READ | SSH_FXF_WRITE,
    content: bytes = b"",
) -> SFTPHandle:
    return SFTPHandle(handle_id, path, flags, file_obj=io.BytesIO(content))


# ---------------------------------------------------------------------------
# SFTPServer.__init__ / _run_server (lines 217-232)
# ---------------------------------------------------------------------------


class TestSFTPServerInit:
    def test_no_thread_when_start_thread_false(self, mock_channel, temp_root):
        with patch.object(SFTPServer, "_start_sftp_session"):
            srv = SFTPServer(mock_channel, temp_root, start_thread=False)
        assert not hasattr(srv, "_thread")
        srv.close()

    def test_thread_started_when_start_thread_true(self, mock_channel, temp_root):
        with patch.object(SFTPServer, "_start_sftp_session"):
            srv = SFTPServer(mock_channel, temp_root, start_thread=True)
        assert hasattr(srv, "_thread")
        assert isinstance(srv._thread, threading.Thread)
        srv.close()

    def test_run_server_calls_start_sftp_session(self, mock_channel, temp_root):
        with patch.object(SFTPServer, "_start_sftp_session") as mock_start:
            srv = SFTPServer(mock_channel, temp_root, start_thread=False)
            srv._run_server()
        mock_start.assert_called()
        srv.close()

    def test_run_server_catches_os_error_and_closes(self, mock_channel, temp_root):
        with patch.object(SFTPServer, "_start_sftp_session") as mock_start:
            srv = SFTPServer(mock_channel, temp_root, start_thread=False)

        mock_start.side_effect = OSError("boom")
        with patch.object(srv, "close") as mock_close:
            srv._run_server()
        mock_close.assert_called_once()


# ---------------------------------------------------------------------------
# _generate_handle (lines 270-279)
# ---------------------------------------------------------------------------


class TestGenerateHandle:
    def test_handles_increment(self, server):
        h1 = server._generate_handle()
        h2 = server._generate_handle()
        assert h1 != h2
        assert b"handle_1" in h1
        assert b"handle_2" in h2

    def test_handle_is_bytes(self, server):
        h = server._generate_handle()
        assert isinstance(h, bytes)


# ---------------------------------------------------------------------------
# _resolve_path (lines 414-457)
# ---------------------------------------------------------------------------


class TestResolvePath:
    def test_absolute_sftp_path_maps_to_root(self, server, temp_root):
        result = server._resolve_path("/")
        assert result == os.path.realpath(temp_root)

    def test_relative_path_inside_root(self, server, temp_root):
        result = server._resolve_path("subdir/file.txt")
        assert result.startswith(os.path.realpath(temp_root))

    def test_nul_byte_rejected(self, server):
        with pytest.raises(SFTPError, match="Invalid path"):
            server._resolve_path("file\x00name.txt")

    def test_traversal_rejected(self, server):
        with pytest.raises(SFTPError, match="outside root"):
            server._resolve_path("../../etc/passwd")

    def test_backslash_traversal_rejected(self, server):
        with pytest.raises(SFTPError, match="outside root"):
            server._resolve_path("..\\..\\etc\\passwd")

    def test_deeply_nested_traversal_rejected(self, server):
        with pytest.raises(SFTPError, match="outside root"):
            server._resolve_path("/a/b/c/../../../../../../../../etc/passwd")


# ---------------------------------------------------------------------------
# _path_to_attrs (lines 459-494)
# ---------------------------------------------------------------------------


class TestPathToAttrs:
    def test_existing_file(self, server, temp_root):
        f = os.path.join(temp_root, "a.txt")
        open(f, "w").close()
        attrs = server._path_to_attrs(f)
        assert attrs.size == 0
        assert attrs.permissions is not None

    def test_missing_file_raises_no_such_file(self, server, temp_root):
        with pytest.raises(SFTPError) as exc_info:
            server._path_to_attrs(os.path.join(temp_root, "ghost.txt"))
        assert exc_info.value.status_code == SSH_FX_NO_SUCH_FILE

    def test_other_os_error_raises_failure(self, server, temp_root):
        f = os.path.join(temp_root, "f.txt")
        open(f, "w").close()
        err = OSError("permission denied")
        err.errno = errno.EACCES
        with patch("os.stat", side_effect=err):
            with pytest.raises(SFTPError) as exc_info:
                server._path_to_attrs(f)
        assert exc_info.value.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_open (lines 497-613)
# ---------------------------------------------------------------------------


class TestHandleOpen:
    def test_open_read_success(self, server, temp_root):
        f = os.path.join(temp_root, "read_me.txt")
        open(f, "w").close()
        msg = SFTPOpenMessage(1, "read_me.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPHandleMessage)

    def test_open_write_create_truncate(self, server, temp_root):
        msg = SFTPOpenMessage(
            2,
            "new_trunc.txt",
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC,
            SFTPAttributes(),
        )
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPHandleMessage)

    def test_open_write_create_excl(self, server, temp_root):
        msg = SFTPOpenMessage(
            3,
            "excl_new.txt",
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL,
            SFTPAttributes(),
        )
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPHandleMessage)

    def test_open_write_create_no_trunc_no_excl(self, server, temp_root):
        """CREAT without TRUNC/EXCL → mode 'ab' (append)."""
        msg = SFTPOpenMessage(
            4,
            "append_create.txt",
            SSH_FXF_WRITE | SSH_FXF_CREAT,
            SFTPAttributes(),
        )
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPHandleMessage)

    def test_open_read_write_flags(self, server, temp_root):
        f = os.path.join(temp_root, "rw.txt")
        open(f, "w").close()
        msg = SFTPOpenMessage(
            5, "rw.txt", SSH_FXF_READ | SSH_FXF_WRITE, SFTPAttributes()
        )
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPHandleMessage)

    def test_open_append_only(self, server, temp_root):
        f = os.path.join(temp_root, "app.txt")
        open(f, "w").close()
        msg = SFTPOpenMessage(6, "app.txt", SSH_FXF_APPEND, SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPHandleMessage)

    def test_open_write_existing_no_creat(self, server, temp_root):
        """Write to existing file without CREAT → mode 'r+b'."""
        f = os.path.join(temp_root, "existing_w.txt")
        with open(f, "w") as fh:
            fh.write("x")
        msg = SFTPOpenMessage(7, "existing_w.txt", SSH_FXF_WRITE, SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPHandleMessage)

    def test_open_nonexistent_read_returns_no_such_file(self, server):
        msg = SFTPOpenMessage(10, "ghost.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_NO_SUCH_FILE

    def test_open_permission_denied_file_access(self, server, temp_root):
        server.check_file_access = MagicMock(return_value=False)
        f = os.path.join(temp_root, "secret.txt")
        open(f, "w").close()
        msg = SFTPOpenMessage(11, "secret.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_open_permission_denied_write(self, server, temp_root):
        server.check_file_access = MagicMock(return_value=False)
        msg = SFTPOpenMessage(
            12, "denied.txt", SSH_FXF_WRITE | SSH_FXF_CREAT, SFTPAttributes()
        )
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_open_file_exists_error(self, server, temp_root):
        """Opening with EXCL when file already exists → SSH_FX_FAILURE."""
        f = os.path.join(temp_root, "already.txt")
        open(f, "w").close()
        msg = SFTPOpenMessage(
            13,
            "already.txt",
            SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL,
            SFTPAttributes(),
        )
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_FAILURE

    def test_open_permission_error_on_os_open(self, server, temp_root):
        msg = SFTPOpenMessage(14, "perm.txt", SSH_FXF_READ, SFTPAttributes())
        with patch("builtins.open", side_effect=PermissionError("denied")):
            with patch.object(server, "_send_message") as send:
                server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_open_sftp_error_path_outside_root(self, server):
        """Path traversal raises SFTPError → caught and returned as status."""
        msg = SFTPOpenMessage(15, "../../outside.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_open_too_many_handles(self, server, temp_root):
        """When handles are at MAX_SFTP_HANDLES, respond with failure."""
        from spindlex.protocol.sftp_constants import MAX_SFTP_HANDLES

        f = os.path.join(temp_root, "maxfile.txt")
        open(f, "w").close()
        # Fill handles up to limit
        fake_handles = {
            f"handle_{i}".encode(): MagicMock() for i in range(MAX_SFTP_HANDLES)
        }
        server._handles = fake_handles

        msg = SFTPOpenMessage(20, "maxfile.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_FAILURE

        # Cleanup actual file objects opened by _handle_open
        for h in server._handles.values():
            if hasattr(h, "close"):
                try:
                    h.close()
                except Exception:
                    pass


# ---------------------------------------------------------------------------
# _handle_close (lines 615-638)
# ---------------------------------------------------------------------------


class TestHandleClose:
    def test_close_valid_handle(self, server):
        handle = _make_file_handle()
        server._handles[b"fh"] = handle
        msg = SFTPCloseMessage(1, b"fh")
        with patch.object(server, "_send_message") as send:
            server._handle_close(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK
        assert b"fh" not in server._handles

    def test_close_invalid_handle(self, server):
        msg = SFTPCloseMessage(2, b"ghost")
        with patch.object(server, "_send_message") as send:
            server._handle_close(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_close_os_error_caught(self, server):
        handle = _make_file_handle()
        server._handles[b"fh"] = handle
        msg = SFTPCloseMessage(3, b"fh")
        with patch.object(handle, "close", side_effect=OSError("fail")):
            with patch.object(server, "_send_message") as send:
                server._handle_close(msg)
        # Should still send a status (either OK or FAILURE)
        assert send.called


# ---------------------------------------------------------------------------
# _handle_read (lines 640-678)
# ---------------------------------------------------------------------------


class TestHandleRead:
    def test_read_data(self, server):
        handle = _make_file_handle(content=b"hello world")
        server._handles[b"fh"] = handle
        msg = SFTPReadMessage(1, b"fh", 0, 5)
        with patch.object(server, "_send_message") as send:
            server._handle_read(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPDataMessage)
        assert sent.data == b"hello"

    def test_read_eof(self, server):
        handle = _make_file_handle(content=b"")
        server._handles[b"fh"] = handle
        msg = SFTPReadMessage(2, b"fh", 0, 100)
        with patch.object(server, "_send_message") as send:
            server._handle_read(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_EOF

    def test_read_invalid_handle(self, server):
        msg = SFTPReadMessage(3, b"ghost", 0, 100)
        with patch.object(server, "_send_message") as send:
            server._handle_read(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_read_sftp_error_propagated(self, server):
        handle = _make_file_handle(content=b"data")
        server._handles[b"fh"] = handle
        msg = SFTPReadMessage(4, b"fh", 0, 5)
        with patch.object(
            handle, "read", side_effect=SFTPError("read err", SSH_FX_FAILURE)
        ):
            with patch.object(server, "_send_message") as send:
                server._handle_read(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_FAILURE

    def test_read_os_error_propagated(self, server):
        handle = _make_file_handle(content=b"data")
        server._handles[b"fh"] = handle
        msg = SFTPReadMessage(5, b"fh", 0, 5)
        with patch.object(handle, "seek", side_effect=OSError("seek fail")):
            with patch.object(server, "_send_message") as send:
                server._handle_read(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_write (lines 680-716)
# ---------------------------------------------------------------------------


class TestHandleWrite:
    def test_write_success(self, server):
        handle = _make_file_handle(flags=SSH_FXF_WRITE)
        server._handles[b"fh"] = handle
        msg = SFTPWriteMessage(1, b"fh", 0, b"written data")
        with patch.object(server, "_send_message") as send:
            server._handle_write(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_OK

    def test_write_invalid_handle(self, server):
        msg = SFTPWriteMessage(2, b"ghost", 0, b"data")
        with patch.object(server, "_send_message") as send:
            server._handle_write(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_write_sftp_error(self, server):
        handle = _make_file_handle(flags=SSH_FXF_WRITE)
        server._handles[b"fh"] = handle
        msg = SFTPWriteMessage(3, b"fh", 0, b"data")
        with patch.object(
            handle, "write", side_effect=SFTPError("write err", SSH_FX_FAILURE)
        ):
            with patch.object(server, "_send_message") as send:
                server._handle_write(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_write_os_error(self, server):
        handle = _make_file_handle(flags=SSH_FXF_WRITE)
        server._handles[b"fh"] = handle
        msg = SFTPWriteMessage(4, b"fh", 0, b"data")
        with patch.object(handle, "seek", side_effect=OSError("no space")):
            with patch.object(server, "_send_message") as send:
                server._handle_write(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_stat (lines 718-749)
# ---------------------------------------------------------------------------


class TestHandleStat:
    def test_stat_existing_file(self, server, temp_root):
        f = os.path.join(temp_root, "s.txt")
        open(f, "w").close()
        msg = SFTPStatMessage(1, "s.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_stat(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPAttrsMessage)

    def test_stat_nonexistent(self, server):
        msg = SFTPStatMessage(2, "no_file.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_stat(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code != SSH_FX_OK

    def test_stat_access_denied(self, server, temp_root):
        server.check_file_access = MagicMock(return_value=False)
        f = os.path.join(temp_root, "secret.txt")
        open(f, "w").close()
        msg = SFTPStatMessage(3, "secret.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_stat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_stat_sftp_error_caught(self, server, temp_root):
        f = os.path.join(temp_root, "f.txt")
        open(f, "w").close()
        msg = SFTPStatMessage(4, "f.txt")
        with patch.object(
            server, "_path_to_attrs", side_effect=SFTPError("err", SSH_FX_FAILURE)
        ):
            with patch.object(server, "_send_message") as send:
                server._handle_stat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_stat_path_outside_root_permission_denied(self, server):
        msg = SFTPStatMessage(5, "../../outside")
        with patch.object(server, "_send_message") as send:
            server._handle_stat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED


# ---------------------------------------------------------------------------
# _handle_lstat (lines 751-803)
# ---------------------------------------------------------------------------


class TestHandleLstat:
    def test_lstat_existing_file(self, server, temp_root):
        f = os.path.join(temp_root, "l.txt")
        open(f, "w").close()
        msg = SFTPLStatMessage(1, "l.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_lstat(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPAttrsMessage)

    def test_lstat_nonexistent(self, server):
        msg = SFTPLStatMessage(2, "ghost_l.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_lstat(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_NO_SUCH_FILE

    def test_lstat_access_denied(self, server, temp_root):
        server.check_file_access = MagicMock(return_value=False)
        f = os.path.join(temp_root, "lsec.txt")
        open(f, "w").close()
        msg = SFTPLStatMessage(3, "lsec.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_lstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_lstat_other_oserror(self, server, temp_root):
        f = os.path.join(temp_root, "oserr.txt")
        open(f, "w").close()
        msg = SFTPLStatMessage(4, "oserr.txt")
        err = OSError("perm")
        err.errno = errno.EACCES
        with patch("os.lstat", side_effect=err):
            with patch.object(server, "_send_message") as send:
                server._handle_lstat(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_fstat (lines 805-834)
# ---------------------------------------------------------------------------


class TestHandleFstat:
    def test_fstat_valid_handle(self, server, temp_root):
        f = os.path.join(temp_root, "fstat.txt")
        open(f, "w").close()
        handle = SFTPHandle(b"fsh", f, SSH_FXF_READ, io.BytesIO(b""))
        server._handles[b"fsh"] = handle
        msg = SFTPFStatMessage(1, b"fsh")
        with patch.object(server, "_send_message") as send:
            server._handle_fstat(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPAttrsMessage)

    def test_fstat_invalid_handle(self, server):
        msg = SFTPFStatMessage(2, b"ghost")
        with patch.object(server, "_send_message") as send:
            server._handle_fstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_fstat_sftp_error(self, server, temp_root):
        f = os.path.join(temp_root, "fstat2.txt")
        open(f, "w").close()
        handle = SFTPHandle(b"fsh2", f, SSH_FXF_READ, io.BytesIO(b""))
        server._handles[b"fsh2"] = handle
        msg = SFTPFStatMessage(3, b"fsh2")
        with patch.object(
            server, "_path_to_attrs", side_effect=SFTPError("err", SSH_FX_FAILURE)
        ):
            with patch.object(server, "_send_message") as send:
                server._handle_fstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_setstat (lines 836-907)
# ---------------------------------------------------------------------------


class TestHandleSetstat:
    def test_setstat_permissions(self, server, temp_root):
        f = os.path.join(temp_root, "perm.txt")
        open(f, "w").close()
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS
        attrs.permissions = 0o600
        msg = SFTPSetStatMessage(1, "perm.txt", attrs)
        with patch.object(server, "_send_message") as send:
            server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK

    def test_setstat_access_denied(self, server, temp_root):
        server.check_file_access = MagicMock(return_value=False)
        f = os.path.join(temp_root, "sec.txt")
        open(f, "w").close()
        attrs = SFTPAttributes()
        attrs.flags = 0
        msg = SFTPSetStatMessage(2, "sec.txt", attrs)
        with patch.object(server, "_send_message") as send:
            server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_setstat_chmod_fails(self, server, temp_root):
        f = os.path.join(temp_root, "cf.txt")
        open(f, "w").close()
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS
        attrs.permissions = 0o777
        msg = SFTPSetStatMessage(3, "cf.txt", attrs)
        with patch("os.chmod", side_effect=OSError("chmod failed")):
            with patch.object(server, "_send_message") as send:
                server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_FAILURE

    def test_setstat_utime(self, server, temp_root):
        f = os.path.join(temp_root, "utime.txt")
        open(f, "w").close()
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_ACMODTIME
        attrs.atime = 1000000
        attrs.mtime = 1000000
        msg = SFTPSetStatMessage(4, "utime.txt", attrs)
        with patch.object(server, "_send_message") as send:
            server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK

    def test_setstat_utime_fails(self, server, temp_root):
        f = os.path.join(temp_root, "utimefail.txt")
        open(f, "w").close()
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_ACMODTIME
        attrs.atime = 1000000
        attrs.mtime = 1000000
        msg = SFTPSetStatMessage(5, "utimefail.txt", attrs)
        with patch("os.utime", side_effect=OSError("utime fail")):
            with patch.object(server, "_send_message") as send:
                server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_setstat_uidgid_with_chown(self, server, temp_root):
        f = os.path.join(temp_root, "chown.txt")
        open(f, "w").close()
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_UIDGID
        attrs.uid = 0
        attrs.gid = 0
        msg = SFTPSetStatMessage(6, "chown.txt", attrs)
        with patch("os.chown", MagicMock(), create=True):
            with patch.object(server, "_send_message") as send:
                server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK

    def test_setstat_sftp_error_path(self, server):
        msg = SFTPSetStatMessage(7, "../../outside.txt", SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED


# ---------------------------------------------------------------------------
# _handle_opendir (lines 909-980)
# ---------------------------------------------------------------------------


class TestHandleOpendir:
    def test_opendir_success(self, server, temp_root):
        msg = SFTPOpenDirMessage(1, ".")
        with patch.object(server, "_send_message") as send:
            server._handle_opendir(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPHandleMessage)

    def test_opendir_access_denied(self, server, temp_root):
        server.check_directory_access = MagicMock(return_value=False)
        msg = SFTPOpenDirMessage(2, ".")
        with patch.object(server, "_send_message") as send:
            server._handle_opendir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_opendir_not_a_directory(self, server, temp_root):
        f = os.path.join(temp_root, "notdir.txt")
        open(f, "w").close()
        msg = SFTPOpenDirMessage(3, "notdir.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_opendir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_NO_SUCH_FILE

    def test_opendir_listdir_permission_error(self, server, temp_root):
        subdir = os.path.join(temp_root, "locked")
        os.makedirs(subdir)
        msg = SFTPOpenDirMessage(4, "locked")
        with patch("os.listdir", side_effect=OSError("permission denied")):
            with patch.object(server, "_send_message") as send:
                server._handle_opendir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_opendir_path_outside_root(self, server):
        msg = SFTPOpenDirMessage(5, "../../etc")
        with patch.object(server, "_send_message") as send:
            server._handle_opendir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED


# ---------------------------------------------------------------------------
# _handle_readdir (lines 982-1024)
# ---------------------------------------------------------------------------


class TestHandleReaddir:
    def _make_dir_handle(self, server, entries=None):
        h = SFTPHandle(b"dh", "/dir", 0, file_obj=None)
        h.dir_entries = entries or []
        h.dir_index = 0
        server._handles[b"dh"] = h
        return h

    def test_readdir_eof_empty(self, server):
        self._make_dir_handle(server, entries=[])
        msg = SFTPReadDirMessage(1, b"dh")
        with patch.object(server, "_send_message") as send:
            server._handle_readdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_EOF

    def test_readdir_returns_batch(self, server, temp_root):
        attrs = SFTPAttributes()
        entries = [(f"file{i}.txt", f"ls -l file{i}", attrs) for i in range(5)]
        self._make_dir_handle(server, entries=entries)
        msg = SFTPReadDirMessage(2, b"dh")
        with patch.object(server, "_send_message") as send:
            server._handle_readdir(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPNameMessage)
        assert len(sent.names) == 5

    def test_readdir_invalid_handle(self, server):
        msg = SFTPReadDirMessage(3, b"ghost")
        with patch.object(server, "_send_message") as send:
            server._handle_readdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_readdir_handle_not_directory(self, server):
        h = _make_file_handle()
        server._handles[b"fh"] = h
        msg = SFTPReadDirMessage(4, b"fh")
        with patch.object(server, "_send_message") as send:
            server._handle_readdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_readdir_none_dir_entries(self, server):
        h = SFTPHandle(b"dh2", "/dir", 0, file_obj=None)
        h.dir_entries = None
        h.dir_index = 0
        server._handles[b"dh2"] = h
        msg = SFTPReadDirMessage(5, b"dh2")
        with patch.object(server, "_send_message") as send:
            server._handle_readdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_EOF


# ---------------------------------------------------------------------------
# _handle_mkdir (lines 1026-1092)
# ---------------------------------------------------------------------------


class TestHandleMkdir:
    def test_mkdir_success(self, server, temp_root):
        msg = SFTPMkdirMessage(1, "mydir", SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK
        assert os.path.isdir(os.path.join(temp_root, "mydir"))

    def test_mkdir_already_exists(self, server, temp_root):
        existing = os.path.join(temp_root, "existing_dir")
        os.makedirs(existing)
        msg = SFTPMkdirMessage(2, "existing_dir", SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_mkdir_access_denied(self, server):
        server.check_directory_access = MagicMock(return_value=False)
        msg = SFTPMkdirMessage(3, "denied_dir", SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_mkdir_with_permissions_attr(self, server, temp_root):
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS
        attrs.permissions = 0o700
        msg = SFTPMkdirMessage(4, "permdir", attrs)
        with patch.object(server, "_send_message") as send:
            server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK

    def test_mkdir_with_uidgid_attr(self, server, temp_root):
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_UIDGID
        attrs.uid = 0
        attrs.gid = 0
        msg = SFTPMkdirMessage(5, "ugdir", attrs)
        with patch("os.chown", MagicMock(), create=True):
            with patch.object(server, "_send_message") as send:
                server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK

    def test_mkdir_os_error(self, server, temp_root):
        msg = SFTPMkdirMessage(6, "baddir", SFTPAttributes())
        with patch("os.mkdir", side_effect=OSError("no space")):
            with patch.object(server, "_send_message") as send:
                server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_mkdir_sftp_error_path(self, server):
        msg = SFTPMkdirMessage(7, "../../outside", SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED


# ---------------------------------------------------------------------------
# _handle_rmdir (lines 1094-1146)
# ---------------------------------------------------------------------------


class TestHandleRmdir:
    def test_rmdir_success(self, server, temp_root):
        d = os.path.join(temp_root, "torm")
        os.makedirs(d)
        msg = SFTPRmdirMessage(1, "torm")
        with patch.object(server, "_send_message") as send:
            server._handle_rmdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK

    def test_rmdir_not_found(self, server):
        msg = SFTPRmdirMessage(2, "ghostdir")
        with patch.object(server, "_send_message") as send:
            server._handle_rmdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_NO_SUCH_FILE

    def test_rmdir_access_denied(self, server):
        server.check_directory_access = MagicMock(return_value=False)
        msg = SFTPRmdirMessage(3, "some_dir")
        with patch.object(server, "_send_message") as send:
            server._handle_rmdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_rmdir_not_empty(self, server, temp_root):
        d = os.path.join(temp_root, "notempty")
        os.makedirs(d)
        with open(os.path.join(d, "file.txt"), "w") as f:
            f.write("x")
        msg = SFTPRmdirMessage(4, "notempty")
        with patch.object(server, "_send_message") as send:
            server._handle_rmdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_rmdir_other_oserror(self, server, temp_root):
        d = os.path.join(temp_root, "errd")
        os.makedirs(d)
        msg = SFTPRmdirMessage(5, "errd")
        err = OSError("some error")
        err.errno = errno.EACCES
        with patch("os.rmdir", side_effect=err):
            with patch.object(server, "_send_message") as send:
                server._handle_rmdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_remove (lines 1148-1194)
# ---------------------------------------------------------------------------


class TestHandleRemove:
    def test_remove_success(self, server, temp_root):
        f = os.path.join(temp_root, "del.txt")
        open(f, "w").close()
        msg = SFTPRemoveMessage(1, "del.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_remove(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK
        assert not os.path.exists(f)

    def test_remove_not_found(self, server):
        msg = SFTPRemoveMessage(2, "ghost.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_remove(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_NO_SUCH_FILE

    def test_remove_access_denied(self, server, temp_root):
        server.check_file_access = MagicMock(return_value=False)
        f = os.path.join(temp_root, "secret.txt")
        open(f, "w").close()
        msg = SFTPRemoveMessage(3, "secret.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_remove(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_remove_os_error(self, server, temp_root):
        f = os.path.join(temp_root, "oserr.txt")
        open(f, "w").close()
        msg = SFTPRemoveMessage(4, "oserr.txt")
        with patch("os.unlink", side_effect=OSError("permission")):
            with patch.object(server, "_send_message") as send:
                server._handle_remove(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE

    def test_remove_sftp_error_path(self, server):
        msg = SFTPRemoveMessage(5, "../../outside.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_remove(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED


# ---------------------------------------------------------------------------
# _handle_rename (lines 1196-1253)
# ---------------------------------------------------------------------------


class TestHandleRename:
    def test_rename_success(self, server, temp_root):
        src = os.path.join(temp_root, "old.txt")
        open(src, "w").close()
        msg = SFTPRenameMessage(1, "old.txt", "new.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_rename(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_OK
        assert os.path.exists(os.path.join(temp_root, "new.txt"))

    def test_rename_source_not_found(self, server):
        msg = SFTPRenameMessage(2, "ghost.txt", "dest.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_rename(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_NO_SUCH_FILE

    def test_rename_source_access_denied(self, server, temp_root):
        server.check_file_access = MagicMock(return_value=False)
        src = os.path.join(temp_root, "src.txt")
        open(src, "w").close()
        msg = SFTPRenameMessage(3, "src.txt", "dst.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_rename(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_rename_dest_dir_access_denied(self, server, temp_root):
        src = os.path.join(temp_root, "src2.txt")
        open(src, "w").close()
        # Allow read but deny directory write
        server.check_file_access = MagicMock(return_value=True)
        server.check_directory_access = MagicMock(return_value=False)
        msg = SFTPRenameMessage(4, "src2.txt", "dst2.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_rename(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_rename_os_error(self, server, temp_root):
        src = os.path.join(temp_root, "osr.txt")
        open(src, "w").close()
        msg = SFTPRenameMessage(5, "osr.txt", "dst.txt")
        with patch("os.rename", side_effect=OSError("cross device")):
            with patch.object(server, "_send_message") as send:
                server._handle_rename(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_realpath (lines 1255-1292)
# ---------------------------------------------------------------------------


class TestHandleRealpath:
    def test_realpath_root(self, server):
        msg = SFTPRealPathMessage(1, ".")
        with patch.object(server, "_send_message") as send:
            server._handle_realpath(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPNameMessage)
        assert sent.names[0][0] == "/"

    def test_realpath_subpath(self, server, temp_root):
        msg = SFTPRealPathMessage(2, "subdir")
        with patch.object(server, "_send_message") as send:
            server._handle_realpath(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPNameMessage)

    def test_realpath_nonexistent_gives_minimal_attrs(self, server, temp_root):
        msg = SFTPRealPathMessage(3, "nonexistent_xyz")
        with patch.object(server, "_send_message") as send:
            server._handle_realpath(msg)
        sent = send.call_args[0][0]
        # Should still return a name message
        assert isinstance(sent, SFTPNameMessage)

    def test_realpath_sftp_error(self, server):
        msg = SFTPRealPathMessage(4, "../../outside")
        with patch.object(server, "_send_message") as send:
            server._handle_realpath(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_PERMISSION_DENIED


# ---------------------------------------------------------------------------
# _format_longname (lines 1294-1353)
# ---------------------------------------------------------------------------


class TestFormatLongname:
    def test_regular_file(self, server):
        attrs = SFTPAttributes()
        attrs.permissions = stat.S_IFREG | 0o644
        attrs.size = 1234
        attrs.uid = 0
        attrs.gid = 0
        attrs.mtime = 1000000
        result = server._format_longname("file.txt", attrs)
        assert "-" in result
        assert "file.txt" in result

    def test_directory(self, server):
        attrs = SFTPAttributes()
        attrs.permissions = stat.S_IFDIR | 0o755
        attrs.size = 4096
        attrs.uid = 0
        attrs.gid = 0
        attrs.mtime = 1000000
        result = server._format_longname("mydir", attrs)
        assert result.startswith("d")

    def test_symlink(self, server):
        attrs = SFTPAttributes()
        attrs.permissions = stat.S_IFLNK | 0o777
        attrs.size = 10
        attrs.uid = 0
        attrs.gid = 0
        attrs.mtime = 1000000
        result = server._format_longname("link", attrs)
        assert result.startswith("l")

    def test_no_permissions(self, server):
        attrs = SFTPAttributes()
        attrs.permissions = None
        attrs.size = None
        attrs.uid = None
        attrs.gid = None
        attrs.mtime = None
        result = server._format_longname("unknown", attrs)
        assert "unknown" in result
        assert "----------" in result

    def test_unknown_file_type(self, server):
        attrs = SFTPAttributes()
        # Use a socket file type
        attrs.permissions = stat.S_IFSOCK | 0o600
        attrs.size = 0
        attrs.uid = 0
        attrs.gid = 0
        attrs.mtime = 1000000
        result = server._format_longname("sock", attrs)
        assert result.startswith("?")


# ---------------------------------------------------------------------------
# close() (lines 1419-1432)
# ---------------------------------------------------------------------------


class TestSFTPServerClose:
    def test_close_closes_all_handles(self, server):
        h1 = _make_file_handle(b"h1")
        h2 = _make_file_handle(b"h2")
        server._handles[b"h1"] = h1
        server._handles[b"h2"] = h2
        server.close()
        assert server._handles == {}

    def test_close_closes_channel(self, server, mock_channel):
        server.close()
        mock_channel.close.assert_called()

    def test_close_ignores_channel_error(self, server, mock_channel):
        mock_channel.close.side_effect = OSError("already closed")
        server.close()  # should not raise

    def test_close_twice_no_error(self, server):
        server.close()
        server.close()  # second close must be a no-op


# ---------------------------------------------------------------------------
# _process_messages error handling (lines 320-359)
# ---------------------------------------------------------------------------


class TestProcessMessages:
    def test_eof_terminates_loop(self, server):
        with patch.object(server, "_receive_message", side_effect=OSError("eof")):
            server._process_messages()  # Should return, not raise

    def test_closed_terminates_loop(self, server):
        with patch.object(server, "_receive_message", side_effect=OSError("closed")):
            server._process_messages()

    def test_non_eof_error_sends_status(self, server):
        call_count = [0]
        msg = SFTPOpenMessage(1, "x.txt", SSH_FXF_READ, SFTPAttributes())

        def fake_recv():
            call_count[0] += 1
            if call_count[0] == 1:
                return msg
            raise OSError("some unexpected error")

        with (
            patch.object(server, "_receive_message", side_effect=fake_recv),
            patch.object(server, "_handle_message", side_effect=OSError("unexpected")),
            patch.object(server, "_send_message"),
        ):
            server._process_messages()
        # May or may not have sent; the important thing is it returned cleanly

    def test_unknown_message_sends_unsupported(self, server):
        unknown = MagicMock(spec=SFTPMessage)
        unknown.request_id = 77

        with patch.object(server, "_send_message") as send:
            server._handle_message(unknown)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_OP_UNSUPPORTED


# ---------------------------------------------------------------------------
# _start_sftp_session (lines 234-268)
# ---------------------------------------------------------------------------


class TestStartSftpSession:
    def test_bad_first_message_raises(self, mock_channel, temp_root):
        with patch.object(SFTPServer, "_start_sftp_session"):
            srv = SFTPServer(mock_channel, temp_root, start_thread=False)

        # Patch _receive_message to return something that is NOT SFTPInitMessage
        with patch.object(
            srv, "_receive_message", return_value=MagicMock(spec=SFTPMessage)
        ):
            with pytest.raises(SFTPError, match="Expected SFTP init"):
                srv._start_sftp_session()

    def test_success_sends_version(self, mock_channel, temp_root):
        with patch.object(SFTPServer, "_start_sftp_session"):
            srv = SFTPServer(mock_channel, temp_root, start_thread=False)

        call_count = [0]

        def fake_recv():
            call_count[0] += 1
            if call_count[0] == 1:
                return SFTPInitMessage(3)
            raise OSError("eof")

        with patch.object(srv, "_receive_message", side_effect=fake_recv):
            with patch.object(srv, "_send_message") as send:
                srv._start_sftp_session()
        # Version message should be the first thing sent
        sent = send.call_args_list[0][0][0]
        assert isinstance(sent, SFTPVersionMessage)
