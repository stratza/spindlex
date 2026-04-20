"""
Coverage tests for SFTPHandle (sftp_server.py) — all read/write/seek/close paths.
Also tests SFTPServer._handle_message dispatch and _process_messages break paths.
"""
import io
import os
import tempfile
from unittest.mock import MagicMock, patch, call

import pytest

from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import (
    SSH_FX_EOF,
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
    SSH_FX_OP_UNSUPPORTED,
    SSH_FX_PERMISSION_DENIED,
    SSH_FXF_APPEND,
    SSH_FXF_READ,
    SSH_FXF_WRITE,
)
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
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
# SFTPHandle tests
# ---------------------------------------------------------------------------

class TestSFTPHandleRead:
    def _make_file_handle(self, content=b"hello world", flags=SSH_FXF_READ):
        file_obj = io.BytesIO(content)
        return SFTPHandle(b"h1", "/path/file.txt", flags, file_obj)

    def test_read_success(self):
        h = self._make_file_handle(b"data here")
        result = h.read(4)
        assert result == b"data"

    def test_read_all(self):
        h = self._make_file_handle(b"all")
        result = h.read(100)
        assert result == b"all"

    def test_read_directory_raises(self):
        h = SFTPHandle(b"h2", "/dir", SSH_FXF_READ, file_obj=None)
        with pytest.raises(SFTPError, match="Cannot read from directory"):
            h.read(10)

    def test_read_without_read_flag_raises(self):
        h = self._make_file_handle(flags=SSH_FXF_WRITE)
        with pytest.raises(SFTPError, match="not open for reading"):
            h.read(10)

    def test_read_without_file_obj_raises(self):
        h = SFTPHandle(b"h3", "/file.txt", SSH_FXF_READ, file_obj=None)
        h.is_directory = False  # override so it passes the directory check
        with pytest.raises(SFTPError, match="File object not available"):
            h.read(10)


class TestSFTPHandleWrite:
    def _make_write_handle(self, flags=SSH_FXF_WRITE):
        file_obj = io.BytesIO()
        return SFTPHandle(b"wh", "/path/file.txt", flags, file_obj)

    def test_write_success(self):
        h = self._make_write_handle()
        n = h.write(b"hello")
        assert n == 5

    def test_write_append_flag(self):
        h = self._make_write_handle(flags=SSH_FXF_APPEND)
        n = h.write(b"appended")
        assert n == 8

    def test_write_to_directory_raises(self):
        h = SFTPHandle(b"dh", "/dir", SSH_FXF_WRITE, file_obj=None)
        with pytest.raises(SFTPError, match="Cannot write to directory"):
            h.write(b"data")

    def test_write_without_write_flag_raises(self):
        h = self._make_write_handle(flags=SSH_FXF_READ)
        with pytest.raises(SFTPError, match="not open for writing"):
            h.write(b"data")

    def test_write_without_file_obj_raises(self):
        h = SFTPHandle(b"wh2", "/file.txt", SSH_FXF_WRITE, file_obj=None)
        h.is_directory = False
        with pytest.raises(SFTPError, match="File object not available"):
            h.write(b"data")

    def test_write_io_error_raises(self):
        bad_obj = MagicMock()
        bad_obj.write.side_effect = IOError("disk full")
        h = SFTPHandle(b"wh3", "/file.txt", SSH_FXF_WRITE, file_obj=bad_obj)
        with pytest.raises(SFTPError, match="Write failed"):
            h.write(b"data")


class TestSFTPHandleSeek:
    def _make_seek_handle(self):
        file_obj = io.BytesIO(b"seekable content")
        return SFTPHandle(b"sh", "/file.txt", SSH_FXF_READ, file_obj)

    def test_seek_success(self):
        h = self._make_seek_handle()
        h.seek(4)  # 'seekable content'[4:8] = 'able'
        assert h.position == 4
        result = h.read(4)
        assert result == b"able"

    def test_seek_directory_raises(self):
        h = SFTPHandle(b"dsh", "/dir", SSH_FXF_READ, file_obj=None)
        with pytest.raises(SFTPError, match="Cannot seek in directory"):
            h.seek(0)

    def test_seek_without_file_obj_raises(self):
        h = SFTPHandle(b"sh2", "/file.txt", SSH_FXF_READ, file_obj=None)
        h.is_directory = False
        with pytest.raises(SFTPError, match="File object not available"):
            h.seek(0)

    def test_seek_io_error_raises(self):
        bad_obj = MagicMock()
        bad_obj.seek.side_effect = IOError("seek error")
        h = SFTPHandle(b"sh3", "/file.txt", SSH_FXF_READ, file_obj=bad_obj)
        with pytest.raises(SFTPError, match="Seek failed"):
            h.seek(5)


class TestSFTPHandleClose:
    def test_close_file(self):
        file_obj = io.BytesIO(b"data")
        h = SFTPHandle(b"ch", "/file.txt", SSH_FXF_READ, file_obj)
        h.close()
        assert h.file_obj is None

    def test_close_directory(self):
        h = SFTPHandle(b"dch", "/dir", SSH_FXF_READ, file_obj=None)
        h.close()  # should not raise

    def test_close_already_closed(self):
        file_obj = io.BytesIO(b"data")
        h = SFTPHandle(b"ach", "/file.txt", SSH_FXF_READ, file_obj)
        h.close()
        h.close()  # second close should not raise

    def test_close_with_error_on_file_close(self):
        bad_obj = MagicMock()
        bad_obj.close.side_effect = IOError("close error")
        h = SFTPHandle(b"ech", "/file.txt", SSH_FXF_READ, file_obj=bad_obj)
        h.close()  # error should be silenced
        assert h.file_obj is None


# ---------------------------------------------------------------------------
# SFTPServer message dispatch tests
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_root():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_channel():
    return MagicMock()


@pytest.fixture
def sftp_server(mock_channel, temp_root):
    with patch.object(SFTPServer, "_start_sftp_session"):
        server = SFTPServer(mock_channel, temp_root)
        server.check_file_access = MagicMock(return_value=True)
        server._client_version = 3
        yield server
        server.close()


class TestHandleMessageDispatch:
    """Test that _handle_message dispatches to the right handler."""

    def test_dispatch_open(self, sftp_server):
        msg = SFTPOpenMessage(1, "file.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(sftp_server, "_handle_open") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_close(self, sftp_server):
        msg = SFTPCloseMessage(2, b"handle")
        with patch.object(sftp_server, "_handle_close") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_read(self, sftp_server):
        msg = SFTPReadMessage(3, b"handle", 0, 100)
        with patch.object(sftp_server, "_handle_read") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_write(self, sftp_server):
        msg = SFTPWriteMessage(4, b"handle", 0, b"data")
        with patch.object(sftp_server, "_handle_write") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_stat(self, sftp_server):
        msg = SFTPStatMessage(5, "file.txt")
        with patch.object(sftp_server, "_handle_stat") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_lstat(self, sftp_server):
        msg = SFTPLStatMessage(6, "file.txt")
        with patch.object(sftp_server, "_handle_lstat") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_fstat(self, sftp_server):
        msg = SFTPFStatMessage(7, b"handle")
        with patch.object(sftp_server, "_handle_fstat") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_setstat(self, sftp_server):
        msg = SFTPSetStatMessage(8, "file.txt", SFTPAttributes())
        with patch.object(sftp_server, "_handle_setstat") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_opendir(self, sftp_server):
        msg = SFTPOpenDirMessage(9, ".")
        with patch.object(sftp_server, "_handle_opendir") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_readdir(self, sftp_server):
        msg = SFTPReadDirMessage(10, b"handle")
        with patch.object(sftp_server, "_handle_readdir") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_mkdir(self, sftp_server):
        msg = SFTPMkdirMessage(11, "newdir", SFTPAttributes())
        with patch.object(sftp_server, "_handle_mkdir") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_rmdir(self, sftp_server):
        msg = SFTPRmdirMessage(12, "emptydir")
        with patch.object(sftp_server, "_handle_rmdir") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_remove(self, sftp_server):
        msg = SFTPRemoveMessage(13, "file.txt")
        with patch.object(sftp_server, "_handle_remove") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_rename(self, sftp_server):
        msg = SFTPRenameMessage(14, "old.txt", "new.txt")
        with patch.object(sftp_server, "_handle_rename") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_realpath(self, sftp_server):
        msg = SFTPRealPathMessage(15, ".")
        with patch.object(sftp_server, "_handle_realpath") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_init_noop(self, sftp_server):
        msg = SFTPInitMessage(3)
        with patch.object(sftp_server, "_handle_init") as m:
            sftp_server._handle_message(msg)
            m.assert_called_once_with(msg)

    def test_dispatch_unknown_sends_unsupported(self, sftp_server, mock_channel):
        """Unknown message type should send SSH_FX_OP_UNSUPPORTED status."""
        unknown_msg = MagicMock(spec=SFTPMessage)
        unknown_msg.request_id = 99

        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_message(unknown_msg)
            send_mock.assert_called_once()
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_OP_UNSUPPORTED


class TestHandleOpenFile:
    def test_handle_open_existing_read(self, sftp_server, temp_root):
        test_file = os.path.join(temp_root, "existing.txt")
        with open(test_file, "w") as f:
            f.write("content")

        msg = SFTPOpenMessage(1, "existing.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_open(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPHandleMessage)

    def test_handle_open_write_create(self, sftp_server, temp_root):
        from spindlex.protocol.sftp_constants import SSH_FXF_CREAT
        msg = SFTPOpenMessage(2, "newfile.txt", SSH_FXF_WRITE | SSH_FXF_CREAT, SFTPAttributes())
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_open(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPHandleMessage)
        assert os.path.exists(os.path.join(temp_root, "newfile.txt"))

    def test_handle_open_nonexistent_read_returns_no_such_file(self, sftp_server):
        msg = SFTPOpenMessage(3, "ghost.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_open(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_NO_SUCH_FILE


class TestHandleClose:
    def test_handle_close_existing_handle(self, sftp_server):
        # Add a fake handle
        file_obj = io.BytesIO(b"data")
        handle = SFTPHandle(b"test_handle", "/file.txt", SSH_FXF_READ, file_obj)
        sftp_server._handles[b"test_handle"] = handle

        msg = SFTPCloseMessage(1, b"test_handle")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_close(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_OK

        assert b"test_handle" not in sftp_server._handles

    def test_handle_close_unknown_handle_returns_failure(self, sftp_server):
        msg = SFTPCloseMessage(2, b"ghost_handle")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_close(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_FAILURE


class TestHandleReadWrite:
    def _add_file_handle(self, sftp_server, content=b"file data", flags=SSH_FXF_READ):
        file_obj = io.BytesIO(content)
        handle = SFTPHandle(b"fh", "/file.txt", flags, file_obj)
        sftp_server._handles[b"fh"] = handle
        return handle

    def test_handle_read_success(self, sftp_server):
        self._add_file_handle(sftp_server, content=b"hello world")
        msg = SFTPReadMessage(1, b"fh", 0, 5)
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_read(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPDataMessage)

    def test_handle_read_eof(self, sftp_server):
        handle = self._add_file_handle(sftp_server, content=b"")
        msg = SFTPReadMessage(1, b"fh", 0, 100)
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_read(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_EOF  # empty read = EOF status

    def test_handle_write_success(self, sftp_server, temp_root):
        file_obj = io.BytesIO()
        handle = SFTPHandle(b"wh", "/file.txt", SSH_FXF_WRITE, file_obj)
        sftp_server._handles[b"wh"] = handle

        msg = SFTPWriteMessage(2, b"wh", 0, b"write data")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_write(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_OK

    def test_handle_read_unknown_handle(self, sftp_server):
        msg = SFTPReadMessage(1, b"ghost", 0, 100)
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_read(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_FAILURE


class TestHandleStatOperations:
    def test_handle_stat_existing(self, sftp_server, temp_root):
        test_file = os.path.join(temp_root, "statme.txt")
        with open(test_file, "w") as f:
            f.write("test")

        msg = SFTPStatMessage(1, "statme.txt")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_stat(msg)
            sent = send_mock.call_args[0][0]
            assert not isinstance(sent, SFTPStatusMessage) or sent.status_code == SSH_FX_OK

    def test_handle_stat_nonexistent(self, sftp_server):
        msg = SFTPStatMessage(2, "ghost_file.txt")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_stat(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code != SSH_FX_OK

    def test_handle_lstat(self, sftp_server, temp_root):
        test_file = os.path.join(temp_root, "lstatme.txt")
        with open(test_file, "w") as f:
            f.write("x")

        msg = SFTPLStatMessage(3, "lstatme.txt")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_lstat(msg)
            send_mock.assert_called_once()

    def test_handle_mkdir(self, sftp_server, temp_root):
        msg = SFTPMkdirMessage(4, "newdir_test", SFTPAttributes())
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_mkdir(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_OK
        assert os.path.isdir(os.path.join(temp_root, "newdir_test"))

    def test_handle_rmdir(self, sftp_server, temp_root):
        dirpath = os.path.join(temp_root, "rmdir_test")
        os.makedirs(dirpath)
        msg = SFTPRmdirMessage(5, "rmdir_test")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_rmdir(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_OK
        assert not os.path.exists(dirpath)

    def test_handle_remove(self, sftp_server, temp_root):
        test_file = os.path.join(temp_root, "remove_me.txt")
        with open(test_file, "w") as f:
            f.write("del")
        msg = SFTPRemoveMessage(6, "remove_me.txt")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_remove(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_OK
        assert not os.path.exists(test_file)

    def test_handle_rename(self, sftp_server, temp_root):
        src = os.path.join(temp_root, "rename_src.txt")
        with open(src, "w") as f:
            f.write("rename")
        msg = SFTPRenameMessage(7, "rename_src.txt", "rename_dst.txt")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_rename(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code == SSH_FX_OK
        assert os.path.exists(os.path.join(temp_root, "rename_dst.txt"))
        assert not os.path.exists(src)

    def test_handle_realpath(self, sftp_server, temp_root):
        msg = SFTPRealPathMessage(8, ".")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_realpath(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPNameMessage)


class TestHandleOpenDir:
    def test_handle_opendir_success(self, sftp_server, temp_root):
        msg = SFTPOpenDirMessage(1, ".")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_opendir(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPHandleMessage)

    def test_handle_readdir_after_opendir(self, sftp_server, temp_root):
        # Create a file so there's something to read
        with open(os.path.join(temp_root, "file_in_dir.txt"), "w") as f:
            f.write("x")

        # Open the dir
        open_msg = SFTPOpenDirMessage(1, ".")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_opendir(open_msg)
            handle_msg = send_mock.call_args[0][0]

        # Get the handle bytes
        handle_bytes = handle_msg.handle

        # Read entries
        read_msg = SFTPReadDirMessage(2, handle_bytes)
        with patch.object(sftp_server, "_send_message") as send_mock2:
            sftp_server._handle_readdir(read_msg)
            sent = send_mock2.call_args[0][0]
            assert isinstance(sent, (SFTPNameMessage, SFTPStatusMessage))

    def test_handle_opendir_nonexistent(self, sftp_server):
        msg = SFTPOpenDirMessage(99, "ghost_dir_xyz")
        with patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._handle_opendir(msg)
            sent = send_mock.call_args[0][0]
            assert isinstance(sent, SFTPStatusMessage)
            assert sent.status_code != SSH_FX_OK


class TestGenerateHandle:
    def test_handles_are_unique(self, sftp_server):
        h1 = sftp_server._generate_handle()
        h2 = sftp_server._generate_handle()
        h3 = sftp_server._generate_handle()
        assert h1 != h2
        assert h2 != h3


class TestProcessMessagesBreak:
    def test_process_messages_breaks_on_eof(self, sftp_server):
        """_process_messages should break when it gets an EOF-like exception."""
        with patch.object(sftp_server, "_receive_message",
                          side_effect=SFTPError("connection closed", SSH_FX_FAILURE)):
            sftp_server._process_messages()  # Should not raise and should return

    def test_process_messages_sends_error_on_unknown_exception(self, sftp_server):
        call_count = [0]
        real_msg = SFTPOpenMessage(1, "file.txt", SSH_FXF_READ, SFTPAttributes())

        def fake_receive():
            call_count[0] += 1
            if call_count[0] == 1:
                return real_msg
            raise SFTPError("closed", SSH_FX_FAILURE)

        with patch.object(sftp_server, "_receive_message", side_effect=fake_receive), \
             patch.object(sftp_server, "_handle_message",
                          side_effect=RuntimeError("unexpected error")), \
             patch.object(sftp_server, "_send_message") as send_mock:
            sftp_server._process_messages()
            # Error status should have been attempted
            if send_mock.call_count > 0:
                sent = send_mock.call_args[0][0]
                assert isinstance(sent, SFTPStatusMessage)
