import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import *
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPCloseMessage,
    SFTPDataMessage,
    SFTPHandleMessage,
    SFTPInitMessage,
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


@pytest.fixture
def temp_root():
    path = tempfile.mkdtemp()
    yield path
    shutil.rmtree(path)


@pytest.fixture
def mock_channel():
    channel = MagicMock()
    return channel


def test_sftp_handle_file(temp_root):
    file_path = os.path.join(temp_root, "test.txt")
    with open(file_path, "wb") as f:
        f.write(b"hello world")

    with open(file_path, "rb+") as f:
        handle = SFTPHandle(b"h1", file_path, SSH_FXF_READ | SSH_FXF_WRITE, f)

        assert handle.read(5) == b"hello"
        handle.seek(6)
        assert handle.read(5) == b"world"

        handle.seek(0)
        handle.write(b"HELLO")
        handle.seek(0)
        assert handle.read(5) == b"HELLO"

        handle.close()
        assert f.closed


def test_sftp_server_init_failure(mock_channel, temp_root):
    # Mock _receive_message to fail during INIT
    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        mock_recv.side_effect = OSError("Failed to receive INIT")

        with pytest.raises(SFTPError, match="SFTP initialization failed"):
            server = SFTPServer(mock_channel, temp_root, start_thread=False)
            server._start_sftp_session()


def test_sftp_server_init_success(mock_channel, temp_root):
    # Mock _receive_message to return INIT then stop
    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as mock_send:
            mock_recv.side_effect = [SFTPInitMessage(3), OSError("Stop")]

            # SFTPServer won't raise SFTPError if it stops in _process_messages
            server = SFTPServer(mock_channel, temp_root, start_thread=False)
            server._start_sftp_session()

            assert mock_send.called
            sent_msg = mock_send.call_args_list[0][0][0]
            assert isinstance(sent_msg, SFTPVersionMessage)


def test_sftp_server_open_read_close(mock_channel, temp_root):
    file_path = os.path.join(temp_root, "test.txt")
    with open(file_path, "wb") as f:
        f.write(b"sftp test data")

    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as mock_send:
            # Sequence: INIT, OPEN, READ, CLOSE, STOP
            attrs = SFTPAttributes()
            mock_recv.side_effect = [
                SFTPInitMessage(3),
                SFTPOpenMessage(1, "test.txt", SSH_FXF_READ, attrs),
                SFTPReadMessage(2, b"handle_1", 0, 100),
                SFTPCloseMessage(3, b"handle_1"),
                Exception("Stop"),
            ]

            try:
                server = SFTPServer(mock_channel, temp_root, start_thread=False)
                server._start_sftp_session()
            except Exception:
                pass

            # Check sent messages
            sent_messages = [call[0][0] for call in mock_send.call_args_list]
            assert isinstance(sent_messages[0], SFTPVersionMessage)
            assert isinstance(sent_messages[1], SFTPHandleMessage)
            assert sent_messages[1].handle == b"handle_1"
            assert isinstance(sent_messages[2], SFTPDataMessage)
            assert sent_messages[2].data == b"sftp test data"
            assert isinstance(sent_messages[3], SFTPStatusMessage)
            assert sent_messages[3].status_code == SSH_FX_OK


def test_sftp_server_realpath(mock_channel, temp_root):
    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as mock_send:
            mock_recv.side_effect = [
                SFTPInitMessage(3),
                SFTPRealPathMessage(1, "."),
                Exception("Stop"),
            ]

            try:
                server = SFTPServer(mock_channel, temp_root, start_thread=False)
                server._start_sftp_session()
            except Exception:
                pass

            sent_messages = [call[0][0] for call in mock_send.call_args_list]
            assert isinstance(sent_messages[1], SFTPNameMessage)
            assert sent_messages[1].names[0][0] == "/"


def test_sftp_server_resolve_path_security(mock_channel, temp_root):
    # Test path traversal prevention
    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        mock_recv.side_effect = [SFTPInitMessage(3), Exception("Stop")]
        try:
            server = SFTPServer(mock_channel, temp_root, start_thread=False)
            server._start_sftp_session()
        except Exception:
            # We need to get the server instance, but __init__ might enter loop or fail
            pass

    # Let's bypass __init__ loop for easier testing of helper methods
    with patch.object(SFTPServer, "_start_sftp_session"):
        server = SFTPServer(mock_channel, temp_root, start_thread=False)

        assert server._resolve_path("test.txt") == os.path.abspath(
            os.path.join(temp_root, "test.txt")
        )
        assert server._resolve_path("/test.txt") == os.path.abspath(
            os.path.join(temp_root, "test.txt")
        )

        with pytest.raises(SFTPError, match="outside root"):
            server._resolve_path("../outside.txt")

        with pytest.raises(SFTPError, match="outside root"):
            server._resolve_path("/../outside.txt")


def test_sftp_server_resolve_path_hardening(mock_channel, temp_root):
    """Targeted checks for the path-traversal hardening in _resolve_path.

    Covers NUL bytes, Windows-style backslash separators, deeply nested
    traversal, and prefix-boundary sibling directories (e.g.
    ``/tmp/rootBAD`` when root is ``/tmp/root``). Symlink escape is
    covered separately because symlink creation on Windows is usually
    gated on developer-mode / admin rights.
    """
    with patch.object(SFTPServer, "_start_sftp_session"):
        server = SFTPServer(mock_channel, temp_root, start_thread=False)

        # NUL bytes are rejected outright.
        with pytest.raises(SFTPError, match="Invalid path"):
            server._resolve_path("ok\x00name")

        # Backslash separators on any platform should be normalized before
        # the traversal check — ``..\\..\\etc\\passwd`` must not bypass it.
        with pytest.raises(SFTPError, match="outside root"):
            server._resolve_path("..\\..\\etc\\passwd")

        # Deeply-nested ``..`` sequences still resolve above the root.
        with pytest.raises(SFTPError, match="outside root"):
            server._resolve_path("/a/b/c/../../../../../outside.txt")

        # Prefix-boundary bypass: a sibling directory whose name begins with
        # the root's name (e.g. root=/tmp/xyz vs /tmp/xyzbad) must not be
        # accepted. We create such a sibling and ensure the check rejects it.
        sibling = temp_root + "_sibling"
        os.makedirs(sibling, exist_ok=True)
        try:
            # Compute an SFTP-style path that navigates out of root and
            # into the sibling by name.
            rel = "/../" + os.path.basename(sibling) + "/file.txt"
            with pytest.raises(SFTPError, match="outside root"):
                server._resolve_path(rel)
        finally:
            shutil.rmtree(sibling, ignore_errors=True)


def test_sftp_server_resolve_path_symlink_escape(mock_channel, temp_root):
    """A symlink inside the root that targets outside it must be rejected
    once ``realpath`` resolves the link. Skipped when the platform does
    not permit unprivileged symlink creation (Windows without developer
    mode/admin)."""
    with patch.object(SFTPServer, "_start_sftp_session"):
        server = SFTPServer(mock_channel, temp_root, start_thread=False)

        outside = tempfile.mkdtemp()
        try:
            link_path = os.path.join(temp_root, "escape")
            try:
                os.symlink(outside, link_path)
            except (OSError, NotImplementedError):
                pytest.skip("symlink creation not supported on this platform")
            with pytest.raises(SFTPError, match="outside root"):
                server._resolve_path("escape/anything.txt")
        finally:
            shutil.rmtree(outside, ignore_errors=True)


def test_sftp_server_stat(mock_channel, temp_root):
    file_path = os.path.join(temp_root, "test.txt")
    with open(file_path, "wb") as f:
        f.write(b"data")

    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as mock_send:
            mock_recv.side_effect = [
                SFTPInitMessage(3),
                SFTPStatMessage(1, "test.txt"),
                Exception("Stop"),
            ]

            try:
                server = SFTPServer(mock_channel, temp_root, start_thread=False)
                server._start_sftp_session()
            except Exception:
                pass

            sent_messages = [call[0][0] for call in mock_send.call_args_list]
            assert isinstance(sent_messages[1], SFTPAttrsMessage)
            assert sent_messages[1].attrs.size == 4


def test_sftp_server_mkdir_rmdir(mock_channel, temp_root):
    dir_name = "new_dir"
    dir_path = os.path.join(temp_root, dir_name)

    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as mock_send:
            attrs = SFTPAttributes()
            mock_recv.side_effect = [
                SFTPInitMessage(3),
                SFTPMkdirMessage(1, dir_name, attrs),
                SFTPRmdirMessage(2, dir_name),
                Exception("Stop"),
            ]

            try:
                server = SFTPServer(mock_channel, temp_root, start_thread=False)
                server._start_sftp_session()
            except Exception:
                pass

            assert (
                os.path.exists(dir_path) is False
            )  # because it was created then removed
            sent_messages = [call[0][0] for call in mock_send.call_args_list]
            assert sent_messages[1].status_code == SSH_FX_OK
            assert sent_messages[2].status_code == SSH_FX_OK


def test_sftp_server_write(mock_channel, temp_root):
    file_path = os.path.join(temp_root, "write_test.txt")

    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as _:
            attrs = SFTPAttributes()
            mock_recv.side_effect = [
                SFTPInitMessage(3),
                SFTPOpenMessage(
                    1, "write_test.txt", SSH_FXF_WRITE | SSH_FXF_CREAT, attrs
                ),
                SFTPWriteMessage(2, b"handle_1", 0, b"new data"),
                SFTPCloseMessage(3, b"handle_1"),
                Exception("Stop"),
            ]

            try:
                server = SFTPServer(mock_channel, temp_root, start_thread=False)
                server._start_sftp_session()
            except Exception:
                pass

            with open(file_path, "rb") as f:
                assert f.read() == b"new data"


def test_sftp_server_opendir_readdir(mock_channel, temp_root):
    os.mkdir(os.path.join(temp_root, "subdir"))
    with open(os.path.join(temp_root, "subdir", "file1.txt"), "w") as f:
        f.write("test")

    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as mock_send:
            mock_recv.side_effect = [
                SFTPInitMessage(3),
                SFTPOpenDirMessage(1, "subdir"),
                SFTPReadDirMessage(2, b"handle_1"),
                SFTPReadDirMessage(3, b"handle_1"),  # Should return EOF
                SFTPCloseMessage(4, b"handle_1"),
                Exception("Stop"),
            ]

            try:
                server = SFTPServer(mock_channel, temp_root, start_thread=False)
                server._start_sftp_session()
            except Exception:
                pass

            sent_messages = [call[0][0] for call in mock_send.call_args_list]
            assert isinstance(sent_messages[2], SFTPNameMessage)
            assert len(sent_messages[2].names) == 1
            assert sent_messages[2].names[0][0] == "file1.txt"
            assert isinstance(sent_messages[3], SFTPStatusMessage)
            assert sent_messages[3].status_code == SSH_FX_EOF


def test_sftp_server_remove_rename(mock_channel, temp_root):
    file1 = os.path.join(temp_root, "file1.txt")
    file2 = os.path.join(temp_root, "file2.txt")
    with open(file1, "w") as f:
        f.write("1")

    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as _:
            mock_recv.side_effect = [
                SFTPInitMessage(3),
                SFTPRenameMessage(1, "file1.txt", "file2.txt"),
                SFTPRemoveMessage(2, "file2.txt"),
                Exception("Stop"),
            ]

            try:
                server = SFTPServer(mock_channel, temp_root, start_thread=False)
                server._start_sftp_session()
            except Exception:
                pass

            assert not os.path.exists(file1)
            assert not os.path.exists(file2)


def test_sftp_server_setstat(mock_channel, temp_root):
    file_path = os.path.join(temp_root, "test.txt")
    with open(file_path, "w") as f:
        f.write("test")

    try:
        with patch.object(SFTPServer, "_receive_message") as mock_recv:
            with patch.object(SFTPServer, "_send_message") as _:
                attrs = SFTPAttributes()
                attrs.permissions = 0o444
                attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS
                mock_recv.side_effect = [
                    SFTPInitMessage(3),
                    SFTPSetStatMessage(1, "test.txt", attrs),
                    Exception("Stop"),
                ]

                try:
                    server = SFTPServer(mock_channel, temp_root, start_thread=False)
                    server._start_sftp_session()
                except Exception:
                    pass

                st = os.stat(file_path)
                assert (st.st_mode & 0o777) == 0o444
    finally:
        os.chmod(file_path, 0o666)


def test_sftp_server_errors(mock_channel, temp_root):
    with patch.object(SFTPServer, "_receive_message") as mock_recv:
        with patch.object(SFTPServer, "_send_message") as mock_send:
            mock_recv.side_effect = [
                SFTPInitMessage(3),
                SFTPStatMessage(1, "nonexistent.txt"),
                SFTPOpenMessage(2, "nonexistent.txt", SSH_FXF_READ, SFTPAttributes()),
                SFTPReadMessage(3, b"invalid_handle", 0, 10),
                Exception("Stop"),
            ]

            try:
                server = SFTPServer(mock_channel, temp_root, start_thread=False)
                server._start_sftp_session()
            except Exception:
                pass

            sent_messages = [call[0][0] for call in mock_send.call_args_list]
            # [Version, Status(Stat Error), Status(Open Error), Status(Read Error)]
            assert sent_messages[1].status_code == SSH_FX_NO_SUCH_FILE
            assert sent_messages[2].status_code == SSH_FX_NO_SUCH_FILE
            assert sent_messages[3].status_code == SSH_FX_FAILURE  # Invalid handle
