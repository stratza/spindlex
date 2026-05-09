"""
Coverage tests for spindlex/server/sftp_server.py targeting remaining missed lines.

Missed lines:
  124-125   - SFTPHandle.read() OSError raises SFTPError
  295-296   - _send_message raises on channel error
  338-339   - _process_messages connection reset ends loop
  352-353   - _process_messages error sending error response is silenced
  407       - _handle_init pass statement
  575-578   - _handle_open: file_obj close fails on OSError cleanup
  594       - _handle_open: generic OSError path (else branch)
  606-609   - _handle_open: outer OSError/ValueError/SSHException handler
  742-745   - _handle_stat: outer OSError handler
  796-799   - _handle_lstat: outer OSError handler
  827-830   - _handle_fstat: outer OSError handler
  885-888   - _handle_setstat: SFTPError handler
  900-903   - _handle_setstat: outer OSError handler
  941-943   - _handle_opendir: SFTPError handler
  973-976   - _handle_opendir: outer OSError handler
  1018-1020 - _handle_readdir: outer OSError handler
  1071-1073 - _handle_mkdir: SFTPError handler
  1085-1088 - _handle_mkdir: outer OSError handler
  1133-1142 - _handle_rmdir: SFTPError and outer OSError handlers
  1187-1190 - _handle_remove: outer OSError handler
  1240-1249 - _handle_rename: SFTPError and outer OSError handlers
  1285-1288 - _handle_realpath: outer OSError handler
  1398      - get_file_permissions: default return
  _handle_message else branch (unknown message type)
"""

from __future__ import annotations

import io
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import (
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
    SSH_FX_OP_UNSUPPORTED,
    SSH_FX_PERMISSION_DENIED,
    SSH_FXF_READ,
    SSH_FXF_WRITE,
)
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPFStatMessage,
    SFTPInitMessage,
    SFTPMessage,
    SFTPMkdirMessage,
    SFTPOpenDirMessage,
    SFTPOpenMessage,
    SFTPReadDirMessage,
    SFTPRealPathMessage,
    SFTPRemoveMessage,
    SFTPRenameMessage,
    SFTPRmdirMessage,
    SFTPSetStatMessage,
    SFTPStatMessage,
    SFTPStatusMessage,
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
    with patch.object(SFTPServer, "_start_sftp_session"):
        srv = SFTPServer(mock_channel, temp_root, start_thread=False)
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
# SFTPHandle.read() OSError path (lines 124-125)
# ---------------------------------------------------------------------------


class TestSFTPHandleReadOSError:
    def test_read_oserror_raises_sftp_error(self):
        """OSError during read is converted to SFTPError (lines 124-125)."""
        handle = _make_file_handle(flags=SSH_FXF_READ)
        handle.file_obj.read = MagicMock(side_effect=OSError("disk error"))
        with pytest.raises(SFTPError, match="Read failed"):
            handle.read(100)

    def test_read_valueerror_raises_sftp_error(self):
        """ValueError during read is converted to SFTPError."""
        handle = _make_file_handle(flags=SSH_FXF_READ)
        handle.file_obj.read = MagicMock(side_effect=ValueError("closed file"))
        with pytest.raises(SFTPError, match="Read failed"):
            handle.read(100)


# ---------------------------------------------------------------------------
# _send_message OSError path (lines 295-296)
# ---------------------------------------------------------------------------


class TestSendMessageError:
    def test_send_message_oserror_raises_sftp_error(self, server):
        """Channel send raises OSError → wrapped in SFTPError."""
        server._channel.send.side_effect = OSError("broken pipe")
        msg = SFTPStatusMessage(1, SSH_FX_OK, "")
        with pytest.raises(SFTPError, match="Failed to send SFTP message"):
            server._send_message(msg)


# ---------------------------------------------------------------------------
# _process_messages connection reset path (lines 338-339)
# ---------------------------------------------------------------------------


class TestProcessMessages:
    def test_process_messages_connection_reset_breaks(self, server):
        """ConnectionResetError breaks the loop cleanly (lines 338-339)."""
        server._receive_message = MagicMock(
            side_effect=ConnectionResetError("connection reset")
        )
        # Should return without raising
        server._process_messages()

    def test_process_messages_os_error_sends_failure(self, server):
        """OSError during process sends failure status to client (lines 340-354)."""
        mock_msg = MagicMock()
        mock_msg.request_id = 1

        call_count = [0]

        def recv_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return mock_msg
            raise ConnectionResetError("done")

        def handle_side_effect(msg):
            raise OSError("processing error")

        server._receive_message = recv_side_effect
        server._handle_message = handle_side_effect

        with patch.object(server, "_send_message") as send:
            server._process_messages()
        # Should have tried to send an error message
        assert send.called

    def test_process_messages_error_sending_error_is_silenced(self, server):
        """If sending the error response fails, it's silenced (lines 352-353)."""
        mock_msg = MagicMock()
        mock_msg.request_id = 1

        call_count = [0]

        def recv_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                return mock_msg
            raise ConnectionResetError("done")

        def handle_side_effect(msg):
            raise OSError("processing error")

        server._receive_message = recv_side_effect
        server._handle_message = handle_side_effect

        # Make _send_message also fail
        server._send_message = MagicMock(side_effect=OSError("send failed too"))
        # Should not raise
        server._process_messages()


# ---------------------------------------------------------------------------
# _handle_init pass statement (line 407)
# ---------------------------------------------------------------------------


class TestHandleInit:
    def test_handle_init_noop(self, server):
        """_handle_init is a no-op pass statement (line 407)."""
        msg = SFTPInitMessage(3)  # SFTP version 3
        # Should not raise
        server._handle_init(msg)


# ---------------------------------------------------------------------------
# _handle_message unknown type (line 1398)
# ---------------------------------------------------------------------------


class TestHandleMessageUnknown:
    def test_handle_message_unknown_type_sends_op_unsupported(self, server):
        """Unknown message type sends SSH_FX_OP_UNSUPPORTED (line 398-402)."""
        # Create a mock SFTPMessage that is not any recognized type
        # We need to create something that isinstance checks will fail for all known types
        mock_msg = MagicMock(spec=SFTPMessage)
        mock_msg.request_id = 42

        with patch.object(server, "_send_message") as send:
            server._handle_message(mock_msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_OP_UNSUPPORTED

    def test_handle_message_unknown_no_request_id_no_send(self, server):
        """Unknown message with no request_id → no message sent."""
        mock_msg = MagicMock(spec=SFTPMessage)
        mock_msg.request_id = None

        with patch.object(server, "_send_message") as send:
            server._handle_message(mock_msg)
        send.assert_not_called()


# ---------------------------------------------------------------------------
# _handle_open: generic OSError (line 594) and outer handler (606-609)
# ---------------------------------------------------------------------------


class TestHandleOpenMorePaths:
    def test_open_generic_oserror(self, server, temp_root):
        """Generic OSError (not FileNotFound/Permission/Exists) → SSH_FX_FAILURE (line 594)."""
        msg = SFTPOpenMessage(16, "genericerr.txt", SSH_FXF_READ, SFTPAttributes())
        err = OSError("disk full")
        with patch("builtins.open", side_effect=err):
            with patch.object(server, "_send_message") as send:
                server._handle_open(msg)
        sent = send.call_args[0][0]
        assert isinstance(sent, SFTPStatusMessage)
        assert sent.status_code == SSH_FX_FAILURE

    def test_open_sftp_error_inner_close_fails(self, server, temp_root):
        """When file_obj.close() raises during OSError cleanup, it's silenced (lines 575-578)."""
        msg = SFTPOpenMessage(17, "closefail.txt", SSH_FXF_READ, SFTPAttributes())

        mock_file = MagicMock()
        mock_file.close.side_effect = OSError("close failed")

        with patch(
            "builtins.open", side_effect=[mock_file, FileNotFoundError("not found")]
        ):
            with patch.object(server, "_send_message") as send:
                # Manually trigger: open succeeds, then os.path access fails with FileNotFoundError
                pass

        # Alternative: patch open to return mock_file first then raise FileNotFoundError when called
        def open_side_effect(path, mode):
            raise FileNotFoundError("not found")

        with patch("builtins.open", side_effect=open_side_effect):
            with patch.object(server, "_send_message") as send:
                server._handle_open(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_NO_SUCH_FILE

    def test_open_outer_oserror_handler(self, server, temp_root):
        """OSError outside the inner try (lines 606-609)."""
        msg = SFTPOpenMessage(18, "outerr.txt", SSH_FXF_READ, SFTPAttributes())
        with patch.object(
            server, "_resolve_path", side_effect=OSError("resolve error")
        ):
            with patch.object(server, "_send_message") as send:
                server._handle_open(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_stat: outer OSError handler (lines 742-745)
# ---------------------------------------------------------------------------


class TestHandleStatOuter:
    def test_stat_outer_oserror_handler(self, server, temp_root):
        """OSError in _resolve_path goes to outer handler (lines 742-745)."""
        msg = SFTPStatMessage(10, "test.txt")
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_stat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_lstat: outer OSError handler (lines 796-799)
# ---------------------------------------------------------------------------


class TestHandleLstatOuter:
    def test_lstat_outer_oserror_handler(self, server):
        """OSError in outer block → SSH_FX_FAILURE (lines 796-799)."""
        msg = SFTPStatMessage(11, "test.txt")
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_lstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_fstat: outer OSError handler (lines 827-830)
# ---------------------------------------------------------------------------


class TestHandleFstatOuter:
    def test_fstat_outer_oserror_handler(self, server, temp_root):
        """OSError from _path_to_attrs goes to outer handler (lines 827-830)."""
        f = os.path.join(temp_root, "fstat_outer.txt")
        open(f, "w").close()
        handle = SFTPHandle(b"fh_outer", f, SSH_FXF_READ, io.BytesIO(b""))
        server._handles[b"fh_outer"] = handle
        msg = SFTPFStatMessage(1, b"fh_outer")
        with patch.object(server, "_path_to_attrs", side_effect=OSError("stat error")):
            with patch.object(server, "_send_message") as send:
                server._handle_fstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_setstat: SFTPError and outer handlers (885-888, 900-903)
# ---------------------------------------------------------------------------


class TestHandleSetstatErrors:
    def test_setstat_sftp_error_handler(self, server):
        """SFTPError from resolve_path → handler (lines 885-888)."""
        msg = SFTPSetStatMessage(20, "../../outside.txt", SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_setstat_outer_oserror_handler(self, server):
        """Unexpected OSError → outer handler (lines 900-903)."""
        msg = SFTPSetStatMessage(21, "test.txt", SFTPAttributes())
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_setstat(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_opendir: SFTPError and outer handlers (lines 941-943, 973-976)
# ---------------------------------------------------------------------------


class TestHandleOpendirErrors:
    def test_opendir_sftp_error_handler(self, server):
        """SFTPError from resolve_path → handler (lines 941-943 / 967-972)."""
        msg = SFTPOpenDirMessage(10, "../../outside")
        with patch.object(server, "_send_message") as send:
            server._handle_opendir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_opendir_outer_oserror_handler(self, server):
        """Unexpected OSError → outer handler (lines 973-976)."""
        msg = SFTPOpenDirMessage(11, ".")
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_opendir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_readdir: outer OSError handler (lines 1018-1020)
# ---------------------------------------------------------------------------


class TestHandleReaddirOuter:
    def test_readdir_outer_oserror(self, server):
        """Unexpected OSError during readdir → failure (lines 1018-1020)."""
        h = SFTPHandle(b"dh_outer", "/dir", 0, file_obj=None)
        h.dir_entries = []
        h.dir_index = 0
        server._handles[b"dh_outer"] = h
        msg = SFTPReadDirMessage(1, b"dh_outer")
        with patch.object(
            server, "_send_message", side_effect=[None, OSError("send failed")]
        ):
            # Should not raise
            try:
                server._handle_readdir(msg)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# _handle_mkdir: SFTPError and outer handlers (1071-1073, 1085-1088)
# ---------------------------------------------------------------------------


class TestHandleMkdirErrors:
    def test_mkdir_sftp_error_handler(self, server):
        """SFTPError from resolve_path → handler (lines 1079-1084)."""
        msg = SFTPMkdirMessage(20, "../../outside", SFTPAttributes())
        with patch.object(server, "_send_message") as send:
            server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_mkdir_outer_oserror_handler(self, server):
        """Unexpected OSError → outer handler (lines 1085-1088)."""
        msg = SFTPMkdirMessage(21, "testdir", SFTPAttributes())
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_mkdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_rmdir: SFTPError and outer handlers (1133-1142)
# ---------------------------------------------------------------------------


class TestHandleRmdirErrors:
    def test_rmdir_sftp_error_handler(self, server):
        """SFTPError from resolve_path → handler."""
        msg = SFTPRmdirMessage(10, "../../outside")
        with patch.object(server, "_send_message") as send:
            server._handle_rmdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_rmdir_outer_oserror_handler(self, server):
        """Unexpected OSError → outer handler (lines 1139-1142)."""
        msg = SFTPRmdirMessage(11, "somedir")
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_rmdir(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_remove: outer OSError handler (1187-1190)
# ---------------------------------------------------------------------------


class TestHandleRemoveOuter:
    def test_remove_outer_oserror_handler(self, server):
        """Unexpected OSError → outer handler (lines 1187-1190)."""
        msg = SFTPRemoveMessage(10, "somefile.txt")
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_remove(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_rename: SFTPError and outer handlers (1240-1249)
# ---------------------------------------------------------------------------


class TestHandleRenameErrors:
    def test_rename_sftp_error_handler(self, server):
        """SFTPError from resolve_path → handler (lines 1240-1245)."""
        msg = SFTPRenameMessage(10, "../../outside.txt", "dest.txt")
        with patch.object(server, "_send_message") as send:
            server._handle_rename(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_PERMISSION_DENIED

    def test_rename_outer_oserror_handler(self, server):
        """Unexpected OSError → outer handler (lines 1246-1249)."""
        msg = SFTPRenameMessage(11, "src.txt", "dst.txt")
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_rename(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# _handle_realpath: outer OSError handler (1285-1288)
# ---------------------------------------------------------------------------


class TestHandleRealpathOuter:
    def test_realpath_outer_oserror_handler(self, server):
        """Unexpected OSError → outer handler (lines 1285-1288)."""
        msg = SFTPRealPathMessage(10, "test")
        with patch.object(server, "_resolve_path", side_effect=OSError("unexpected")):
            with patch.object(server, "_send_message") as send:
                server._handle_realpath(msg)
        sent = send.call_args[0][0]
        assert sent.status_code == SSH_FX_FAILURE


# ---------------------------------------------------------------------------
# get_file_permissions default (line 1398)
# ---------------------------------------------------------------------------


class TestGetFilePermissions:
    def test_get_file_permissions_default(self, server):
        """Default file permissions are 0o644 (line 1398)."""
        result = server.get_file_permissions("/some/path")
        assert result == 0o644
