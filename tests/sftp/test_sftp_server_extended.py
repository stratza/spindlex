import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from spindlex.protocol.sftp_constants import *
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPOpenMessage,
    SFTPReadMessage,
    SFTPRealPathMessage,
    SFTPRemoveMessage,
    SFTPRenameMessage,
)
from spindlex.server.sftp_server import SFTPServer


@pytest.fixture
def temp_root():
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def mock_channel():
    channel = MagicMock()
    return channel


@pytest.fixture
def sftp_server(mock_channel, temp_root):
    # Mock _start_sftp_session to avoid infinite loop in __init__
    with patch.object(SFTPServer, "_start_sftp_session"):
        server = SFTPServer(mock_channel, temp_root)
        server.check_file_access = MagicMock(return_value=True)
        yield server
        server.close()


def test_sftp_server_resolve_path(sftp_server, temp_root):
    # Within root
    assert sftp_server._resolve_path("file.txt") == os.path.join(temp_root, "file.txt")
    assert sftp_server._resolve_path("/subdir/file.txt") == os.path.join(
        temp_root, "subdir", "file.txt"
    )

    # Outside root
    from spindlex.exceptions import SFTPError

    with pytest.raises(SFTPError, match="outside root"):
        sftp_server._resolve_path("../outside.txt")


def test_sftp_server_handle_open_success(sftp_server, temp_root):
    test_file = os.path.join(temp_root, "test.txt")
    with open(test_file, "w") as f:
        f.write("hello")

    msg = SFTPOpenMessage(1, "test.txt", SSH_FXF_READ, SFTPAttributes())

    with patch.object(sftp_server, "_send_message") as mock_send:
        sftp_server._handle_open(msg)

        # Should have sent handle
        sent_msg = mock_send.call_args[0][0]
        assert sent_msg.msg_type == SSH_FXP_HANDLE


def test_sftp_server_handle_open_fail_not_found(sftp_server):
    msg = SFTPOpenMessage(1, "nonexistent.txt", SSH_FXF_READ, SFTPAttributes())

    with patch.object(sftp_server, "_send_message") as mock_send:
        sftp_server._handle_open(msg)

        status_msg = mock_send.call_args[0][0]
        assert status_msg.msg_type == SSH_FXP_STATUS
        assert status_msg.status_code == SSH_FX_NO_SUCH_FILE


def test_sftp_server_handle_read_eof(sftp_server, temp_root):
    test_file = os.path.join(temp_root, "test.txt")
    with open(test_file, "w") as f:
        f.write("a")

    # Open first to get handle
    open_msg = SFTPOpenMessage(1, "test.txt", SSH_FXF_READ, SFTPAttributes())
    sftp_server._handle_open(open_msg)
    handle_id = list(sftp_server._handles.keys())[0]

    # Read past EOF
    read_msg = SFTPReadMessage(2, handle_id, 1, 10)

    with patch.object(sftp_server, "_send_message") as mock_send:
        sftp_server._handle_read(read_msg)
        status_msg = mock_send.call_args[0][0]
        assert status_msg.status_code == SSH_FX_EOF


def test_sftp_server_handle_remove(sftp_server, temp_root):
    test_file = os.path.join(temp_root, "test.txt")
    open(test_file, "w").close()

    msg = SFTPRemoveMessage(1, "test.txt")
    with patch.object(sftp_server, "_send_message"):
        sftp_server._handle_remove(msg)
        assert not os.path.exists(test_file)


def test_sftp_server_handle_rename(sftp_server, temp_root):
    old_file = os.path.join(temp_root, "old.txt")
    new_file = os.path.join(temp_root, "new.txt")
    open(old_file, "w").close()

    msg = SFTPRenameMessage(1, "old.txt", "new.txt")
    with patch.object(sftp_server, "_send_message"):
        sftp_server._handle_rename(msg)
        assert not os.path.exists(old_file)
        assert os.path.exists(new_file)


def test_sftp_server_handle_realpath(sftp_server):
    msg = SFTPRealPathMessage(1, ".")
    with patch.object(sftp_server, "_send_message") as mock_send:
        sftp_server._handle_realpath(msg)
        name_msg = mock_send.call_args[0][0]
        assert name_msg.msg_type == SSH_FXP_NAME
        # The first entry in names list should have the path
        assert name_msg.names[0][0] == "/"


def test_sftp_server_process_messages_break(sftp_server):
    # Mock _receive_message to raise error to break loop
    with patch.object(sftp_server, "_receive_message") as mock_recv:
        mock_recv.side_effect = OSError("error")
        sftp_server._process_messages()  # Should return
        assert mock_recv.called
