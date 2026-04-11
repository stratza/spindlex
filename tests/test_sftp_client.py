from unittest.mock import MagicMock, patch

import pytest
from spindlex.client.sftp_client import SFTPClient, SFTPFile
from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import *
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPDataMessage,
    SFTPHandleMessage,
    SFTPInitMessage,
    SFTPNameMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
)


@pytest.fixture
def mock_transport():
    transport = MagicMock()
    channel = MagicMock()
    transport.open_channel.return_value = channel
    return transport


@pytest.fixture
def mock_channel(mock_transport):
    return mock_transport.open_channel.return_value


@pytest.fixture
def sftp_client(mock_transport, mock_channel):
    # Mock the initialization sequence
    with patch.object(SFTPClient, "_send_message"):
        with patch.object(SFTPClient, "_receive_message") as mock_recv:
            mock_recv.return_value = SFTPVersionMessage(SFTP_VERSION, {})
            client = SFTPClient(mock_transport)
            return client


def test_sftp_client_init(mock_transport, mock_channel):
    with patch.object(SFTPClient, "_send_message") as mock_send:
        with patch.object(SFTPClient, "_receive_message") as mock_recv:
            mock_recv.return_value = SFTPVersionMessage(3, {"ext": "val"})

            client = SFTPClient(mock_transport)

            assert client._server_version == 3
            assert client._server_extensions == {"ext": "val"}
            mock_channel.invoke_subsystem.assert_called_with("sftp")
            sent_msg = mock_send.call_args[0][0]
            assert isinstance(sent_msg, SFTPInitMessage)


def test_sftp_client_init_failure(mock_transport, mock_channel):
    mock_transport.open_channel.return_value = None
    with pytest.raises(SFTPError, match="Failed to open channel"):
        SFTPClient(mock_transport)


def test_sftp_client_get(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        handle = b"h1"
        mock_req.side_effect = [
            SFTPHandleMessage(1, handle),
            SFTPDataMessage(2, b"hello"),
            SFTPStatusMessage(3, SSH_FX_EOF, "EOF"),
            SFTPStatusMessage(4, SSH_FX_OK, "OK"),
        ]

        # We need a local file to write to
        with patch("builtins.open", create=True) as mock_open_call:
            mock_file = MagicMock()
            mock_open_call.return_value.__enter__.return_value = mock_file

            # Using a mock path that won't exist
            with patch("os.path.getsize", return_value=10):
                sftp_client.get("remote.txt", "local.txt")

        assert mock_req.call_count == 4


def test_sftp_client_put(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        handle = b"h1"
        mock_req.side_effect = [
            SFTPHandleMessage(1, handle),
            SFTPStatusMessage(2, SSH_FX_OK, "OK"),
            SFTPStatusMessage(3, SSH_FX_OK, "OK"),
        ]

        with patch("os.path.getsize", return_value=5):
            with patch("builtins.open", MagicMock()) as mock_file_open:
                mock_file_open.return_value.__enter__.return_value.read.side_effect = [
                    b"hello",
                    b"",
                ]
                sftp_client.put("local.txt", "remote.txt")

        assert mock_req.call_count == 3


def test_sftp_client_listdir(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        handle = b"h1"
        mock_req.side_effect = [
            SFTPHandleMessage(1, handle),
            SFTPNameMessage(
                2,
                [
                    ("file1", "long1", SFTPAttributes()),
                    ("file2", "long2", SFTPAttributes()),
                ],
            ),
            SFTPStatusMessage(3, SSH_FX_EOF, "EOF"),
            SFTPStatusMessage(4, SSH_FX_OK, "OK"),
        ]

        files = sftp_client.listdir(".")
        assert files == ["file1", "file2"]
        assert mock_req.call_count == 4


def test_sftp_client_stat(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        attrs = SFTPAttributes()
        attrs.size = 123
        mock_req.return_value = SFTPAttrsMessage(1, attrs)

        res = sftp_client.stat("path")
        assert res.size == 123


def test_sftp_client_mkdir(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPStatusMessage(1, SSH_FX_OK, "OK")
        sftp_client.mkdir("dir")
        assert mock_req.called


def test_sftp_client_remove(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPStatusMessage(1, SSH_FX_OK, "OK")
        sftp_client.remove("file")
        assert mock_req.called


def test_sftp_client_rename(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPStatusMessage(1, SSH_FX_OK, "OK")
        sftp_client.rename("old", "new")
        assert mock_req.called


def test_sftp_client_getcwd(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPNameMessage(
            1, [("/home/user", "", SFTPAttributes())]
        )
        cwd = sftp_client.getcwd()
        assert cwd == "/home/user"


def test_sftp_file_read_write(sftp_client):
    handle = b"h1"
    sfile = SFTPFile(sftp_client, handle, "rb")

    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        # Test read
        mock_req.return_value = SFTPDataMessage(1, b"data")
        assert sfile.read(4) == b"data"

        # Test read all
        mock_req.side_effect = [
            SFTPDataMessage(2, b"part1"),
            SFTPStatusMessage(3, SSH_FX_EOF, "EOF"),
        ]
        assert sfile.read(-1) == b"part1"

        # Test write
        mock_req.side_effect = None
        mock_req.return_value = SFTPStatusMessage(4, SSH_FX_OK, "OK")
        assert sfile.write(b"more") == 4

        # Test close
        mock_req.return_value = SFTPStatusMessage(5, SSH_FX_OK, "OK")
        sfile.close()
        assert sfile._closed

        with pytest.raises(SFTPError, match="closed"):
            sfile.read(1)


def test_sftp_client_receive_message_error(sftp_client, mock_channel):
    # Mock short read for length
    mock_channel.recv.side_effect = [b"a"]
    with pytest.raises(SFTPError, match="Failed to read message length"):
        sftp_client._receive_message()

    # Mock channel failure
    sftp_client._channel = None
    with pytest.raises(SFTPError, match="not available"):
        sftp_client._receive_message()


def test_sftp_client_lstat(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        attrs = SFTPAttributes()
        mock_req.return_value = SFTPAttrsMessage(1, attrs)
        res = sftp_client.lstat("path")
        assert isinstance(res, SFTPAttributes)


def test_sftp_client_rmdir(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPStatusMessage(1, SSH_FX_OK, "OK")
        sftp_client.rmdir("dir")
        assert mock_req.called


def test_sftp_client_normalize(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPNameMessage(
            1, [("/abs/path", "", SFTPAttributes())]
        )
        res = sftp_client.normalize(".")
        assert res == "/abs/path"


def test_sftp_client_chmod(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPStatusMessage(1, SSH_FX_OK, "OK")
        sftp_client.chmod("path", 0o755)
        assert mock_req.called


def test_sftp_file_context_manager(sftp_client):
    handle = b"h1"
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPStatusMessage(1, SSH_FX_OK, "OK")
        with SFTPFile(sftp_client, handle, "rb") as sfile:
            assert sfile._handle == handle
        assert sfile._closed


def test_sftp_client_send_message_error(sftp_client, mock_channel):
    mock_channel.send.side_effect = Exception("Send failed")
    with pytest.raises(SFTPError, match="Failed to send"):
        sftp_client._send_message(SFTPInitMessage(3))


def test_sftp_client_open(sftp_client):
    with patch.object(sftp_client, "_send_request_and_wait_response") as mock_req:
        mock_req.return_value = SFTPHandleMessage(1, b"handle1")
        f = sftp_client.open("test.txt", "r")
        assert isinstance(f, SFTPFile)
        assert f._handle == b"handle1"


def test_sftp_client_context_manager(sftp_client):
    with patch.object(sftp_client, "close") as mock_close:
        with sftp_client as client:
            assert client == sftp_client
        mock_close.assert_called_once()
