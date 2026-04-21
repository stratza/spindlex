from unittest.mock import MagicMock, patch

from spindlex.client.sftp_client import SFTPClient, SFTPFile
from spindlex.protocol.sftp_constants import SSH_FX_EOF, SSH_FX_OK
from spindlex.protocol.sftp_messages import SFTPDataMessage, SFTPStatusMessage


def test_sftp_file_read_all():
    client = MagicMock()
    # Mock _get_next_request_id and _send_request_and_wait_response
    client._get_next_request_id.side_effect = [1, 2]

    # First response is data, second is EOF
    data_msg = SFTPDataMessage(1, b"some data")
    eof_msg = SFTPStatusMessage(2, SSH_FX_EOF, "EOF")

    client._send_request_and_wait_response.side_effect = [data_msg, eof_msg]

    f = SFTPFile(client, b"handle", "r")
    data = f.read(-1)
    assert data == b"some data"


def test_sftp_file_write_success():
    client = MagicMock()
    client._get_next_request_id.return_value = 1
    ok_msg = SFTPStatusMessage(1, SSH_FX_OK, "OK")
    client._send_request_and_wait_response.return_value = ok_msg

    f = SFTPFile(client, b"handle", "w")
    written = f.write(b"data")
    assert written == 4
    assert f._offset == 4


def test_sftp_file_close():
    client = MagicMock()
    client._get_next_request_id.return_value = 1
    ok_msg = SFTPStatusMessage(1, SSH_FX_OK, "OK")
    client._send_request_and_wait_response.return_value = ok_msg

    f = SFTPFile(client, b"handle", "r")
    f.close()
    assert f._closed
    assert client._send_request_and_wait_response.called


@patch("spindlex.client.sftp_client.SFTPClient._initialize_sftp")
def test_sftp_client_context_manager(mock_init):
    with patch("spindlex.client.sftp_client.SFTPClient.close") as mock_close:
        # We need a mock transport for __init__
        mock_transport = MagicMock()
        client = SFTPClient(mock_transport)
        with client:
            pass
        assert mock_close.called
