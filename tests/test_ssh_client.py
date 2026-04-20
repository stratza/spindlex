from unittest.mock import MagicMock, patch

import pytest
from spindlex.client.ssh_client import SSHClient


@pytest.fixture
def mock_socket():
    return MagicMock()


@pytest.fixture
def ssh_client(mock_socket):
    with patch("socket.socket", return_value=mock_socket):
        client = SSHClient()
        # Mock transport to avoid real connection
        client._transport = MagicMock()
        client._transport.active = False
        client._transport.authenticated = False
        yield client


def test_ssh_client_connect(ssh_client, mock_socket):
    with patch("spindlex.transport.transport.Transport.start_client"):
        # Clear the mocked transport from fixture so connect() can create a new one
        ssh_client._transport = None
        
        # We need to patch the Transport constructor to return a mock
        with patch("spindlex.client.ssh_client.Transport") as mock_transport_class:
            mock_transport = MagicMock()
            mock_transport.active = True
            mock_transport.auth_password.return_value = True
            mock_transport_class.return_value = mock_transport
            
            # Bypass host key verification for this test
            with patch.object(ssh_client, "_verify_host_key"):
                ssh_client.connect("localhost", username="alice", password="password")
                assert ssh_client.get_transport() is not None


def test_ssh_client_exec_command(ssh_client):
    transport = MagicMock()
    ssh_client._transport = transport
    channel = MagicMock()
    transport.open_channel.return_value = channel

    stdin, stdout, stderr = ssh_client.exec_command("ls")
    assert transport.open_channel.called
    assert channel.exec_command.called


def test_ssh_client_open_sftp(ssh_client):
    transport = MagicMock()
    ssh_client._transport = transport
    transport.active = True
    transport.authenticated = True

    with patch("spindlex.client.sftp_client.SFTPClient") as mock_sftp:
        ssh_client.open_sftp()
        assert mock_sftp.called
        assert mock_sftp.call_args[0][0] == transport


def test_ssh_client_close(ssh_client):
    transport = MagicMock()
    ssh_client._transport = transport
    ssh_client.close()
    assert transport.close.called
    assert ssh_client.get_transport() is None
