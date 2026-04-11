from unittest.mock import MagicMock, patch

import pytest
from spindlex.client.ssh_client import SSHClient
from spindlex.exceptions import AuthenticationException


@pytest.fixture
def mock_socket():
    return MagicMock()


@pytest.fixture
def ssh_client(mock_socket):
    with patch("socket.socket", return_value=mock_socket):
        client = SSHClient()
        # Mock transport to avoid real connection
        client._transport = MagicMock()
        return client


def test_ssh_client_connect(ssh_client, mock_socket):
    with patch("spindlex.transport.transport.Transport.start_client"):
        with patch.object(ssh_client, "auth_password", return_value=True):
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
    
    with patch("spindlex.client.sftp_client.SFTPClient") as mock_sftp:
        ssh_client.open_sftp()
        assert transport.open_channel.called
        assert mock_sftp.called


def test_ssh_client_close(ssh_client):
    transport = MagicMock()
    ssh_client._transport = transport
    ssh_client.close()
    assert transport.close.called
    assert ssh_client.get_transport() is None
