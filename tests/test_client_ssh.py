from unittest.mock import MagicMock, patch

import pytest

from spindlex.client.ssh_client import SSHClient
from spindlex.exceptions import AuthenticationException, SSHException


@pytest.fixture
def mock_transport():
    with patch("spindlex.client.ssh_client.Transport") as mock:
        yield mock


@pytest.fixture
def mock_socket():
    with patch("socket.socket") as mock:
        yield mock


def test_ssh_client_connect_password(mock_transport, mock_socket):
    client = SSHClient()
    mock_transport_instance = mock_transport.return_value
    mock_transport_instance.auth_password.return_value = True

    # Mocking verify_host_key to avoid further complexity
    client._verify_host_key = MagicMock()

    client.connect("localhost", username="alice", password="secret")

    assert mock_socket.called
    assert mock_transport_instance.start_client.called
    assert mock_transport_instance.auth_password.called
    assert client.get_transport() == mock_transport_instance


def test_ssh_client_connect_failure(mock_transport, mock_socket):
    client = SSHClient()
    mock_transport_instance = mock_transport.return_value
    mock_transport_instance.auth_password.return_value = False

    client._verify_host_key = MagicMock()

    with pytest.raises(AuthenticationException):
        client.connect("localhost", username="alice", password="wrong")


def test_ssh_client_exec_command(mock_transport):
    client = SSHClient()
    mock_transport_instance = mock_transport.return_value
    client._transport = mock_transport_instance
    client.is_connected = MagicMock(return_value=True)

    mock_channel = MagicMock()
    mock_transport_instance.open_channel.return_value = mock_channel

    client.exec_command("ls -l")

    assert mock_transport_instance.open_channel.called
    assert mock_channel.exec_command.called
    mock_channel.exec_command.assert_called_with("ls -l")


def test_ssh_client_close(mock_transport):
    client = SSHClient()
    mock_transport_instance = mock_transport.return_value
    client._transport = mock_transport_instance

    client.close()
    assert mock_transport_instance.close.called
