import pytest
from unittest.mock import MagicMock, patch
from spindlex import SSHClient
from spindlex.hostkeys.policy import RejectPolicy, AutoAddPolicy

def test_ssh_client_default_policy():
    client = SSHClient()
    assert isinstance(client._host_key_policy, RejectPolicy)

def test_ssh_client_set_policy():
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    assert isinstance(client._host_key_policy, AutoAddPolicy)

def test_ssh_client_get_transport_none():
    client = SSHClient()
    assert client.get_transport() is None

@patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
@patch("spindlex.client.ssh_client.Transport")
def test_ssh_client_connect_mock(mock_transport_class, mock_verify):
    mock_transport = MagicMock()
    mock_transport_class.return_value = mock_transport
    
    client = SSHClient()
    # Mock socket.socket
    with patch("spindlex.client.ssh_client.socket.socket") as mock_socket_class:
        mock_sock = MagicMock()
        mock_socket_class.return_value = mock_sock
        
        client.connect("localhost", username="user", password="pass")
        
        assert mock_socket_class.called
        assert mock_sock.connect.called
        assert mock_transport_class.called
        assert mock_transport.start_client.called
        assert mock_transport.auth_password.called

def test_ssh_client_is_active():
    client = SSHClient()
    assert not client.is_active
    
    client._transport = MagicMock()
    client._transport.active = True
    assert client.is_active

def test_ssh_client_get_host_keys():
    client = SSHClient()
    assert client.get_host_keys() == client._host_key_storage

def test_ssh_client_close():
    client = SSHClient()
    mock_transport = MagicMock()
    client._transport = mock_transport
    client.close()
    assert mock_transport.close.called
    assert client._transport is None

def test_ssh_client_context_manager():
    with patch("spindlex.client.ssh_client.SSHClient.close") as mock_close:
        with SSHClient() as client:
            pass
        assert mock_close.called
