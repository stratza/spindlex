from unittest.mock import patch

from spindlex.client.ssh_client import SSHClient


def test_client_init_defaults():
    client = SSHClient()
    assert client._host_key_storage is not None
    assert client._transport is None
    assert client._host_key_policy is not None


def test_client_context_manager():
    with patch("socket.socket") as _:
        # Mock connect to not fail immediately
        with SSHClient() as client:
            assert isinstance(client, SSHClient)
            # Should call close on exit
            with patch.object(client, "close") as _:
                pass
            # Manual check because __exit__ calls self.close()


def test_client_connect_params():
    with patch("socket.socket") as mock_sock:
        mock_instance = mock_sock.return_value
        client = SSHClient()

        # Mock transport start to avoid full handshake
        with patch("spindlex.transport.transport.Transport.start_client"):
            with patch.object(client, "_authenticate"):
                client.connect("localhost", port=2222, timeout=5.0)

                assert mock_sock.call_count >= 1
                mock_instance.settimeout.assert_called_with(5.0)
                mock_instance.connect.assert_called_with(("localhost", 2222))


def test_client_get_transport_not_connected():
    client = SSHClient()
    assert client.get_transport() is None


def test_client_close_not_connected():
    client = SSHClient()
    client.close()  # Should not raise
