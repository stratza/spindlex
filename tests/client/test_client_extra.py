from unittest.mock import MagicMock, patch

import pytest

from spindlex.client.ssh_client import ChannelFile, SSHClient
from spindlex.exceptions import (
    BadHostKeyException,
    SSHException,
)
from spindlex.hostkeys.policy import AutoAddPolicy, RejectPolicy


def test_channel_file_read():
    channel = MagicMock()
    channel.recv.side_effect = [b"data1", b"data2", b""]

    cf = ChannelFile(channel, mode="r")
    assert cf.read() == b"data1data2"
    assert channel.recv.call_count == 3


def test_channel_file_read_size():
    channel = MagicMock()
    channel.recv.return_value = b"data"

    cf = ChannelFile(channel, mode="r")
    assert cf.read(4) == b"data"
    channel.recv.assert_called_with(4)


def test_channel_file_write():
    channel = MagicMock()
    channel.send.return_value = 5

    cf = ChannelFile(channel, mode="w")
    assert cf.write("hello") == 5
    channel.send.assert_called_with(b"hello")


def test_channel_file_context_manager():
    channel = MagicMock()
    with ChannelFile(channel, mode="r") as cf:
        assert not cf._closed
    assert cf._closed


def test_ssh_client_connect_socket_fail():
    client = SSHClient()
    with patch("socket.socket") as mock_sock_cls:
        mock_sock = mock_sock_cls.return_value
        mock_sock.connect.side_effect = OSError("Connection refused")

        with pytest.raises(SSHException, match="Connection failed"):
            client.connect("localhost")

        assert mock_sock.close.called


def test_ssh_client_connect_transport_fail():
    client = SSHClient()
    with patch("socket.socket"):
        with patch(
            "spindlex.transport.transport.Transport.start_client",
            side_effect=Exception("KEX failed"),
        ):
            with pytest.raises(SSHException, match="Connection failed"):
                client.connect("localhost")


def test_ssh_client_verify_host_key_reject():
    client = SSHClient()
    transport = MagicMock()
    client._transport = transport
    client._hostname = "localhost"

    server_key = MagicMock()
    server_key.get_public_key_bytes.return_value = b"server_key"
    transport.get_server_host_key.return_value = server_key

    # Mock storage to return None (unknown host)
    client._host_key_storage = MagicMock()
    client._host_key_storage.get.return_value = None

    # RejectPolicy should raise BadHostKeyException
    client.set_missing_host_key_policy(RejectPolicy())

    with pytest.raises(BadHostKeyException):
        client._verify_host_key()


def test_ssh_client_verify_host_key_auto_add():
    client = SSHClient()
    transport = MagicMock()
    client._transport = transport
    client._hostname = "localhost"

    server_key = MagicMock()
    server_key.get_public_key_bytes.return_value = b"server_key"
    transport.get_server_host_key.return_value = server_key

    client._host_key_storage = MagicMock()
    client._host_key_storage.get_all.return_value = []

    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    # Should not raise
    client._verify_host_key()
    assert client._host_key_storage.add.called


def test_ssh_client_verify_host_key_mismatch():
    client = SSHClient()
    transport = MagicMock()
    client._transport = transport
    client._hostname = "localhost"

    server_key = MagicMock()
    server_key.get_public_key_bytes.return_value = b"new_key"
    transport.get_server_host_key.return_value = server_key

    known_key = MagicMock()
    known_key.get_public_key_bytes.return_value = b"old_key"
    client._host_key_storage = MagicMock()
    client._host_key_storage.get_all.return_value = [known_key]

    with pytest.raises(BadHostKeyException):
        client._verify_host_key()


def test_ssh_client_context_manager():
    with patch("socket.socket"):
        with patch("spindlex.transport.transport.Transport") as mock_trans_cls:
            mock_trans = mock_trans_cls.return_value
            mock_trans.active = True
            mock_trans.authenticated = True

            with SSHClient() as client:
                client._transport = mock_trans
                client._hostname = "localhost"

            assert mock_trans.close.called


def test_ssh_client_auth_methods():
    client = SSHClient()
    transport = MagicMock()
    client._transport = transport

    transport.auth_password.return_value = True
    client.auth_password("user", "pass")
    transport.auth_password.assert_called_with("user", "pass")

    transport.auth_publickey.return_value = True
    key = MagicMock()
    client.auth_publickey("user", key)
    transport.auth_publickey.assert_called_with("user", key)

    transport.auth_keyboard_interactive.return_value = True
    client.auth_keyboard_interactive("user")
    transport.auth_keyboard_interactive.assert_called()


def test_ssh_client_is_connected():
    client = SSHClient()
    assert client.is_connected() is False

    transport = MagicMock()
    client._transport = transport
    transport.active = True
    transport.authenticated = True
    assert client.is_connected() is True

    transport.authenticated = False
    assert client.is_connected() is False
