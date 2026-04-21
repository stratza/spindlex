import pytest
from spindlex import SSHClient
from spindlex.hostkeys.policy import AutoAddPolicy

pytestmark = pytest.mark.real_server


def test_ssh_client_connect(ssh_server):
    host, port, user, password = ssh_server
    client = SSHClient()
    try:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(host, port=port, username=user, password=password)
        assert client.get_transport() is not None
        assert client.get_transport().active
        assert client.get_transport().authenticated
    finally:
        client.close()


def test_ssh_client_exec_command(ssh_client):
    stdin, stdout, stderr = ssh_client.exec_command("echo 'Hello SpindleX'")
    output = stdout.read().decode().strip()
    assert output == "Hello SpindleX"


def test_ssh_client_open_sftp(ssh_client):
    with ssh_client.open_sftp() as sftp:
        assert sftp is not None
        # Check if listdir works
        files = sftp.listdir(".")
        assert isinstance(files, list)


def test_ssh_client_close(ssh_server):
    host, port, user, password = ssh_server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password)
    client.close()
    assert client.get_transport() is None
    assert not client.is_active
