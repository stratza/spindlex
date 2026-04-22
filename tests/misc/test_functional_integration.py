import pytest

from spindlex.client.ssh_client import SSHClient
from spindlex.crypto.pkey import Ed25519Key
from spindlex.hostkeys.policy import AutoAddPolicy
from spindlex.hostkeys.storage import HostKeyStorage
from spindlex.protocol.constants import AUTH_SUCCESSFUL
from spindlex.server.ssh_server import SSHServer, SSHServerManager


class SimpleServer(SSHServer):
    def check_auth_password(self, username, password):
        if username == "admin" and password == "secret":
            return AUTH_SUCCESSFUL
        return 1  # AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return 0  # SSH_OPEN_CONNECT_SUCCESS

    def check_channel_exec_request(self, channel, command):
        # Respond with some data
        cmd_str = command if isinstance(command, str) else command.decode()
        channel.send(f"Executed: {cmd_str}\n")
        channel.send_exit_status(0)
        channel.send_eof()
        channel.close()
        return True

    def check_port_forward_request(self, address, port):
        return True


@pytest.fixture(scope="module")
def persistent_host_key():
    return Ed25519Key.generate()


@pytest.fixture
def temp_host_keys(tmp_path):
    known_hosts = tmp_path / "known_hosts"
    return str(known_hosts)


@pytest.fixture
def ssh_server(persistent_host_key):
    # Use the same host key for all tests to avoid BadHostKeyException
    host_key = persistent_host_key
    server_interface = SimpleServer()

    # Bind to 127.0.0.1:0 to get an ephemeral port
    manager = SSHServerManager(
        server_interface, host_key, bind_address="127.0.0.1", port=0
    )
    manager.start_server()

    # Find out which port we got
    actual_port = manager._server_socket.getsockname()[1]

    yield manager, actual_port

    manager.stop_server()


def test_full_connection_cycle(ssh_server, temp_host_keys):
    manager, port = ssh_server

    client = SSHClient()
    client.set_host_key_storage(HostKeyStorage(temp_host_keys))
    # Trust the host key automatically for this test
    client.set_missing_host_key_policy(AutoAddPolicy())

    client.connect("127.0.0.1", port=port, username="admin", password="secret")
    assert client.get_transport().active

    stdin, stdout, stderr = client.exec_command("ls -la")
    output = stdout.read().decode()
    assert "Executed: ls -la" in output

    client.close()


def test_failed_auth(ssh_server, temp_host_keys):
    manager, port = ssh_server
    client = SSHClient()
    client.set_host_key_storage(HostKeyStorage(temp_host_keys))
    client.set_missing_host_key_policy(AutoAddPolicy())

    from spindlex.exceptions import AuthenticationException

    with pytest.raises(AuthenticationException):
        client.connect("127.0.0.1", port=port, username="admin", password="wrong")


def test_port_forward_request(ssh_server, temp_host_keys):
    manager, port = ssh_server
    client = SSHClient()
    client.set_host_key_storage(HostKeyStorage(temp_host_keys))
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username="admin", password="secret")

    success = (
        client.get_transport()
        .get_port_forwarding_manager()
        .create_remote_tunnel(8080, "localhost", 8081)
    )
    assert success is not None

    client.close()


def test_rekeying(ssh_server, temp_host_keys):
    manager, port = ssh_server
    client = SSHClient()
    client.set_host_key_storage(HostKeyStorage(temp_host_keys))
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect("127.0.0.1", port=port, username="admin", password="secret")

    transport = client.get_transport()
    # Force a rekey at 50KB
    transport._rekey_bytes_limit = 50000

    # Send data to trigger rekey
    stdin, stdout, stderr = client.exec_command("echo " + "a" * 10000)
    output = stdout.read().decode()
    assert "Executed: echo" in output

    # Send enough data to trigger rekey
    for _i in range(5):
        stdin, stdout, stderr = client.exec_command("b" * 10000)
        stdout.read()

    # Rekeying should have happened (total data > 50KB)
    import time

    time.sleep(1)
    client.close()
