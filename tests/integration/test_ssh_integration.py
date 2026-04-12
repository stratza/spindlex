import os
import socket
import time

import pytest
from spindlex import SSHClient
from spindlex.hostkeys.policy import AutoAddPolicy

# Skip tests if docker is not available
pytestmark = pytest.mark.integration


@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig):
    return os.path.join(
        str(pytestconfig.rootdir), "tests", "integration", "docker-compose.yml"
    )


@pytest.fixture(scope="session")
def ssh_server(docker_ip, docker_services):
    """Ensure that SSH server is up and responsive."""
    port = docker_services.port_for("openssh-server", 22)

    def check():
        try:
            with socket.create_connection((docker_ip, port), timeout=2) as sock:
                sock.settimeout(2)
                banner = sock.recv(1024)
                return banner.startswith(b"SSH-")
        except Exception:
            return False

    # Wait for SSH server to be responsive (increase timeout for CI)
    docker_services.wait_until_responsive(timeout=60.0, pause=1.0, check=check)
    return docker_ip, port


def test_ssh_connect_password(ssh_server):
    host, port = ssh_server
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(
            hostname=host, port=port, username="testuser", password="password123"
        )
        assert client.get_transport().active
        assert client.get_transport().authenticated


def test_ssh_execute_command(ssh_server):
    host, port = ssh_server
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(host, port=port, username="testuser", password="password123")

        stdin, stdout, stderr = client.exec_command("echo 'Hello SpindleX'")
        output = stdout.read().decode().strip()
        assert output == "Hello SpindleX"


def test_sftp_upload_download(ssh_server, tmp_path):
    host, port = ssh_server
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(host, port=port, username="testuser", password="password123")

        with client.open_sftp() as sftp:
            # Create local file
            local_file = tmp_path / "test.txt"
            local_file.write_text("Integrate me!")

            # Upload
            remote_path = "test_upload.txt"
            sftp.put(str(local_file), remote_path)

            # Download
            download_file = tmp_path / "downloaded.txt"
            sftp.get(remote_path, str(download_file))

            assert download_file.read_text() == "Integrate me!"

            # Cleanup
            sftp.remove(remote_path)


@pytest.mark.slow
def test_rekeying_end_to_end(ssh_server):
    """
    Test that rekeying fires and session survives.
    We set a very low byte limit to trigger rekeying quickly.
    """
    host, port = ssh_server
    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect(host, port=port, username="testuser", password="password123")

        transport = client.get_transport()
        # Set rekey limit to 1KB bytes
        transport.set_rekey_policy(bytes_limit=1024)

        # Initial state
        initial_rekey_time = transport._last_rekey_time

        # Transfer more than 1KB to trigger rekey
        stdin, stdout, stderr = client.exec_command(
            "dd if=/dev/urandom bs=2048 count=1"
        )
        data = stdout.read()
        assert len(data) == 2048

        # Wait a bit for the background thread to finish KEX
        time.sleep(2)

        # Verify rekey occurred (timestamp updated)
        assert transport._last_rekey_time > initial_rekey_time
        assert not transport._kex_in_progress

        # Verify session is still alive
        stdin, stdout, stderr = client.exec_command("echo 'Still alive'")
        assert stdout.read().decode().strip() == "Still alive"
