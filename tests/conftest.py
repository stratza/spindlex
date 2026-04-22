import os
import socket

import pytest

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Real-server connection details (loaded from .env or environment)
# ---------------------------------------------------------------------------

SSH_HOST = os.getenv("SSH_HOST", "")
SSH_PORT = int(os.getenv("SSH_PORT", "22"))
SSH_USER = os.getenv("SSH_USER", "")
SSH_PASSWORD = os.getenv("SSH_PASSWORD", "")
SSH_KEY_PATH = os.getenv("SSH_KEY_PATH", "")

_EXTERNAL_SERVER_AVAILABLE = bool(SSH_HOST and SSH_USER)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_server: requires a live SSH server (Docker or .env)"
    )
    config.addinivalue_line(
        "markers",
        "integration: end-to-end integration tests run against a Docker SSH server",
    )


# ---------------------------------------------------------------------------
# Docker / External Server Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def docker_compose_file(pytestconfig):
    """Path to the docker-compose.yml for integration tests."""
    # Look for it in the integration dir
    path = os.path.join(
        str(pytestconfig.rootdir), "tests", "integration", "docker-compose.yml"
    )
    if os.path.exists(path):
        return path
    return None


@pytest.fixture(scope="session", params=["openssh", "dropbear"])
def ssh_server(request, docker_ip=None, docker_services=None, pytestconfig=None):
    """
    Ensure an SSH server is available.
    Supports OpenSSH and Dropbear via Docker.
    """
    server_type = request.param

    if _EXTERNAL_SERVER_AVAILABLE:
        # If external server is provided, we only test against it once
        # (or we could assume it's OpenSSH)
        if server_type != "openssh":
            pytest.skip("External server only supports OpenSSH tests")
        return SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD

    if not docker_services:
        pytest.skip("No SSH server configured and Docker not available")

    service_name = "openssh-server" if server_type == "openssh" else "dropbear-server"
    internal_port = 2222 if server_type == "openssh" else 22

    port = docker_services.port_for(service_name, internal_port)

    def check():
        try:
            with socket.create_connection((docker_ip, port), timeout=1):
                return True
        except Exception:
            return False

    # Wait for SSH server responsive
    docker_services.wait_until_responsive(timeout=30.0, pause=2.0, check=check)

    return docker_ip, port, "testuser", "password123"


@pytest.fixture
def ssh_client(ssh_server):
    """Yield a connected SSHClient; closes after the test."""
    from spindlex import SSHClient
    from spindlex.hostkeys.policy import AutoAddPolicy

    host, port, user, password = ssh_server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password)
    yield client
    client.close()
