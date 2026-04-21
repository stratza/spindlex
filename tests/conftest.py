import os
import socket
import time

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


@pytest.fixture(scope="session")
def ssh_server(docker_ip=None, docker_services=None, pytestconfig=None):
    """
    Ensure an SSH server is available.
    Favors external config from .env, falls back to Docker.
    """
    if _EXTERNAL_SERVER_AVAILABLE:
        return SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD

    if not docker_services:
        pytest.skip("No SSH server configured and Docker not available")

    port = docker_services.port_for("openssh-server", 2222)

    def check():
        try:
            with socket.create_connection((docker_ip, port), timeout=2):
                return True
        except Exception:
            return False

    # Wait for SSH server responsive
    docker_services.wait_until_responsive(timeout=60.0, pause=2.0, check=check)

    # Give it a bit more time to settle
    time.sleep(2)

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
