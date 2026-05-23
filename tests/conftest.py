import os
import socket
import time
from dataclasses import dataclass

import pytest

try:
    from dotenv import load_dotenv

    load_dotenv(override=True)
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


@dataclass(frozen=True)
class SSHServer:
    host: str
    port: int
    user: str
    password: str
    server_type: str

    def __iter__(self):
        yield self.host
        yield self.port
        yield self.user
        yield self.password

    def __len__(self):
        return 4

    def __getitem__(self, index):
        return (self.host, self.port, self.user, self.password)[index]


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "real_server: requires a live SSH server (Docker or .env)"
    )
    config.addinivalue_line(
        "markers",
        "integration: end-to-end integration tests run against a Docker SSH server",
    )


@pytest.fixture(autouse=True)
def isolated_real_ssh_home(monkeypatch, tmp_path, request):
    """Keep Docker SSH host keys out of the user's real home directory."""
    if request.node.get_closest_marker(
        "real_server"
    ) or request.node.get_closest_marker("integration"):
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))


# ---------------------------------------------------------------------------
# Docker / External Server Fixtures
# ---------------------------------------------------------------------------


def _get_ssh_server_params():
    if _EXTERNAL_SERVER_AVAILABLE:
        return ["openssh"]
    return ["openssh", "dropbear"]


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


@pytest.fixture(scope="session", params=_get_ssh_server_params())
def ssh_server(request):
    """
    Ensure an SSH server is available.
    Supports OpenSSH and Dropbear via Docker.
    """
    server_type = request.param

    if _EXTERNAL_SERVER_AVAILABLE:
        # If external server is provided, we only test against it once
        # (and assume it's compatible with OpenSSH tests)
        return SSHServer(SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD, "external")

    docker_ip = request.getfixturevalue("docker_ip")
    docker_services = request.getfixturevalue("docker_services")
    if not docker_services:
        pytest.skip("No SSH server configured and Docker not available")

    service_name = "openssh-server" if server_type == "openssh" else "dropbear-server"
    internal_port = 22

    port = docker_services.port_for(service_name, internal_port)

    def check():
        try:
            with socket.create_connection((docker_ip, port), timeout=1):
                return True
        except Exception:
            return False

    # Wait for port to open, then give the daemon extra time to finish key generation
    docker_services.wait_until_responsive(timeout=120.0, pause=2.0, check=check)
    time.sleep(15)

    return SSHServer(docker_ip, port, "testuser", "password123", server_type)


@pytest.fixture
def ssh_client(ssh_server):
    """Yield a connected SSHClient; closes after the test."""
    from spindlex import SSHClient
    from spindlex.hostkeys.policy import AutoAddPolicy

    host, port, user, password = ssh_server
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    client.connect(host, port=port, username=user, password=password)
    client._test_server_type = getattr(ssh_server, "server_type", "external")
    yield client
    client.close()
