"""Shared pytest fixtures for SpindleX test suite."""
import os

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

_REAL_SERVER_AVAILABLE = bool(SSH_HOST and SSH_USER)


def pytest_configure(config):
    config.addinivalue_line("markers", "real_server: requires a live SSH server via .env")


def pytest_collection_modifyitems(config, items):
    skip = pytest.mark.skip(reason="No SSH server configured (set SSH_HOST, SSH_USER in .env)")
    for item in items:
        if "real_server" in item.keywords and not _REAL_SERVER_AVAILABLE:
            item.add_marker(skip)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def real_server_creds():
    """Return (host, port, user, password) for the real SSH server."""
    if not _REAL_SERVER_AVAILABLE:
        pytest.skip("No real SSH server configured")
    return SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD


@pytest.fixture
def ssh_client(real_server_creds):
    """Yield a connected SSHClient; closes after the test."""
    from spindlex import SSHClient
    from spindlex.hostkeys.policy import AutoAddPolicy

    host, port, user, password = real_server_creds
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password)
    yield client
    client.close()
