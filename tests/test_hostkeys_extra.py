import os
import tempfile
from unittest.mock import MagicMock

import pytest
from spindlex.crypto.pkey import RSAKey
from spindlex.hostkeys.policy import AutoAddPolicy, RejectPolicy, WarningPolicy
from spindlex.hostkeys.storage import HostKeyStorage


@pytest.fixture
def temp_hosts():
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        path = tmp.name
    yield path
    if os.path.exists(path):
        os.remove(path)


def test_host_key_storage_basic(temp_hosts):
    storage = HostKeyStorage(temp_hosts)
    assert len(storage._keys) == 0

    key = RSAKey.generate(1024)
    storage.add("localhost", key)

    assert "localhost" in storage._keys
    assert storage.get("localhost").get_public_key_bytes() == key.get_public_key_bytes()
    assert storage.get("unknown") is None


def test_auto_add_policy(temp_hosts):
    policy = AutoAddPolicy()
    client = MagicMock()
    client._host_key_storage = HostKeyStorage(temp_hosts)
    key = RSAKey.generate(1024)

    # Should add the key to storage
    policy.missing_host_key(client, "localhost", key)
    stored_key = client._host_key_storage.get("localhost")
    assert stored_key.get_public_key_bytes() == key.get_public_key_bytes()


def test_reject_policy():
    policy = RejectPolicy()
    client = MagicMock()
    key = RSAKey.generate(1024)
    from spindlex.exceptions import SSHException

    with pytest.raises(SSHException):
        policy.missing_host_key(client, "localhost", key)


def test_warning_policy(temp_hosts):
    policy = WarningPolicy()
    client = MagicMock()
    key = RSAKey.generate(1024)
    client._host_key_storage = HostKeyStorage(temp_hosts)
    policy.missing_host_key(client, "localhost", key)
    assert client._host_key_storage.get("localhost") is None
