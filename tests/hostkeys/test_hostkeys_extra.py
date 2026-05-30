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
    policy = AutoAddPolicy(accept_risk=True)
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
    """WarningPolicy logs a warning AND stores the key on first use (TOFU)."""
    policy = WarningPolicy()
    client = MagicMock()
    key = RSAKey.generate(1024)
    client._host_key_storage = HostKeyStorage(temp_hosts)
    policy.missing_host_key(client, "localhost", key)
    assert client._host_key_storage.get("localhost") is not None


def test_auto_add_policy_storage_failure():
    policy = AutoAddPolicy(accept_risk=True)
    client = MagicMock()
    storage = MagicMock()
    # Mock storage.save to raise an exception
    storage.save.side_effect = Exception("Storage full")
    client._host_key_storage = storage

    hostname = "test.example.com"
    key = MagicMock()
    key.algorithm_name = "ssh-ed25519"
    key.get_fingerprint.return_value = "SHA256:abc..."

    from spindlex.exceptions import SSHException

    with pytest.raises(SSHException) as excinfo:
        policy.missing_host_key(client, hostname, key)

    assert "Failed to persist new host key" in str(excinfo.value)


def test_auto_add_policy_without_accept_risk_emits_warning():
    """AutoAddPolicy() with accept_risk=False emits UserWarning."""
    import warnings

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        policy = AutoAddPolicy(accept_risk=False)
        assert policy._accept_risk is False
    user_warnings = [w for w in caught if issubclass(w.category, UserWarning)]
    assert len(user_warnings) == 1
    assert "insecure" in str(user_warnings[0].message).lower()


def test_auto_add_policy_missing_host_key_no_storage():
    """missing_host_key logs debug when client has no host key storage."""
    policy = AutoAddPolicy(accept_risk=True)
    client = MagicMock(spec=[])  # no _host_key_storage attribute
    key = MagicMock()
    key.algorithm_name = "ssh-ed25519"
    key.get_fingerprint.return_value = "SHA256:abc..."
    # Should not raise; the else branch logs a debug message
    policy.missing_host_key(client, "host.example.com", key)
