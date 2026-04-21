import os
from unittest.mock import MagicMock, patch

import pytest
from spindlex.crypto.pkey import Ed25519Key, RSAKey
from spindlex.hostkeys.storage import HostKeyStorage


class TestHostKeyStorage:
    @pytest.fixture
    def temp_known_hosts(self, tmp_path):
        return str(tmp_path / "known_hosts")

    def test_init_and_load_empty(self, temp_known_hosts):
        storage = HostKeyStorage(temp_known_hosts)
        assert storage._filename == temp_known_hosts
        assert len(storage._keys) == 0

    def test_add_and_get(self, temp_known_hosts):
        storage = HostKeyStorage(temp_known_hosts)
        key = MagicMock(spec=Ed25519Key)
        key.algorithm_name = "ssh-ed25519"

        storage.add("example.com", key)
        assert storage.get("example.com") == key
        assert storage.get_all("example.com") == [key]
        assert storage.get("unknown.com") is None

    def test_save_and_load(self, temp_known_hosts):
        storage = HostKeyStorage(temp_known_hosts)

        # Mock an Ed25519 key
        key = MagicMock(spec=Ed25519Key)
        key.algorithm_name = "ssh-ed25519"
        key.get_public_key_bytes.return_value = b"fake-key-data"

        storage.add("localhost", key)
        storage.save()

        # Verify file exists
        assert os.path.exists(temp_known_hosts)

        # Load in new storage instance
        # We need to mock the key creation for loading
        with patch(
            "spindlex.hostkeys.storage.HostKeyStorage._create_key_from_type_and_data"
        ) as mock_create:
            mock_create.return_value = key
            new_storage = HostKeyStorage(temp_known_hosts)
            assert new_storage.get("localhost") == key

    def test_parse_line_formats(self, temp_known_hosts):
        # Use valid base64 data for keys (or at least data that looks like it could be valid)
        # Actually, let's use real generated keys to be sure
        import base64

        ed_key = Ed25519Key.generate()
        ed_b64 = base64.b64encode(ed_key.get_public_key_bytes()).decode("ascii")

        rsa_key = RSAKey.generate(bits=1024)
        rsa_b64 = base64.b64encode(rsa_key.get_public_key_bytes()).decode("ascii")

        content = (
            "# A comment\n"
            f"host1 ssh-ed25519 {ed_b64}\n"
            f"host2,host3 ssh-rsa {rsa_b64}\n"
            "\n"
            "host4 ssh-ed25519 invalid-base64-!!\n"
        )
        with open(temp_known_hosts, "w", encoding="utf-8") as f:
            f.write(content)

        storage = HostKeyStorage(temp_known_hosts)

        # Check parsing results
        assert "host1" in storage._keys
        assert "host2" in storage._keys
        assert "host3" in storage._keys
        assert "host4" not in storage._keys
        assert len(storage._keys["host1"]) == 1
        assert len(storage._keys["host2"]) == 1

    def test_remove_keys(self, temp_known_hosts):
        storage = HostKeyStorage(temp_known_hosts)
        key1 = MagicMock(spec=Ed25519Key)
        key2 = MagicMock(spec=RSAKey)

        storage.add("host", key1)
        storage.add("host", key2)

        assert len(storage.get_all("host")) == 2

        # Remove partial
        storage.remove("host", key1)
        assert storage.get_all("host") == [key2]

        # Remove all
        storage.remove("host")
        assert "host" not in storage._keys

    def test_create_key_from_type_and_data(self, temp_known_hosts):
        storage = HostKeyStorage(temp_known_hosts)

        # We can't easily mock the imports inside the method without patching the whole method or using real keys
        # Let's use real keys to test the actual logic path

        real_key = Ed25519Key.generate()
        key_data = real_key.get_public_key_bytes()

        key = storage._create_key_from_type_and_data("ssh-ed25519", key_data)
        assert isinstance(key, Ed25519Key)
        assert key.get_public_key_bytes() == key_data

        # Test unsupported type
        assert storage._create_key_from_type_and_data("unknown-type", b"data") is None
