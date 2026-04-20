"""Tests for spindlex.tools.keygen and benchmark CLI tools."""
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from spindlex.tools.keygen import generate_key, save_key_pair, main


class TestGenerateKey:
    def test_generate_ed25519(self):
        priv, pub = generate_key("ed25519")
        assert priv is not None
        assert pub is not None

    def test_generate_ecdsa(self):
        priv, pub = generate_key("ecdsa")
        assert priv is not None
        assert pub is not None

    def test_generate_rsa_default(self):
        priv, pub = generate_key("rsa")
        assert priv is not None
        assert pub is not None

    def test_generate_rsa_explicit_bits(self):
        priv, pub = generate_key("rsa", bits=2048)
        assert priv is not None

    def test_generate_rsa_too_small_raises(self):
        with pytest.raises(ValueError, match="2048"):
            generate_key("rsa", bits=1024)

    def test_generate_unsupported_type(self):
        with pytest.raises(ValueError, match="Unsupported key type"):
            generate_key("dsa")

    def test_generate_with_comment(self):
        priv, pub = generate_key("ed25519", comment="test@example.com")
        assert priv is not None


class TestSaveKeyPair:
    def test_save_ed25519(self, tmp_path):
        import sys
        priv, pub = generate_key("ed25519")
        filename = str(tmp_path / "id_ed25519")
        save_key_pair(priv, pub, filename)

        assert Path(filename).exists()
        assert Path(f"{filename}.pub").exists()
        # Permission check only meaningful on POSIX systems
        if sys.platform != "win32":
            assert oct(Path(filename).stat().st_mode)[-3:] == "600"
            assert oct(Path(f"{filename}.pub").stat().st_mode)[-3:] == "644"

    def test_save_with_comment(self, tmp_path):
        priv, pub = generate_key("ed25519")
        filename = str(tmp_path / "id_ed25519_comment")
        save_key_pair(priv, pub, filename, comment="user@host")

        pub_content = Path(f"{filename}.pub").read_text()
        assert "user@host" in pub_content

    def test_save_ecdsa(self, tmp_path):
        priv, pub = generate_key("ecdsa")
        filename = str(tmp_path / "id_ecdsa")
        save_key_pair(priv, pub, filename)
        assert Path(filename).exists()

    def test_save_rsa(self, tmp_path):
        priv, pub = generate_key("rsa")
        filename = str(tmp_path / "id_rsa")
        save_key_pair(priv, pub, filename)
        assert Path(filename).exists()


class TestMainCLI:
    def test_main_ed25519(self, tmp_path):
        filename = str(tmp_path / "test_ed25519")
        with patch("sys.argv", ["keygen", "-t", "ed25519", "-f", filename]):
            main()
        assert Path(filename).exists()
        assert Path(f"{filename}.pub").exists()

    def test_main_rsa(self, tmp_path):
        filename = str(tmp_path / "test_rsa")
        with patch("sys.argv", ["keygen", "-t", "rsa", "-f", filename]):
            main()
        assert Path(filename).exists()

    def test_main_ecdsa(self, tmp_path):
        filename = str(tmp_path / "test_ecdsa")
        with patch("sys.argv", ["keygen", "-t", "ecdsa", "-f", filename]):
            main()
        assert Path(filename).exists()

    def test_main_with_comment(self, tmp_path):
        filename = str(tmp_path / "test_comment")
        with patch("sys.argv", ["keygen", "-t", "ed25519", "-f", filename, "-C", "me@host"]):
            main()
        pub = Path(f"{filename}.pub").read_text()
        assert "me@host" in pub

    def test_main_overwrite_false_existing_private(self, tmp_path):
        filename = str(tmp_path / "existing")
        Path(filename).write_text("fake")

        with patch("sys.argv", ["keygen", "-t", "ed25519", "-f", filename]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    def test_main_overwrite_false_existing_pub(self, tmp_path):
        filename = str(tmp_path / "existing2")
        Path(f"{filename}.pub").write_text("fake pub")

        with patch("sys.argv", ["keygen", "-t", "ed25519", "-f", filename]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    def test_main_overwrite_true(self, tmp_path):
        filename = str(tmp_path / "overwrite_test")
        # Create first key
        with patch("sys.argv", ["keygen", "-t", "ed25519", "-f", filename]):
            main()

        # Overwrite with second
        with patch("sys.argv", ["keygen", "-t", "ed25519", "-f", filename, "--overwrite"]):
            main()

        assert Path(filename).exists()

    def test_main_rsa_with_bits(self, tmp_path):
        filename = str(tmp_path / "test_rsa_bits")
        with patch("sys.argv", ["keygen", "-t", "rsa", "-b", "2048", "-f", filename]):
            main()
        assert Path(filename).exists()

    def test_main_invalid_key_type_raises(self, tmp_path):
        filename = str(tmp_path / "bad_type")
        # argparse will reject unknown choices and exit(2)
        with patch("sys.argv", ["keygen", "-t", "dsa", "-f", filename]):
            with pytest.raises(SystemExit):
                main()
