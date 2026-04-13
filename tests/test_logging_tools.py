import logging
import unittest

from spindlex.logging.formatters import SSHFormatter
from spindlex.logging.logger import get_logger
from spindlex.logging.sanitizer import LogSanitizer


class TestLogging(unittest.TestCase):
    def test_sanitizer_basic(self):
        text = "Password is: secret123"
        sanitized = LogSanitizer.sanitize_message(text)
        assert "secret123" not in sanitized

    def test_formatter(self):
        formatter = SSHFormatter()
        record = logging.LogRecord(
            "test", logging.INFO, "test.py", 10, "message", None, None
        )
        formatted = formatter.format(record)
        assert "INFO" in formatted
        assert "message" in formatted

    def test_logger_get(self):
        logger = get_logger("test_service")
        assert logger.name == "spindlex.test_service"


class TestTools(unittest.TestCase):
    def test_keygen_cli(self):
        # We can't easily test CLI but we can test the PKey generation
        from spindlex.crypto.pkey import Ed25519Key, RSAKey

        key = RSAKey.generate(bits=2048)
        assert key.get_name() == "rsa-sha2-256"

        ed_key = Ed25519Key.generate()
        assert ed_key.get_name() == "ssh-ed25519"


if __name__ == "__main__":
    unittest.main()
