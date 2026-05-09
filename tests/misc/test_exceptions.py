from unittest.mock import MagicMock

from spindlex.exceptions import (
    AuthenticationException,
    BadHostKeyException,
    CryptoException,
    IncompatiblePeer,
    ProtocolException,
    SFTPError,
    SSHException,
    TimeoutException,
    TransportException,
)


def test_base_exception():
    e = SSHException("error", 123)
    assert str(e) == "[123] error"

    e2 = SSHException("error")
    assert str(e2) == "error"


def test_auth_exception():
    e = AuthenticationException("failed", ["password"])
    assert e.message == "failed"
    assert e.allowed_methods == ["password"]


def test_bad_host_key_exception():
    e = BadHostKeyException("localhost", "key")
    assert "localhost" in str(e)
    assert e.hostname == "localhost"


def test_sftp_error():
    e = SFTPError("eof", SFTPError.SSH_FX_EOF)
    assert e.sftp_code == SFTPError.SSH_FX_EOF
    assert e.status_code == SFTPError.SSH_FX_EOF

    e2 = SFTPError.from_status(SFTPError.SSH_FX_PERMISSION_DENIED, filename="test.txt")
    assert "Permission denied" in str(e2)
    assert "test.txt" in str(e2)


def test_transport_exception():
    e = TransportException("failed", 11)
    assert e.disconnect_code == 11


def test_protocol_exception():
    e = ProtocolException("bad message", "2.0")
    assert e.protocol_version == "2.0"


def test_crypto_exception():
    e = CryptoException("failed", "aes")
    assert e.algorithm == "aes"


def test_bad_host_key_with_fingerprints():
    expected_key = MagicMock()
    expected_key.get_fingerprint.return_value = "SHA256:abc"
    key = MagicMock()
    key.get_fingerprint.return_value = "SHA256:xyz"
    e = BadHostKeyException("host.example.com", key, expected_key)
    assert "SHA256:abc" in str(e)
    assert "SHA256:xyz" in str(e)


def test_bad_host_key_fingerprint_raises_fallback():
    expected_key = MagicMock()
    expected_key.get_fingerprint.side_effect = Exception("no fingerprint")
    expected_key.get_name.return_value = "ssh-rsa"
    key = MagicMock()
    key.get_fingerprint.side_effect = Exception("no fingerprint")
    key.get_name.return_value = "ssh-ed25519"
    e = BadHostKeyException("host.example.com", key, expected_key)
    assert "host.example.com" in str(e)


def test_timeout_exception():
    e = TimeoutException("timed out", timeout_value=30.0)
    assert e.timeout_value == 30.0
    assert "timed out" in str(e)


def test_incompatible_peer():
    e = IncompatiblePeer("incompatible peer", peer_version="SSH-1.99")
    assert e.peer_version == "SSH-1.99"
    assert "incompatible peer" in str(e)
