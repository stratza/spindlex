
from spindlex.exceptions import (
    AuthenticationException,
    BadHostKeyException,
    CryptoException,
    ProtocolException,
    SFTPError,
    SSHException,
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
