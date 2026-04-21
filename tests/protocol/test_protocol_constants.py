import pytest
from spindlex.protocol.constants import (
    create_version_string,
    is_supported_version,
    parse_version_string,
    validate_message_type,
)


def test_parse_version_string():
    assert parse_version_string("SSH-2.0-OpenSSH_8.0") == ("2.0", "OpenSSH_8.0")
    assert parse_version_string("SSH-2.0") == ("2.0", "")
    assert parse_version_string("SSH-1.99-SomeClient") == ("1.99", "SomeClient")


def test_parse_version_string_invalid():
    with pytest.raises(ValueError, match="Invalid SSH version string: INVALID-2.0"):
        parse_version_string("INVALID-2.0")
    with pytest.raises(ValueError, match="Invalid SSH version string: SSH"):
        parse_version_string("SSH")


def test_is_supported_version():
    assert is_supported_version("2.0") is True
    assert is_supported_version("1.99") is False
    assert is_supported_version("1.5") is False


def test_create_version_string():
    ver = create_version_string("testapp", "1.2.3")
    assert ver == "SSH-2.0-testapp_1.2.3"


def test_validate_message_type():
    assert validate_message_type(1) is True  # MSG_DISCONNECT
    assert validate_message_type(20) is True  # MSG_KEXINIT
    assert validate_message_type(94) is True  # MSG_CHANNEL_DATA
    assert validate_message_type(255) is True  # Local extension
    assert validate_message_type(0) is False
    assert validate_message_type(256) is False
