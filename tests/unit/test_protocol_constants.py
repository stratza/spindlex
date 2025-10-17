"""
Tests for SSH protocol constants and utility functions.
"""

import pytest

from spindlex.protocol.constants import (
    CIPHER_CHACHA20_POLY1305,
    HOSTKEY_ED25519,
    KEX_CURVE25519_SHA256,
    MSG_DISCONNECT,
    MSG_KEXINIT,
    MSG_USERAUTH_REQUEST,
    SSH_PROTOCOL_VERSION_2,
    SUPPORTED_PROTOCOL_VERSIONS,
    create_version_string,
    get_message_name,
    is_supported_version,
    parse_version_string,
    validate_message_type,
)


class TestProtocolConstants:
    """Test protocol constants definitions."""

    def test_message_types_defined(self):
        """Test that essential message types are defined."""
        assert MSG_DISCONNECT == 1
        assert MSG_KEXINIT == 20
        assert MSG_USERAUTH_REQUEST == 50

    def test_protocol_version_constants(self):
        """Test protocol version constants."""
        assert SSH_PROTOCOL_VERSION_2 == "2.0"
        assert SSH_PROTOCOL_VERSION_2 in SUPPORTED_PROTOCOL_VERSIONS

    def test_algorithm_constants(self):
        """Test algorithm name constants."""
        assert KEX_CURVE25519_SHA256 == "curve25519-sha256"
        assert HOSTKEY_ED25519 == "ssh-ed25519"
        assert CIPHER_CHACHA20_POLY1305 == "chacha20-poly1305@openssh.com"


class TestVersionParsing:
    """Test SSH version string parsing functions."""

    def test_parse_valid_version_string(self):
        """Test parsing valid SSH version strings."""
        protocol, software = parse_version_string("SSH-2.0-OpenSSH_8.0")
        assert protocol == "2.0"
        assert software == "OpenSSH_8.0"

        protocol, software = parse_version_string("SSH-1.99-spindlex_1.0")
        assert protocol == "1.99"
        assert software == "spindlex_1.0"

    def test_parse_version_string_no_software(self):
        """Test parsing version string without software version."""
        protocol, software = parse_version_string("SSH-2.0")
        assert protocol == "2.0"
        assert software == ""

    def test_parse_invalid_version_string(self):
        """Test parsing invalid version strings."""
        with pytest.raises(ValueError, match="Invalid SSH version string"):
            parse_version_string("HTTP/1.1")

        with pytest.raises(ValueError, match="Invalid SSH version string"):
            parse_version_string("SSH")

    def test_is_supported_version(self):
        """Test version support checking."""
        assert is_supported_version("2.0") is True
        assert is_supported_version("1.99") is False
        assert is_supported_version("3.0") is False

    def test_create_version_string(self):
        """Test creating version strings."""
        version = create_version_string()
        assert version == "SSH-2.0-spindlex_0.1.0"

        version = create_version_string("MySSH", "2.1")
        assert version == "SSH-2.0-MySSH_2.1"


class TestMessageValidation:
    """Test message type validation functions."""

    def test_validate_message_type_valid(self):
        """Test validation of valid message types."""
        # Transport layer generic (1-19)
        assert validate_message_type(1) is True
        assert validate_message_type(19) is True

        # Algorithm negotiation (20-29)
        assert validate_message_type(20) is True
        assert validate_message_type(29) is True

        # Key exchange method specific (30-41)
        assert validate_message_type(30) is True
        assert validate_message_type(41) is True

        # User authentication generic (50-59)
        assert validate_message_type(50) is True
        assert validate_message_type(59) is True

        # Connection protocol (80-127)
        assert validate_message_type(80) is True
        assert validate_message_type(127) is True

    def test_validate_message_type_invalid(self):
        """Test validation of invalid message types."""
        assert validate_message_type(0) is False
        assert validate_message_type(42) is False
        assert validate_message_type(256) is False

    def test_get_message_name(self):
        """Test getting message names."""
        assert get_message_name(MSG_DISCONNECT) == "MSG_DISCONNECT"
        assert get_message_name(MSG_KEXINIT) == "MSG_KEXINIT"
        assert get_message_name(999) == "UNKNOWN(999)"
