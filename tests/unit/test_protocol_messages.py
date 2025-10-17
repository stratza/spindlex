"""
Tests for SSH protocol message classes.
"""

import pytest

from ssh_library.exceptions import ProtocolException
from ssh_library.protocol.constants import (
    KEX_COOKIE_SIZE,
    MSG_CHANNEL_CLOSE,
    MSG_CHANNEL_DATA,
    MSG_CHANNEL_OPEN,
    MSG_CHANNEL_OPEN_CONFIRMATION,
    MSG_CHANNEL_OPEN_FAILURE,
    MSG_DISCONNECT,
    MSG_IGNORE,
    MSG_KEXINIT,
    MSG_SERVICE_ACCEPT,
    MSG_SERVICE_REQUEST,
    MSG_USERAUTH_FAILURE,
    MSG_USERAUTH_REQUEST,
    MSG_USERAUTH_SUCCESS,
    SSH_DISCONNECT_PROTOCOL_ERROR,
    SSH_OPEN_CONNECT_FAILED,
)
from ssh_library.protocol.messages import (
    ChannelCloseMessage,
    ChannelDataMessage,
    ChannelOpenConfirmationMessage,
    ChannelOpenFailureMessage,
    ChannelOpenMessage,
    DisconnectMessage,
    KexInitMessage,
    Message,
    ServiceAcceptMessage,
    ServiceRequestMessage,
    UserAuthFailureMessage,
    UserAuthRequestMessage,
    UserAuthSuccessMessage,
)


class TestBaseMessage:
    """Test base Message class functionality."""

    def test_message_creation(self):
        """Test creating a basic message."""
        msg = Message(MSG_DISCONNECT)
        assert msg.msg_type == MSG_DISCONNECT
        assert len(msg._data) == 0

    def test_message_invalid_type(self):
        """Test creating message with invalid type."""
        with pytest.raises(ProtocolException, match="Invalid message type"):
            Message(999)

    def test_message_pack_basic(self):
        """Test packing a basic message."""
        msg = Message(MSG_DISCONNECT)
        msg.add_byte(0x42)

        packed = msg.pack()
        assert packed[0] == MSG_DISCONNECT
        assert packed[1] == 0x42

    def test_message_unpack_generic(self):
        """Test unpacking a generic message."""
        # Use a message type that doesn't have a specific class
        data = bytes(
            [MSG_IGNORE, 0x42, 0x43]
        )  # MSG_IGNORE doesn't have a specific class
        msg = Message.unpack(data)

        assert msg.msg_type == MSG_IGNORE
        assert bytes(msg._data) == b"\x42\x43"

    def test_message_unpack_empty(self):
        """Test unpacking empty message data."""
        with pytest.raises(ProtocolException, match="Message data too short"):
            Message.unpack(b"")

    def test_message_add_methods(self):
        """Test message data addition methods."""
        msg = Message(MSG_DISCONNECT)

        msg.add_byte(0x42)
        msg.add_boolean(True)
        msg.add_boolean(False)
        msg.add_uint32(0x12345678)
        msg.add_uint64(0x123456789ABCDEF0)
        msg.add_string("hello")
        msg.add_mpint(0x1234)

        packed = msg.pack()
        assert packed[0] == MSG_DISCONNECT
        # Verify the data was added (detailed verification in utils tests)
        assert len(packed) > 1


class TestDisconnectMessage:
    """Test DisconnectMessage class."""

    def test_disconnect_message_creation(self):
        """Test creating disconnect message."""
        msg = DisconnectMessage(SSH_DISCONNECT_PROTOCOL_ERROR, "Test error", "en-US")

        assert msg.msg_type == MSG_DISCONNECT
        assert msg.reason_code == SSH_DISCONNECT_PROTOCOL_ERROR
        assert msg.description == "Test error"
        assert msg.language == "en-US"

    def test_disconnect_message_pack_unpack(self):
        """Test disconnect message serialization round-trip."""
        original = DisconnectMessage(
            SSH_DISCONNECT_PROTOCOL_ERROR, "Test error", "en-US"
        )
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, DisconnectMessage)
        assert unpacked.reason_code == SSH_DISCONNECT_PROTOCOL_ERROR
        assert unpacked.description == "Test error"
        assert unpacked.language == "en-US"

    def test_disconnect_message_minimal(self):
        """Test disconnect message with minimal data."""
        msg = DisconnectMessage(SSH_DISCONNECT_PROTOCOL_ERROR)

        assert msg.reason_code == SSH_DISCONNECT_PROTOCOL_ERROR
        assert msg.description == ""
        assert msg.language == ""


class TestServiceMessages:
    """Test service request/accept messages."""

    def test_service_request_message(self):
        """Test service request message."""
        msg = ServiceRequestMessage("ssh-userauth")

        assert msg.msg_type == MSG_SERVICE_REQUEST
        assert msg.service_name == "ssh-userauth"

    def test_service_request_pack_unpack(self):
        """Test service request message round-trip."""
        original = ServiceRequestMessage("ssh-connection")
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, ServiceRequestMessage)
        assert unpacked.service_name == "ssh-connection"

    def test_service_accept_message(self):
        """Test service accept message."""
        msg = ServiceAcceptMessage("ssh-userauth")

        assert msg.msg_type == MSG_SERVICE_ACCEPT
        assert msg.service_name == "ssh-userauth"

    def test_service_accept_pack_unpack(self):
        """Test service accept message round-trip."""
        original = ServiceAcceptMessage("ssh-connection")
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, ServiceAcceptMessage)
        assert unpacked.service_name == "ssh-connection"


class TestKexInitMessage:
    """Test KEX init message."""

    def test_kexinit_message_creation(self):
        """Test creating KEX init message."""
        cookie = b"\x00" * KEX_COOKIE_SIZE
        kex_algs = ["curve25519-sha256"]
        host_key_algs = ["ssh-ed25519"]
        enc_algs = ["chacha20-poly1305@openssh.com"]
        mac_algs = ["hmac-sha2-256"]
        comp_algs = ["none"]

        msg = KexInitMessage(
            cookie=cookie,
            kex_algorithms=kex_algs,
            server_host_key_algorithms=host_key_algs,
            encryption_algorithms_client_to_server=enc_algs,
            encryption_algorithms_server_to_client=enc_algs,
            mac_algorithms_client_to_server=mac_algs,
            mac_algorithms_server_to_client=mac_algs,
            compression_algorithms_client_to_server=comp_algs,
            compression_algorithms_server_to_client=comp_algs,
        )

        assert msg.msg_type == MSG_KEXINIT
        assert msg.cookie == cookie
        assert msg.kex_algorithms == kex_algs
        assert msg.server_host_key_algorithms == host_key_algs

    def test_kexinit_invalid_cookie(self):
        """Test KEX init with invalid cookie size."""
        with pytest.raises(ProtocolException, match="Invalid cookie size"):
            KexInitMessage(
                cookie=b"\x00" * 10,  # Wrong size
                kex_algorithms=[],
                server_host_key_algorithms=[],
                encryption_algorithms_client_to_server=[],
                encryption_algorithms_server_to_client=[],
                mac_algorithms_client_to_server=[],
                mac_algorithms_server_to_client=[],
                compression_algorithms_client_to_server=[],
                compression_algorithms_server_to_client=[],
            )

    def test_kexinit_pack_unpack(self):
        """Test KEX init message round-trip."""
        cookie = b"\x42" * KEX_COOKIE_SIZE
        kex_algs = ["curve25519-sha256", "ecdh-sha2-nistp256"]
        host_key_algs = ["ssh-ed25519", "ecdsa-sha2-nistp256"]
        enc_algs = ["chacha20-poly1305@openssh.com"]
        mac_algs = ["hmac-sha2-256"]
        comp_algs = ["none"]

        original = KexInitMessage(
            cookie=cookie,
            kex_algorithms=kex_algs,
            server_host_key_algorithms=host_key_algs,
            encryption_algorithms_client_to_server=enc_algs,
            encryption_algorithms_server_to_client=enc_algs,
            mac_algorithms_client_to_server=mac_algs,
            mac_algorithms_server_to_client=mac_algs,
            compression_algorithms_client_to_server=comp_algs,
            compression_algorithms_server_to_client=comp_algs,
            first_kex_packet_follows=True,
        )

        packed = original.pack()
        unpacked = Message.unpack(packed)

        assert isinstance(unpacked, KexInitMessage)
        assert unpacked.cookie == cookie
        assert unpacked.kex_algorithms == kex_algs
        assert unpacked.server_host_key_algorithms == host_key_algs
        assert unpacked.first_kex_packet_follows is True


class TestUserAuthMessages:
    """Test user authentication messages."""

    def test_userauth_request_message(self):
        """Test user auth request message."""
        msg = UserAuthRequestMessage(
            "testuser", "ssh-connection", "password", b"secret"
        )

        assert msg.msg_type == MSG_USERAUTH_REQUEST
        assert msg.username == "testuser"
        assert msg.service == "ssh-connection"
        assert msg.method == "password"
        assert msg.method_data == b"secret"

    def test_userauth_request_pack_unpack(self):
        """Test user auth request message round-trip."""
        original = UserAuthRequestMessage(
            "testuser", "ssh-connection", "publickey", b"keydata"
        )
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, UserAuthRequestMessage)
        assert unpacked.username == "testuser"
        assert unpacked.service == "ssh-connection"
        assert unpacked.method == "publickey"
        assert unpacked.method_data == b"keydata"

    def test_userauth_failure_message(self):
        """Test user auth failure message."""
        msg = UserAuthFailureMessage(["password", "publickey"], True)

        assert msg.msg_type == MSG_USERAUTH_FAILURE
        assert msg.authentications == ["password", "publickey"]
        assert msg.partial_success is True

    def test_userauth_failure_pack_unpack(self):
        """Test user auth failure message round-trip."""
        original = UserAuthFailureMessage(["password", "publickey"], False)
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, UserAuthFailureMessage)
        assert unpacked.authentications == ["password", "publickey"]
        assert unpacked.partial_success is False

    def test_userauth_success_message(self):
        """Test user auth success message."""
        msg = UserAuthSuccessMessage()

        assert msg.msg_type == MSG_USERAUTH_SUCCESS

    def test_userauth_success_pack_unpack(self):
        """Test user auth success message round-trip."""
        original = UserAuthSuccessMessage()
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, UserAuthSuccessMessage)


class TestChannelMessages:
    """Test channel-related messages."""

    def test_channel_open_message(self):
        """Test channel open message."""
        msg = ChannelOpenMessage("session", 1, 32768, 16384, b"extra")

        assert msg.msg_type == MSG_CHANNEL_OPEN
        assert msg.channel_type == "session"
        assert msg.sender_channel == 1
        assert msg.initial_window_size == 32768
        assert msg.maximum_packet_size == 16384
        assert msg.type_specific_data == b"extra"

    def test_channel_open_pack_unpack(self):
        """Test channel open message round-trip."""
        original = ChannelOpenMessage("direct-tcpip", 2, 65536, 32768)
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, ChannelOpenMessage)
        assert unpacked.channel_type == "direct-tcpip"
        assert unpacked.sender_channel == 2
        assert unpacked.initial_window_size == 65536
        assert unpacked.maximum_packet_size == 32768
        assert unpacked.type_specific_data == b""

    def test_channel_open_confirmation_message(self):
        """Test channel open confirmation message."""
        msg = ChannelOpenConfirmationMessage(1, 2, 32768, 16384, b"response")

        assert msg.msg_type == MSG_CHANNEL_OPEN_CONFIRMATION
        assert msg.recipient_channel == 1
        assert msg.sender_channel == 2
        assert msg.initial_window_size == 32768
        assert msg.maximum_packet_size == 16384
        assert msg.type_specific_data == b"response"

    def test_channel_open_failure_message(self):
        """Test channel open failure message."""
        msg = ChannelOpenFailureMessage(
            1, SSH_OPEN_CONNECT_FAILED, "Connection failed", "en-US"
        )

        assert msg.msg_type == MSG_CHANNEL_OPEN_FAILURE
        assert msg.recipient_channel == 1
        assert msg.reason_code == SSH_OPEN_CONNECT_FAILED
        assert msg.description == "Connection failed"
        assert msg.language == "en-US"

    def test_channel_data_message(self):
        """Test channel data message."""
        msg = ChannelDataMessage(1, b"Hello, World!")

        assert msg.msg_type == MSG_CHANNEL_DATA
        assert msg.recipient_channel == 1
        assert msg.data == b"Hello, World!"

    def test_channel_data_pack_unpack(self):
        """Test channel data message round-trip."""
        original = ChannelDataMessage(5, b"Test data\x00\xff")
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, ChannelDataMessage)
        assert unpacked.recipient_channel == 5
        assert unpacked.data == b"Test data\x00\xff"

    def test_channel_close_message(self):
        """Test channel close message."""
        msg = ChannelCloseMessage(1)

        assert msg.msg_type == MSG_CHANNEL_CLOSE
        assert msg.recipient_channel == 1

    def test_channel_close_pack_unpack(self):
        """Test channel close message round-trip."""
        original = ChannelCloseMessage(10)
        packed = original.pack()

        unpacked = Message.unpack(packed)
        assert isinstance(unpacked, ChannelCloseMessage)
        assert unpacked.recipient_channel == 10


class TestMessageValidation:
    """Test message validation edge cases."""

    def test_message_string_representation(self):
        """Test message string representations."""
        msg = DisconnectMessage(SSH_DISCONNECT_PROTOCOL_ERROR, "Test")

        str_repr = str(msg)
        assert "DisconnectMessage" in str_repr
        assert "type=" in str_repr

        repr_str = repr(msg)
        assert "DisconnectMessage" in repr_str
        assert "msg_type=" in repr_str

    def test_message_validation(self):
        """Test message validation."""
        msg = Message(MSG_DISCONNECT)
        assert msg.validate() is True

        # Test with invalid type (should not happen in normal usage)
        # Note: validate() only checks the message type, and invalid types
        # are caught during construction, so this test validates the base behavior
        assert msg.validate() is True
