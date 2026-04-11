import pytest
from spindlex.exceptions import ProtocolException
from spindlex.protocol.constants import *
from spindlex.protocol.messages import (
    ChannelCloseMessage,
    ChannelDataMessage,
    ChannelEOFMessage,
    ChannelExtendedDataMessage,
    ChannelFailureMessage,
    ChannelOpenConfirmationMessage,
    ChannelOpenFailureMessage,
    ChannelOpenMessage,
    ChannelRequestMessage,
    ChannelSuccessMessage,
    ChannelWindowAdjustMessage,
    DebugMessage,
    DisconnectMessage,
    GlobalRequestMessage,
    IgnoreMessage,
    KexDHInitMessage,
    KexDHReplyMessage,
    KexInitMessage,
    Message,
    RequestFailureMessage,
    RequestSuccessMessage,
    UnimplementedMessage,
    UserAuthBannerMessage,
    UserAuthPKOKMessage,
    UserAuthRequestMessage,
)


def test_disconnect_message():
    msg = DisconnectMessage(SSH_DISCONNECT_BY_APPLICATION, "Goodbye", "en")
    data = msg.pack()
    msg2 = DisconnectMessage.unpack(data)
    assert msg2.reason_code == SSH_DISCONNECT_BY_APPLICATION
    assert msg2.description == "Goodbye"
    assert msg2.language == "en"


def test_ignore_message():
    msg = IgnoreMessage(b"some data")
    data = msg.pack()
    msg2 = IgnoreMessage.unpack(data)
    assert msg2.data == b"some data"


def test_unimplemented_message():
    msg = UnimplementedMessage(123)
    data = msg.pack()
    msg2 = UnimplementedMessage.unpack(data)
    assert msg2.sequence_number == 123


def test_debug_message():
    msg = DebugMessage(True, "debug info", "en")
    data = msg.pack()
    msg2 = DebugMessage.unpack(data)
    assert msg2.always_display is True
    assert msg2.message == "debug info"
    assert msg2.language == "en"


def test_kexdh_init_message():
    msg = KexDHInitMessage(e=123456789)
    data = msg.pack()
    msg2 = KexDHInitMessage.unpack(data)
    assert msg2.e == 123456789


def test_kexdh_reply_message():
    msg = KexDHReplyMessage(b"hostkey", 987654321, b"signature")
    data = msg.pack()
    msg2 = KexDHReplyMessage.unpack(data)
    assert msg2.host_key == b"hostkey"
    assert msg2.f == 987654321
    assert msg2.signature == b"signature"


def test_userauth_banner_message():
    msg = UserAuthBannerMessage("Welcome", "en")
    data = msg.pack()
    msg2 = UserAuthBannerMessage.unpack(data)
    assert msg2.message == "Welcome"
    assert msg2.language == "en"


def test_userauth_pkok_message():
    msg = UserAuthPKOKMessage("ssh-rsa", b"keyblob")
    data = msg.pack()
    msg2 = UserAuthPKOKMessage.unpack(data)
    assert msg2.algorithm == "ssh-rsa"
    assert msg2.public_key == b"keyblob"


def test_global_request_message():
    msg = GlobalRequestMessage("tcpip-forward", True, b"extra")
    data = msg.pack()
    msg2 = GlobalRequestMessage.unpack(data)
    assert msg2.request_name == "tcpip-forward"
    assert msg2.want_reply is True
    assert msg2.request_data == b"extra"


def test_request_success_message():
    msg = RequestSuccessMessage(b"response")
    data = msg.pack()
    msg2 = RequestSuccessMessage.unpack(data)
    assert msg2.response_data == b"response"


def test_request_failure_message():
    msg = RequestFailureMessage()
    data = msg.pack()
    msg2 = RequestFailureMessage.unpack(data)
    assert msg2.msg_type == MSG_REQUEST_FAILURE


def test_channel_open_message():
    msg = ChannelOpenMessage("session", 1, 1024, 512, b"extra")
    msg.validate()
    data = msg.pack()
    msg2 = ChannelOpenMessage.unpack(data)
    assert msg2.channel_type == "session"
    assert msg2.sender_channel == 1
    assert msg2.initial_window_size == 1024
    assert msg2.maximum_packet_size == 512
    assert msg2.type_specific_data == b"extra"


def test_channel_open_confirmation_message():
    msg = ChannelOpenConfirmationMessage(1, 2, 1024, 512, b"extra")
    data = msg.pack()
    msg2 = ChannelOpenConfirmationMessage.unpack(data)
    assert msg2.recipient_channel == 1
    assert msg2.sender_channel == 2
    assert msg2.initial_window_size == 1024
    assert msg2.maximum_packet_size == 512
    assert msg2.type_specific_data == b"extra"


def test_channel_open_failure_message():
    msg = ChannelOpenFailureMessage(
        1, SSH_OPEN_ADMINISTRATIVELY_PROHIBITED, "Denied", "en"
    )
    data = msg.pack()
    msg2 = ChannelOpenFailureMessage.unpack(data)
    assert msg2.recipient_channel == 1
    assert msg2.reason_code == SSH_OPEN_ADMINISTRATIVELY_PROHIBITED
    assert msg2.description == "Denied"
    assert msg2.language == "en"


def test_channel_window_adjust_message():
    msg = ChannelWindowAdjustMessage(1, 1024)
    data = msg.pack()
    msg2 = ChannelWindowAdjustMessage.unpack(data)
    assert msg2.recipient_channel == 1
    assert msg2.bytes_to_add == 1024


def test_channel_data_message():
    msg = ChannelDataMessage(1, b"hello")
    data = msg.pack()
    msg2 = ChannelDataMessage.unpack(data)
    assert msg2.recipient_channel == 1
    assert msg2.data == b"hello"


def test_channel_extended_data_message():
    msg = ChannelExtendedDataMessage(1, SSH_EXTENDED_DATA_STDERR, b"error")
    data = msg.pack()
    msg2 = ChannelExtendedDataMessage.unpack(data)
    assert msg2.recipient_channel == 1
    assert msg2.data_type == SSH_EXTENDED_DATA_STDERR
    assert msg2.data == b"error"


def test_channel_eof_message():
    msg = ChannelEOFMessage(1)
    data = msg.pack()
    msg2 = ChannelEOFMessage.unpack(data)
    assert msg2.recipient_channel == 1


def test_channel_close_message():
    msg = ChannelCloseMessage(1)
    data = msg.pack()
    msg2 = ChannelCloseMessage.unpack(data)
    assert msg2.recipient_channel == 1


def test_channel_request_message():
    msg = ChannelRequestMessage(1, "shell", True, b"extra")
    data = msg.pack()
    msg2 = ChannelRequestMessage.unpack(data)
    assert msg2.recipient_channel == 1
    assert msg2.request_type == "shell"
    assert msg2.want_reply is True
    assert msg2.request_data == b"extra"


def test_channel_success_message():
    msg = ChannelSuccessMessage(1)
    data = msg.pack()
    msg2 = ChannelSuccessMessage.unpack(data)
    assert msg2.recipient_channel == 1


def test_channel_failure_message():
    msg = ChannelFailureMessage(1)
    data = msg.pack()
    msg2 = ChannelFailureMessage.unpack(data)
    assert msg2.recipient_channel == 1


def test_message_unpack_generic():
    data = bytes([MSG_IGNORE]) + b"\x00\x00\x00\x04test"
    msg = Message.unpack(data)
    assert msg.msg_type == MSG_IGNORE
    # Message.unpack for generic returns Message instance with _data
    assert msg._data == b"\x00\x00\x00\x04test"


def test_message_invalid_type():
    with pytest.raises(ProtocolException):
        Message(0)


def test_message_pack_failure():
    # Mocking write_byte to fail is hard, but we can trigger ProtocolException
    # if we bypass the constructor validation and set an invalid type.
    msg = Message(MSG_IGNORE)
    msg.msg_type = "invalid"  # type: ignore
    with pytest.raises(ProtocolException):
        msg.pack()


def test_message_unpack_too_short():
    with pytest.raises(ProtocolException):
        Message.unpack(b"")


def test_message_str_repr():
    msg = Message(MSG_IGNORE)
    assert "Message" in str(msg)
    assert "Message" in repr(msg)


def test_kexinit_validation():
    msg = KexInitMessage(
        cookie=b"0" * 16,
        kex_algorithms=["diffie-hellman-group14-sha1"],
        server_host_key_algorithms=["ssh-rsa"],
        encryption_algorithms_client_to_server=["aes128-ctr"],
        encryption_algorithms_server_to_client=["aes128-ctr"],
        mac_algorithms_client_to_server=["hmac-sha1"],
        mac_algorithms_server_to_client=["hmac-sha1"],
        compression_algorithms_client_to_server=["none"],
        compression_algorithms_server_to_client=["none"],
    )
    msg.validate()

    msg.kex_algorithms = []
    with pytest.raises(ProtocolException):
        msg.validate()


def test_userauth_request_validation():
    msg = UserAuthRequestMessage("user", SERVICE_CONNECTION, AUTH_PASSWORD, b"pass")
    msg.validate()

    msg.username = ""
    with pytest.raises(ProtocolException):
        msg.validate()


def test_channel_open_validation():
    msg = ChannelOpenMessage("session", 1, 1024, 512)
    msg.validate()

    msg.initial_window_size = 0
    with pytest.raises(ProtocolException):
        msg.validate()
