
from spindlex.protocol.constants import *
from spindlex.protocol.messages import (
    KexInitMessage,
    Message,
    NewKeysMessage,
    ServiceAcceptMessage,
    ServiceRequestMessage,
    UserAuthFailureMessage,
    UserAuthRequestMessage,
    UserAuthSuccessMessage,
)


def test_base_message():
    msg = Message(MSG_IGNORE)
    msg.add_string(b"hello")
    msg.add_uint32(1234)
    data = msg.pack()
    assert data[0] == MSG_IGNORE

    msg2 = Message.unpack(data)
    assert msg2.msg_type == MSG_IGNORE
    # Note: Message.unpack currently doesn't deserialize the data into fields,
    # it just keeps it in msg._data if it's a generic message.
    # Specialized messages have better unpack.


def test_kexinit_message():
    msg = KexInitMessage(
        cookie=b"0123456789abcdef",
        kex_algorithms=["curve25519-sha256"],
        server_host_key_algorithms=["ssh-ed25519"],
        encryption_algorithms_client_to_server=["aes256-ctr"],
        encryption_algorithms_server_to_client=["aes256-ctr"],
        mac_algorithms_client_to_server=["hmac-sha2-256"],
        mac_algorithms_server_to_client=["hmac-sha2-256"],
        compression_algorithms_client_to_server=["none"],
        compression_algorithms_server_to_client=["none"],
    )
    data = msg.pack()
    msg2 = KexInitMessage.unpack(data)
    assert msg2.kex_algorithms == ["curve25519-sha256"]
    assert msg2.cookie == b"0123456789abcdef"


def test_newkeys_message():
    msg = NewKeysMessage()
    data = msg.pack()
    assert data[0] == MSG_NEWKEYS
    msg2 = NewKeysMessage.unpack(data)
    assert msg2.msg_type == MSG_NEWKEYS


def test_service_messages():
    req = ServiceRequestMessage(service_name=SERVICE_USERAUTH)
    data = req.pack()
    req2 = ServiceRequestMessage.unpack(data)
    assert req2.service_name == SERVICE_USERAUTH

    acc = ServiceAcceptMessage(service_name=SERVICE_USERAUTH)
    data = acc.pack()
    acc2 = ServiceAcceptMessage.unpack(data)
    assert acc2.service_name == SERVICE_USERAUTH


def test_userauth_messages():
    req = UserAuthRequestMessage(
        username="alice",
        service=SERVICE_CONNECTION,
        method="password",
        method_data=b"secret",
    )
    data = req.pack()
    req2 = UserAuthRequestMessage.unpack(data)
    assert req2.username == "alice"
    assert req2.method == "password"

    succ = UserAuthSuccessMessage()
    assert succ.pack()[0] == MSG_USERAUTH_SUCCESS

    fail = UserAuthFailureMessage(
        authentications=["password", "publickey"], partial_success=False
    )
    data = fail.pack()
    fail2 = UserAuthFailureMessage.unpack(data)
    assert fail2.authentications == ["password", "publickey"]
    assert not fail2.partial_success
