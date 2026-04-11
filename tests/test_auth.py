from unittest.mock import MagicMock

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from spindlex.auth.password import PasswordAuth
from spindlex.auth.publickey import PublicKeyAuth
from spindlex.crypto.pkey import RSAKey


def test_password_auth():
    transport = MagicMock()
    auth = PasswordAuth(transport)
    # Note: PasswordAuth doesn't have a get_method_data or get_method_name method
    # It has an authenticate method that sends a message.
    # We can test that it calls _send_message on transport.

    auth.authenticate("alice", "secret123")
    assert transport._send_message.called
    msg = transport._send_message.call_args[0][0]
    assert msg.username == "alice"
    assert msg.method == "password"


def test_publickey_auth():
    transport = MagicMock()
    key = RSAKey()
    private_key = rsa.generate_private_key(65537, 2048, default_backend())
    key._key = private_key

    auth = PublicKeyAuth(transport)
    # PublicKeyAuth has authenticate method
    auth.authenticate("alice", key)
    assert transport._send_message.called
    msg = transport._send_message.call_args[0][0]
    assert msg.username == "alice"
    assert msg.method == "publickey"
