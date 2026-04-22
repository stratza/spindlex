import socket

import pytest

from spindlex.transport.transport import Transport

pytestmark = pytest.mark.real_server


def test_transport_real_connection(ssh_server):
    host, port, user, password = ssh_server
    sock = socket.create_connection((host, port))
    t = Transport(sock)
    try:
        t.start_client()
        assert t.active
        # Authenticate
        t.auth_password(user, password)
        assert t.authenticated
    finally:
        t.close()


def test_transport_open_channel(ssh_server):
    host, port, user, password = ssh_server
    # Use helper from Transport
    sock = socket.create_connection((host, port))
    t = Transport(sock)
    try:
        t.start_client()
        t.auth_password(user, password)
        chan = t.open_channel("session")
        assert chan is not None
        assert not chan.closed
        chan.close()
    finally:
        t.close()


def test_transport_is_active_property(ssh_client):
    t = ssh_client.get_transport()
    assert t.active
    ssh_client.close()
    assert not t.active
