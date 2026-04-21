import socket

import pytest
from spindlex.exceptions import AuthenticationException
from spindlex.transport.transport import Transport

pytestmark = pytest.mark.real_server


def test_auth_password_success(ssh_server):
    host, port, user, password = ssh_server
    sock = socket.create_connection((host, port))
    t = Transport(sock)
    try:
        t.start_client()
        res = t.auth_password(user, password)
        assert res is True
        assert t.authenticated
    finally:
        t.close()


def test_auth_password_failure(ssh_server):
    host, port, user, password = ssh_server
    sock = socket.create_connection((host, port))
    t = Transport(sock)
    try:
        t.start_client()
        # auth_password returns False on failure, doesn't always raise
        try:
            res = t.auth_password(user, "WRONG_PASSWORD_12345")
            assert res is False
        except AuthenticationException:
            pass
        assert not t.authenticated
    finally:
        t.close()


def test_auth_interactive_if_supported(ssh_server):
    host, port, user, password = ssh_server
    sock = socket.create_connection((host, port))
    t = Transport(sock)
    try:
        t.start_client()
        # Just check if we can call it. We don't assert success as it depends on server config.
        try:
            t.auth_interactive(
                user, lambda title, instructions, prompts: [password for _ in prompts]
            )
        except Exception:
            pass
    finally:
        t.close()
