import socket

import pytest

from spindlex.transport.transport import Transport

pytestmark = pytest.mark.real_server


class TestTransportLive:
    """Consolidated transport tests using real server connections."""

    def test_recv_bytes_via_real_connection(self, ssh_server):
        host, port, _, _ = ssh_server
        sock = socket.create_connection((host, port), timeout=30)
        transport = Transport(sock)
        try:
            # The server should send a version string immediately
            # We can test _recv_bytes by reading the first 4 bytes "SSH-"
            data = transport._recv_bytes(4)
            assert data == b"SSH-"
        finally:
            transport.close()

    def test_version_exchange_live(self, ssh_server):
        host, port, _, _ = ssh_server
        sock = socket.create_connection((host, port), timeout=30)
        transport = Transport(sock)
        try:
            transport._recv_version()
            assert transport._remote_version.startswith("SSH-2.0")

            # Test sending our version
            transport._send_version()
        finally:
            transport.close()

    def test_global_request_live(self, ssh_client):
        # Testing a global request against a real server
        transport = ssh_client.get_transport()
        # Most servers reject random global requests, which is a good test of the failure path
        result = transport._send_global_request(
            "keepalive@openssh.com", want_reply=True
        )
        # result depends on server, but usually it's a valid boolean response (True or False)
        assert isinstance(result, bool)

    def test_rekey_trigger_live(self, ssh_client):
        transport = ssh_client.get_transport()
        # Trigger rekey by setting low limit
        transport.set_rekey_policy(bytes_limit=1024)
        # Send some data to trigger check
        ssh_client.exec_command("echo 123")
        # transport._check_rekey() is called internally during packet send/recv
        # We just verify it doesn't crash the session
        assert transport.active
