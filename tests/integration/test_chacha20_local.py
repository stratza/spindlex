import os
import socket
import tempfile
import threading
import time

import pytest

from spindlex import SSHClient, SSHServer
from spindlex.crypto.ciphers import CipherSuite
from spindlex.crypto.pkey import RSAKey
from spindlex.hostkeys.policy import AutoAddPolicy
from spindlex.hostkeys.storage import HostKeyStorage

pytestmark = pytest.mark.integration


class MockSSHServer(SSHServer):
    def check_auth_password(self, username, password):
        if username == "testuser" and password == "password123":
            return 0  # AUTH_SUCCESS
        return 1  # AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return 0  # OPEN_SUCCEEDED

    def check_auth_publickey(self, username, key):
        return 1  # AUTH_FAILED


def _pump_until_done(transport, timeout=10.0):
    """Drive the server transport's message loop until auth completes or timeout."""
    deadline = time.time() + timeout
    while transport.active and not transport.authenticated and time.time() < deadline:
        transport._pump()


def test_chacha20_local_integration():
    # 1. Setup Server
    server = MockSSHServer()
    server_key = RSAKey.generate(2048)
    server.set_server_key(server_key)

    # Force chacha20-poly1305 as the only cipher
    original_ciphers = CipherSuite.ENCRYPTION_ALGORITHMS
    CipherSuite.ENCRYPTION_ALGORITHMS = ["chacha20-poly1305@openssh.com"]

    # 2. Start Server in a thread
    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]

    server_transport_holder = []

    def run_server():
        conn, addr = lsock.accept()
        try:
            transport = server.start_server(conn)
            server_transport_holder.append(transport)
            _pump_until_done(transport)
            if transport.authenticated:
                # Keep pumping briefly to allow client to complete
                deadline = time.time() + 2
                while transport.active and time.time() < deadline:
                    transport._pump()
            transport.close()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            conn.close()
            lsock.close()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    tmp_known_hosts = tempfile.mktemp(suffix=".known_hosts")
    try:
        # 3. Connect Client
        with SSHClient() as client:
            client.set_host_key_storage(HostKeyStorage(tmp_known_hosts))
            client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
            client.connect(
                "127.0.0.1",
                port=port,
                username="testuser",
                password="password123",
                timeout=10,
            )

            assert client.get_transport().active
            assert client.get_transport().authenticated
            assert (
                client.get_transport()._cipher_out_active
                == "chacha20-poly1305@openssh.com"
            )
            assert (
                client.get_transport()._cipher_in_active
                == "chacha20-poly1305@openssh.com"
            )

    finally:
        CipherSuite.ENCRYPTION_ALGORITHMS = original_ciphers
        if os.path.exists(tmp_known_hosts):
            os.unlink(tmp_known_hosts)
        if server_thread.is_alive():
            try:
                lsock.close()
            except Exception:
                pass
            server_thread.join(timeout=3)


@pytest.mark.asyncio
async def test_chacha20_async_local_integration():
    from spindlex import AsyncSSHClient

    # 1. Setup Server (Sync server is fine for this test)
    server = MockSSHServer()
    server_key = RSAKey.generate(2048)
    server.set_server_key(server_key)

    # Force chacha20-poly1305 as the only cipher
    original_ciphers = CipherSuite.ENCRYPTION_ALGORITHMS
    CipherSuite.ENCRYPTION_ALGORITHMS = ["chacha20-poly1305@openssh.com"]

    lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]

    def run_server():
        conn, addr = lsock.accept()
        try:
            transport = server.start_server(conn)
            _pump_until_done(transport)
            if transport.authenticated:
                deadline = time.time() + 2
                while transport.active and time.time() < deadline:
                    transport._pump()
            transport.close()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            conn.close()
            lsock.close()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    tmp_known_hosts = tempfile.mktemp(suffix=".known_hosts")
    try:
        # 3. Connect Async Client
        async with AsyncSSHClient() as client:
            client.set_host_key_storage(HostKeyStorage(tmp_known_hosts))
            client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
            await client.connect(
                "127.0.0.1",
                port=port,
                username="testuser",
                password="password123",
                timeout=10,
            )

            assert client.connected
            assert client._transport.authenticated
            assert (
                client._transport._cipher_out_active == "chacha20-poly1305@openssh.com"
            )
            assert (
                client._transport._cipher_in_active == "chacha20-poly1305@openssh.com"
            )

    finally:
        CipherSuite.ENCRYPTION_ALGORITHMS = original_ciphers
        if os.path.exists(tmp_known_hosts):
            os.unlink(tmp_known_hosts)
        if server_thread.is_alive():
            try:
                lsock.close()
            except Exception:
                pass
            server_thread.join(timeout=3)
