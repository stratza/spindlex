import socket
import threading
import time

import pytest

from spindlex import SSHClient, SSHServer
from spindlex.crypto.ciphers import CipherSuite
from spindlex.crypto.pkey import RSAKey
from spindlex.hostkeys.policy import AutoAddPolicy
from spindlex.hostkeys.storage import HostKeyStorage


class MockSSHServer(SSHServer):
    def check_auth_password(self, username, password):
        if username == "testuser" and password == "password123":
            return 0  # AUTH_SUCCESS
        return 1  # AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return 0  # OPEN_SUCCEEDED

    def check_auth_publickey(self, username, key):
        return 1  # AUTH_FAILED


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

    def run_server():
        conn, addr = lsock.accept()
        try:
            transport = server.start_server(conn)
            # Wait for authentication
            while not transport.authenticated and transport.active:
                time.sleep(0.1)

            if transport.authenticated:
                # Wait a bit then close
                time.sleep(1)
            transport.close()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            conn.close()
            lsock.close()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    try:
        # 3. Connect Client
        with SSHClient() as client:
            client.set_host_key_storage(HostKeyStorage("/dev/null"))
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
        if server_thread.is_alive():
            try:
                lsock.close()
            except Exception:
                pass
            server_thread.join(timeout=2)


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
            while not transport.authenticated and transport.active:
                time.sleep(0.1)
            time.sleep(1)
            transport.close()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            conn.close()
            lsock.close()

    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()

    try:
        # 3. Connect Async Client
        async with AsyncSSHClient() as client:
            client.set_host_key_storage(HostKeyStorage("/dev/null"))
            client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
            await client.connect(
                "127.0.0.1",
                port=port,
                username="testuser",
                password="password123",
                timeout=10,
            )

            assert client.is_active
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
        if server_thread.is_alive():
            try:
                lsock.close()
            except Exception:
                pass
            server_thread.join(timeout=2)
