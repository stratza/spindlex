"""
End-to-end regression tests: SpindleX client against SpindleX server over a
real loopback socket.

These cover behaviour that unit tests with mocked transports cannot see:
which thread reads the socket, the order messages go out in, and what the
peer actually receives.
"""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from spindlex.client.async_ssh_client import AsyncSSHClient
from spindlex.client.ssh_client import SSHClient
from spindlex.crypto.pkey import Ed25519Key, RSAKey
from spindlex.exceptions import AuthenticationException
from spindlex.hostkeys.policy import AutoAddPolicy
from spindlex.hostkeys.storage import HostKeyStorage
from spindlex.protocol.constants import AUTH_FAILED, AUTH_PARTIAL, AUTH_SUCCESSFUL
from spindlex.server.sftp_server import SFTPServer
from spindlex.server.ssh_server import SSHServer, SSHServerManager

CLIENT_KEY = Ed25519Key.generate()


class LoopbackServer(SSHServer):
    """Accepts user "user" by password "secret" or CLIENT_KEY."""

    def __init__(self, sftp_root: str | None = None) -> None:
        super().__init__()
        self.sftp_root = sftp_root
        self.server_channels: list = []
        self.stdin_bytes: list[int] = []

    def check_auth_password(self, username: str, password: str) -> int:
        if username == "user" and password == "secret":
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        if username == "user" and key == CLIENT_KEY:
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def get_allowed_auths(self, username: str) -> list[str]:
        return ["password", "publickey"]

    def check_channel_request(self, kind: str, chanid: int) -> int:
        return 0

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        self.server_channels.append(channel)
        if command == b"count-stdin":
            # Read stdin on a handler thread while the connection loop keeps
            # reading the socket.
            def run() -> None:
                total = 0
                while True:
                    data = channel.recv(65536)
                    if not data:
                        break
                    total += len(data)
                self.stdin_bytes.append(total)
                channel.send(f"{total}\n".encode())
                channel.send_exit_status(0)
                channel.send_eof()
                channel.close()

            threading.Thread(target=run, daemon=True).start()
            return True
        if command == b"hold":
            return True  # leave the channel open
        # Finish inside the callback: the reply to the exec request must still
        # reach the client before our CLOSE.
        channel.send(b"ran:" + command + b"\n")
        channel.send_exit_status(0)
        channel.send_eof()
        channel.close()
        return True

    def check_channel_subsystem_request(self, channel, name: str) -> bool:
        if name == "sftp" and self.sftp_root:
            SFTPServer(channel, self.sftp_root)
            return True
        return False


def _start(server: SSHServer, host_key=None):
    manager = SSHServerManager(
        server, host_key or Ed25519Key.generate(), bind_address="127.0.0.1", port=0
    )
    manager.start_server()
    return manager, manager._server_socket.getsockname()[1]


@pytest.fixture
def server(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_bytes(b"hello" * 2000)
    iface = LoopbackServer(sftp_root=str(root))
    manager, port = _start(iface)
    yield iface, port, root
    manager.stop_server()


def _client(tmp_path, port: int, **kwargs) -> SSHClient:
    client = SSHClient()
    client.set_host_key_storage(HostKeyStorage(str(tmp_path / "known_hosts")))
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    kwargs.setdefault("password", "secret")
    client.connect("127.0.0.1", port=port, username="user", **kwargs)
    return client


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def test_exec_reply_precedes_close_and_close_reaches_server(server, tmp_path):
    iface, port, _ = server
    client = _client(tmp_path, port)
    try:
        _, stdout, _ = client.exec_command("hello")
        assert stdout.read() == b"ran:hello\n"
        assert stdout.channel.recv_exit_status() == 0

        # A client-side close must reach the server.
        _, stdout, _ = client.exec_command("hold")
        assert _wait_for(lambda: len(iface.server_channels) == 2)
        stdout.channel.close()
        assert _wait_for(lambda: iface.server_channels[1].closed)
    finally:
        client.close()


def test_server_handler_thread_receives_stdin(server, tmp_path):
    iface, port, _ = server
    client = _client(tmp_path, port)
    try:
        stdin, stdout, _ = client.exec_command("count-stdin")
        stdin.write(b"x" * 200_000)  # several full-size channel packets
        stdout.channel.send_eof()
        assert stdout.read() == b"200000\n"
        assert iface.stdin_bytes == [200_000]
    finally:
        client.close()


def test_sftp_against_spindlex_server(server, tmp_path):
    _, port, root = server
    client = _client(tmp_path, port)
    try:
        sftp = client.open_sftp()
        assert sftp.listdir("/") == ["a.txt"]
        local = tmp_path / "dl.txt"
        sftp.get("/a.txt", str(local))
        assert local.read_bytes() == b"hello" * 2000
        sftp.put(str(local), "/b.txt")
        assert (root / "b.txt").read_bytes() == b"hello" * 2000
        sftp.close()
    finally:
        client.close()


def test_publickey_auth_against_spindlex_server(server, tmp_path):
    _, port, _ = server
    client = _client(tmp_path, port, password=None, pkey=CLIENT_KEY)
    try:
        _, stdout, _ = client.exec_command("whoami")
        assert stdout.read() == b"ran:whoami\n"
    finally:
        client.close()


def test_client_initiated_rekey_against_spindlex_server(server, tmp_path):
    _, port, _ = server
    client = _client(tmp_path, port)
    try:
        transport = client.get_transport()
        assert transport is not None
        old_key = transport._encryption_key_c2s
        transport._rekey_bytes_limit = 2000

        for i in range(6):
            _, stdout, _ = client.exec_command("x" * 1000 + str(i))
            assert stdout.read().startswith(b"ran:")

        assert _wait_for(lambda: transport._encryption_key_c2s != old_key)
        assert _wait_for(lambda: not transport._kex_in_progress)
        _, stdout, _ = client.exec_command("after")
        assert stdout.read() == b"ran:after\n"
        assert transport.active
    finally:
        client.close()


def test_connect_timeout_does_not_limit_idle_reads(tmp_path):
    class SlowServer(LoopbackServer):
        def check_channel_exec_request(self, channel, command: bytes) -> bool:
            def later() -> None:
                time.sleep(1.5)
                channel.send(b"done\n")
                channel.send_exit_status(0)
                channel.send_eof()

            threading.Thread(target=later, daemon=True).start()
            return True

    manager, port = _start(SlowServer())
    try:
        client = _client(tmp_path, port, timeout=0.5)
        try:
            _, stdout, _ = client.exec_command("slow")
            assert stdout.read() == b"done\n"
        finally:
            client.close()
    finally:
        manager.stop_server()


def test_rsa_host_key_is_stable_across_connections(tmp_path):
    host_key = RSAKey.generate(bits=2048)
    manager, port = _start(LoopbackServer(), host_key=host_key)
    try:
        blobs = []
        for _ in range(2):
            client = _client(tmp_path, port)
            try:
                server_key = client.get_transport().get_server_host_key()
                blobs.append(server_key.get_public_key_bytes())
            finally:
                client.close()
        assert blobs[0] == blobs[1] == host_key.get_public_key_bytes()
        assert blobs[0][4:11] == b"ssh-rsa"
    finally:
        manager.stop_server()


# ---- async client ----


async def _async_client(tmp_path, port: int, password: str = "secret"):
    client = AsyncSSHClient()
    client.set_host_key_storage(HostKeyStorage(str(tmp_path / "known_hosts")))
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    await client.connect("127.0.0.1", port, username="user", password=password)
    return client


async def test_async_open_channel_while_another_channel_is_read(server, tmp_path):
    _, port, _ = server
    client = await _async_client(tmp_path, port)
    try:
        _, held, _ = await client.exec_command("hold")
        reader = asyncio.create_task(held.read())
        await asyncio.sleep(0.2)
        _, stdout, _ = await asyncio.wait_for(client.exec_command("quick"), 5)
        assert await asyncio.wait_for(stdout.read(), 5) == b"ran:quick\n"
        reader.cancel()
    finally:
        await client.close()


async def test_async_client_survives_server_global_request(tmp_path):
    iface = LoopbackServer()
    manager, port = _start(iface)
    try:
        client = await _async_client(tmp_path, port)
        try:
            server_transport = next(iter(manager._connections.values()))
            replies: list = []

            def keepalive() -> None:
                replies.append(
                    server_transport._send_global_request("keepalive@openssh.com", True)
                )

            sender = threading.Thread(target=keepalive, daemon=True)
            sender.start()
            _, stdout, _ = await client.exec_command("ping")
            assert await asyncio.wait_for(stdout.read(), 5) == b"ran:ping\n"
            await asyncio.to_thread(sender.join, 5)
            assert replies == [False]  # unknown request -> REQUEST_FAILURE
        finally:
            await client.close()
    finally:
        manager.stop_server()


async def test_async_client_can_reconnect_after_failed_auth(server, tmp_path):
    _, port, _ = server
    client = AsyncSSHClient()
    client.set_host_key_storage(HostKeyStorage(str(tmp_path / "known_hosts")))
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    with pytest.raises(AuthenticationException):
        await client.connect("127.0.0.1", port, username="user", password="wrong")
    assert not client.connected
    await client.connect("127.0.0.1", port, username="user", password="secret")
    try:
        assert client.connected
    finally:
        await client.close()


async def test_async_connect_timeout_covers_handshake():
    import socket

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    accepted: list = []
    threading.Thread(
        target=lambda: accepted.append(listener.accept()), daemon=True
    ).start()
    client = AsyncSSHClient()
    started = time.monotonic()
    try:
        with pytest.raises(Exception, match="handshake"):
            await client.connect(
                "127.0.0.1", port, username="user", password="x", timeout=0.5
            )
        assert time.monotonic() - started < 5
    finally:
        for conn, _ in accepted:
            conn.close()
        listener.close()


def test_async_rekey_does_not_touch_asyncio_socket_timeout():
    # The sync key-exchange path runs in a worker thread for AsyncTransport and
    # must not call settimeout() on the asyncio-owned socket.
    from spindlex.transport.async_transport import AsyncTransport

    class NoTimeoutSocket:
        def gettimeout(self):
            raise AssertionError("gettimeout() called on asyncio socket")

        def settimeout(self, value):
            raise AssertionError("settimeout() called on asyncio socket")

        def fileno(self):
            return -1

    transport = AsyncTransport(NoTimeoutSocket())  # type: ignore[arg-type]
    transport._send_kexinit = lambda: None  # type: ignore[method-assign]
    transport._recv_kexinit = lambda: None  # type: ignore[method-assign]
    transport._kex.start_kex = lambda: None  # type: ignore[method-assign]
    transport._start_kex()
    assert not transport._kex_in_progress


# ---- server features wired up end to end ----


class FeatureServer(LoopbackServer):
    def __init__(self) -> None:
        super().__init__()
        self.closed_channels: list = []
        self.global_requests: list[str] = []
        self.partial_done = False

    def get_banner(self):
        return "Authorized use only\n"

    def get_allowed_auths(self, username: str) -> list[str]:
        return ["publickey", "password", "keyboard-interactive"]

    # two-factor for user "mfa": public key first, then password
    def check_auth_publickey(self, username: str, key) -> int:
        if username == "mfa" and key == CLIENT_KEY:
            self.partial_done = True
            return AUTH_PARTIAL
        return super().check_auth_publickey(username, key)

    def check_auth_password(self, username: str, password: str) -> int:
        if username == "mfa":
            return (
                AUTH_SUCCESSFUL
                if self.partial_done and password == "otp"
                else AUTH_FAILED
            )
        return super().check_auth_password(username, password)

    def get_keyboard_interactive_prompts(self, username: str, submethods: str):
        return ("Login", "Answer the question", [("Code: ", False)])

    def check_auth_keyboard_interactive_response(self, username, responses) -> int:
        return AUTH_SUCCESSFUL if responses == ["4242"] else AUTH_FAILED

    def check_global_request(self, kind: str, msg) -> bool:
        self.global_requests.append(kind)
        return kind == "spindlex-test@example.com"

    def on_channel_closed(self, channel) -> None:
        self.closed_channels.append(channel)

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        if command == b"stderr":
            channel.sendall(b"out\n")
            channel.sendall_stderr(b"err\n")
            channel.send_exit_status(2)
            channel.send_eof()
            channel.close()
            return True
        if command == b"cat":

            def run() -> None:
                data = b""
                while True:
                    chunk = channel.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                channel.sendall(data)
                channel.send_exit_status(0)
                channel.send_eof()
                channel.close()

            threading.Thread(target=run, daemon=True).start()
            return True
        return super().check_channel_exec_request(channel, command)


@pytest.fixture
def feature_server():
    iface = FeatureServer()
    manager, port = _start(iface)
    yield iface, port, manager
    manager.stop_server()


def test_keyboard_interactive_against_spindlex_server(feature_server, tmp_path):
    _, port, _ = feature_server
    seen = []

    def handler(title, instructions, prompts):
        seen.append((title, instructions, prompts))
        return ["4242"]

    client = SSHClient()
    client.set_host_key_storage(HostKeyStorage(str(tmp_path / "kh")))
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    client.connect(
        "127.0.0.1", port=port, username="user", keyboard_interactive_handler=handler
    )
    try:
        assert seen == [("Login", "Answer the question", [("Code: ", False)])]
        _, stdout, _ = client.exec_command("hi")
        assert stdout.read() == b"ran:hi\n"
    finally:
        client.close()


def test_partial_success_two_factor(feature_server, tmp_path):
    iface, port, _ = feature_server
    client = SSHClient()
    client.set_host_key_storage(HostKeyStorage(str(tmp_path / "kh")))
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    client.connect(
        "127.0.0.1", port=port, username="mfa", pkey=CLIENT_KEY, password="otp"
    )
    try:
        assert iface.partial_done
        assert client.is_connected()
    finally:
        client.close()


def test_server_stderr_global_request_and_close_callback(feature_server, tmp_path):
    iface, port, manager = feature_server
    client = _client(tmp_path, port)
    try:
        _, stdout, stderr = client.exec_command("stderr")
        assert stdout.read() == b"out\n"
        assert stderr.read() == b"err\n"
        assert stdout.channel.recv_exit_status() == 2

        transport = client.get_transport()
        assert transport._send_global_request("spindlex-test@example.com", True)
        assert not transport._send_global_request("keepalive@openssh.com", True)
        assert iface.global_requests == [
            "spindlex-test@example.com",
            "keepalive@openssh.com",
        ]
        # The client answered the server's CLOSE while reading the replies
        # above; the server then reports the channel closed.
        assert _wait_for(lambda: len(iface.closed_channels) == 1)
    finally:
        client.close()


def test_stdin_close_sends_eof(feature_server, tmp_path):
    _, port, _ = feature_server
    client = _client(tmp_path, port)
    try:
        stdin, stdout, _ = client.exec_command("cat")
        stdin.write(b"line one\nline two\n")
        stdin.close()
        assert stdout.read() == b"line one\nline two\n"
    finally:
        client.close()


def test_client_ignores_server_banner(feature_server, tmp_path):
    _, port, _ = feature_server
    client = _client(tmp_path, port)
    try:
        assert client.is_connected()
        assert not client.get_transport()._message_queue
    finally:
        client.close()


def test_unsupported_service_request_disconnects(feature_server):
    from spindlex.protocol.messages import ServiceRequestMessage
    from spindlex.transport.transport import Transport

    _, port, _ = feature_server
    import socket as socket_mod

    sock = socket_mod.create_connection(("127.0.0.1", port), timeout=5)
    transport = Transport(sock)
    try:
        transport.start_client(timeout=5)
        transport._send_message(ServiceRequestMessage("no-such-service"))
        with pytest.raises(Exception, match="(?i)disconnect|closed|service"):
            transport._expect_message(6)  # SERVICE_ACCEPT never comes
    finally:
        transport.close()


# ---- SFTP file semantics against the SpindleX server ----


def test_sftp_file_position_seek_and_modes(server, tmp_path):
    _, port, root = server
    client = _client(tmp_path, port)
    try:
        sftp = client.open_sftp()
        with sftp.open("/rw.txt", "w+") as f:
            f.write(b"hello world")
            assert f.tell() == 11
            f.seek(0)
            assert f.read(5) == b"hello"
            f.write(b"_")  # continues at the read position
            f.seek(0)
            assert f.read() == b"hello_world"
            assert f.seek(-5, 2) == 6
            assert f.read() == b"world"
        with sftp.open("/rw.txt", "r+") as f:
            f.seek(6)
            f.write(b"WORLD")
        assert (root / "rw.txt").read_bytes() == b"hello_WORLD"
        sftp.truncate("/rw.txt", 5)
        assert (root / "rw.txt").read_bytes() == b"hello"
        assert sftp.stat("/rw.txt").st_size == 5
        sftp.close()
    finally:
        client.close()


@pytest.mark.skipif(
    __import__("os").name == "nt", reason="symlinks need privileges on Windows"
)
def test_sftp_symlink_and_readlink(server, tmp_path):
    _, port, root = server
    client = _client(tmp_path, port)
    try:
        sftp = client.open_sftp()
        sftp.symlink("/a.txt", "/link.txt")
        assert sftp.readlink("/link.txt") == "/a.txt"
        assert sftp.stat("/link.txt").st_size == (root / "a.txt").stat().st_size
        sftp.close()
    finally:
        client.close()


def test_sftp_non_utf8_names_round_trip():
    from spindlex.protocol.sftp_messages import (
        SFTPAttributes,
        SFTPMessage,
        SFTPNameMessage,
    )

    raw = b"caf" + bytes([0xE9]) + b".txt"  # Latin-1, not valid UTF-8
    name = raw.decode("utf-8", "surrogateescape")
    msg = SFTPNameMessage(1, [(name, name, SFTPAttributes())])
    parsed = SFTPMessage.unpack(msg.pack())
    assert parsed.names[0][0] == name
    assert parsed.names[0][0].encode("utf-8", "surrogateescape") == raw


def test_server_advertises_server_sig_algs(server, tmp_path):
    """RFC 8308 EXT_INFO: without server-sig-algs OpenSSH clients refuse to
    use RSA keys ("no mutual signature algorithm")."""
    from spindlex.protocol.utils import read_string, read_uint32
    from spindlex.transport.transport import Transport

    seen: dict[str, bytes] = {}
    original = Transport._dispatch_packet

    def spy(self, packet, single_pump=False):
        from spindlex.protocol.utils import extract_message_from_packet

        payload = extract_message_from_packet(packet)
        if payload[0] == 7:  # SSH_MSG_EXT_INFO
            count, offset = read_uint32(payload, 1)
            for _ in range(count):
                name, offset = read_string(payload, offset)
                value, offset = read_string(payload, offset)
                seen[name.decode()] = value
        return original(self, packet, single_pump)

    Transport._dispatch_packet = spy  # type: ignore[method-assign]
    try:
        _, port, _ = server
        client = _client(tmp_path, port)
        client.close()
    finally:
        Transport._dispatch_packet = original  # type: ignore[method-assign]
    algs = seen.get("server-sig-algs", b"").decode().split(",")
    assert "rsa-sha2-512" in algs and "rsa-sha2-256" in algs and "ssh-ed25519" in algs


def test_sftp_server_closes_channel_when_client_leaves(server, tmp_path):
    """The server must answer the client's EOF by closing the session;
    an OpenSSH sftp client otherwise hangs on exit."""
    iface, port, _ = server
    opened = []
    original = SFTPServer.__init__

    def track(self, channel, root_path="/", start_thread=True):
        opened.append(channel)
        original(self, channel, root_path, start_thread)

    SFTPServer.__init__ = track  # type: ignore[method-assign]
    try:
        client = _client(tmp_path, port)
        sftp = client.open_sftp()
        sftp.listdir("/")
        channel = sftp._channel
        channel.send_eof()  # what OpenSSH's sftp does when it exits
        assert _wait_for(lambda: opened and opened[0].closed)
        sftp.close()
        client.close()
    finally:
        SFTPServer.__init__ = original  # type: ignore[method-assign]
