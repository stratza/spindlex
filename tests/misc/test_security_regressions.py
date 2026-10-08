"""
Regression tests for security hardening (see the private advisory).

Each test drives the real code path - over loopback sockets where the issue
is about what goes over the wire.
"""

from __future__ import annotations

import base64
import logging
import os
import socket
import struct
import tempfile
import time
from unittest.mock import MagicMock

import pytest

from spindlex.crypto.pkey import Ed25519Key
from spindlex.exceptions import BadHostKeyException
from spindlex.hostkeys.storage import HostKeyStorage
from spindlex.protocol.constants import AUTH_FAILED, AUTH_SUCCESSFUL
from spindlex.protocol.messages import UserAuthRequestMessage
from spindlex.protocol.utils import write_string
from spindlex.server.sftp_server import SFTPServer
from spindlex.server.ssh_server import SSHServer, SSHServerManager


def _plain_packet(payload: bytes) -> bytes:
    padding = 8 - ((len(payload) + 5) % 8)
    if padding < 4:
        padding += 8
    return (
        struct.pack(">IB", len(payload) + 1 + padding, padding)
        + payload
        + (b"\x00" * padding)
    )


class RecordingServer(SSHServer):
    def __init__(self) -> None:
        super().__init__()
        self.password_checks: list[tuple[str, str]] = []

    def check_auth_password(self, username: str, password: str) -> int:
        self.password_checks.append((username, password))
        return AUTH_FAILED


@pytest.fixture
def manager():
    iface = RecordingServer()
    mgr = SSHServerManager(iface, Ed25519Key.generate(), "127.0.0.1", 0)
    mgr.set_auth_timeout(2)
    mgr.set_connection_timeout(1)
    mgr.start_server()
    yield iface, mgr, mgr._server_socket.getsockname()[1]
    mgr.stop_server()


def test_plaintext_auth_before_key_exchange_is_refused(manager):
    iface, _, port = manager
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        sock.sendall(b"SSH-2.0-test\r\n")
        time.sleep(0.3)
        request = UserAuthRequestMessage(
            "root", "ssh-connection", "password", b"\x00" + write_string("guess")
        )
        sock.sendall(_plain_packet(request.pack()))
        time.sleep(1.0)
    finally:
        sock.close()
    assert iface.password_checks == []


def test_login_deadline_holds_against_byte_trickling(manager):
    _, _, port = manager  # auth_timeout = 2s, per-recv timeout = 1s
    sock = socket.create_connection(("127.0.0.1", port), timeout=10)
    sock.sendall(b"SSH-2.0-slow")  # never finish the version line
    started = time.monotonic()
    dropped_after = None
    try:
        while time.monotonic() - started < 10:
            time.sleep(0.5)  # below the per-recv timeout
            sock.sendall(b"x")
            sock.settimeout(0.01)
            try:
                if sock.recv(1024) == b"":
                    dropped_after = time.monotonic() - started
                    break
            except socket.timeout:
                pass
            except OSError:
                dropped_after = time.monotonic() - started
                break
    except OSError:
        dropped_after = time.monotonic() - started
    finally:
        sock.close()
    assert dropped_after is not None, "connection outlived the login deadline"
    assert dropped_after < 6


async def test_async_channel_enforces_receive_window():
    from spindlex.transport.async_channel import AsyncChannel

    transport = MagicMock()
    channel = AsyncChannel(transport, 1)
    channel._remote_channel_id = 7
    channel._local_window_size = 1000
    channel._local_max_packet_size = 100
    for _ in range(100):
        channel._handle_data(b"x" * 1000)
    assert channel.closed
    assert len(channel._recv_buffer) <= 1100
    transport._close_channel.assert_called_with(1)


def _known_hosts_with(tmp_path, *lines: str) -> str:
    path = tmp_path / "known_hosts"
    path.write_text("".join(line + "\n" for line in lines))
    return str(path)


def test_revoked_host_key_is_refused_even_with_permissive_policy(tmp_path):
    from spindlex.client.ssh_client import SSHClient
    from spindlex.hostkeys.policy import AutoAddPolicy

    key = Ed25519Key.generate()
    path = _known_hosts_with(tmp_path, f"@revoked * {key.get_openssh_string()}")
    storage = HostKeyStorage(path)
    assert storage.is_revoked("example.com", 22, key)
    assert not storage.is_revoked("example.com", 22, Ed25519Key.generate())

    client = SSHClient()
    client.set_host_key_storage(storage)
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    client._hostname = "example.com"
    client._transport = MagicMock()
    client._transport.get_server_host_key.return_value = key
    with pytest.raises(BadHostKeyException):
        client._verify_host_key()
    assert storage.lookup("example.com") == []


def test_revoked_marker_respects_host_patterns(tmp_path):
    key = Ed25519Key.generate()
    path = _known_hosts_with(
        tmp_path, f"@revoked *.bad.example {key.get_openssh_string()}"
    )
    storage = HostKeyStorage(path)
    assert storage.is_revoked("host.bad.example", 22, key)
    assert not storage.is_revoked("host.good.example", 22, key)


def test_removed_host_key_is_deleted_from_disk(tmp_path):
    old, new = Ed25519Key.generate(), Ed25519Key.generate()
    path = _known_hosts_with(
        tmp_path,
        "# my hosts",
        f"server.example,10.0.0.5 {old.get_openssh_string()}",
        f"other.example {old.get_openssh_string()}",
    )
    storage = HostKeyStorage(path)
    assert storage.remove("server.example", old)
    storage.add("server.example", new)
    storage.save()

    reloaded = HostKeyStorage(path)
    assert reloaded.lookup("server.example") == [new]
    # Other hosts sharing the line / the key are untouched.
    assert reloaded.lookup("10.0.0.5") == [old]
    assert reloaded.lookup("other.example") == [old]
    assert open(path).read().startswith("# my hosts\n")


def test_removed_hashed_host_key_is_deleted_from_disk(tmp_path):
    import hashlib
    import hmac

    key = Ed25519Key.generate()
    salt = os.urandom(20)
    digest = hmac.new(salt, b"secret.example", hashlib.sha1).digest()
    token = f"|1|{base64.b64encode(salt).decode()}|{base64.b64encode(digest).decode()}"
    path = _known_hosts_with(tmp_path, f"{token} {key.get_openssh_string()}")
    storage = HostKeyStorage(path)
    assert storage.lookup("secret.example") == [key]
    assert storage.remove("secret.example")
    storage.save()
    assert HostKeyStorage(path).lookup("secret.example") == []


def test_sanitizer_covers_records_from_child_loggers():
    import io

    from spindlex.logging.sanitizer import configure_sanitizing_logging

    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    root = logging.getLogger()
    root.addHandler(handler)
    previous = root.level
    root.setLevel(logging.INFO)
    try:
        configure_sanitizing_logging()
        logging.getLogger("spindlex.transport.transport").warning(
            "login password=hunter2"
        )
    finally:
        root.removeHandler(handler)
        root.setLevel(previous)
    assert "hunter2" not in buffer.getvalue()
    assert "[PASSWORD_REDACTED]" in buffer.getvalue()


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_private_key_files_are_created_owner_only(tmp_path):
    from spindlex.crypto.pkey import ECDSAKey, RSAKey

    for key in (Ed25519Key.generate(), ECDSAKey.generate(), RSAKey.generate()):
        path = tmp_path / f"key-{key.algorithm_name}"
        old_umask = os.umask(0)
        try:
            key.save_to_file(str(path))
        finally:
            os.umask(old_umask)
        assert (path.stat().st_mode & 0o777) == 0o600


# ---- SFTP server ----


def _sftp_server(root: str) -> SFTPServer:
    channel = MagicMock()
    channel.closed = False
    channel.eof_received = False
    return SFTPServer(channel, root, start_thread=False)


def test_sftp_error_status_does_not_reveal_server_paths(tmp_path):
    from spindlex.protocol.sftp_messages import SFTPAttributes, SFTPMkdirMessage

    root = tmp_path / "secret-root-location"
    root.mkdir()
    (root / "file.txt").write_text("x")
    server = _sftp_server(str(root))
    sent = []
    server._send_message = sent.append
    # mkdir below a regular file fails with an OSError naming the full path.
    server._handle_mkdir(SFTPMkdirMessage(1, "/file.txt/sub", SFTPAttributes()))
    assert sent
    assert "secret-root-location" not in sent[0].message
    assert str(tmp_path) not in sent[0].message


def test_sftp_directory_handles_are_capped(tmp_path):
    from spindlex.protocol.sftp_constants import MAX_SFTP_HANDLES, SSH_FX_FAILURE
    from spindlex.protocol.sftp_messages import SFTPOpenDirMessage, SFTPStatusMessage

    server = _sftp_server(str(tmp_path))
    sent = []
    server._send_message = sent.append
    for i in range(MAX_SFTP_HANDLES + 5):
        server._handle_opendir(SFTPOpenDirMessage(i, "/"))
    assert len(server._handles) == MAX_SFTP_HANDLES
    refusals = [
        m
        for m in sent
        if isinstance(m, SFTPStatusMessage) and m.status_code == SSH_FX_FAILURE
    ]
    assert len(refusals) == 5


def test_sftp_session_end_closes_open_files(tmp_path):
    (tmp_path / "f.txt").write_text("data")
    server = _sftp_server(str(tmp_path))
    file_obj = open(tmp_path / "f.txt", "rb")
    from spindlex.server.sftp_server import SFTPHandle

    server._handles[b"h"] = SFTPHandle(b"h", str(tmp_path / "f.txt"), 1, file_obj)

    def session_ends():
        return None  # client sent EOF: the message loop simply returns

    server._start_sftp_session = session_ends
    server._run_server()
    assert file_obj.closed
    assert server._handles == {}


@pytest.mark.skipif(os.name == "nt", reason="symlinks need privileges on Windows")
def test_sftp_listing_does_not_follow_links_out_of_root(tmp_path):
    from spindlex.protocol.sftp_messages import (
        SFTPNameMessage,
        SFTPOpenDirMessage,
        SFTPReadDirMessage,
    )

    outside = tempfile.mkdtemp()
    secret = os.path.join(outside, "secret.bin")
    with open(secret, "wb") as fh:
        fh.write(b"x" * 12345)
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(secret, root / "escape")

    server = _sftp_server(str(root))
    sent = []
    server._send_message = sent.append
    server._handle_opendir(SFTPOpenDirMessage(1, "/"))
    handle = sent[-1].handle
    server._handle_readdir(SFTPReadDirMessage(2, handle))
    names = [m for m in sent if isinstance(m, SFTPNameMessage)][0].names
    attrs = {n: a for n, _, a in names}["escape"]
    assert attrs.size != 12345  # the link itself, not the outside file


def test_concurrency_limit_for_async_recursive_download(tmp_path):
    import asyncio
    import stat as stat_module
    from unittest.mock import AsyncMock

    from spindlex.client.async_sftp_client import AsyncSFTPClient
    from spindlex.protocol.sftp_messages import SFTPAttributes

    client = AsyncSFTPClient(MagicMock())
    dir_attrs, file_attrs = SFTPAttributes(), SFTPAttributes()
    dir_attrs.st_mode = stat_module.S_IFDIR | 0o755
    file_attrs.st_mode = stat_module.S_IFREG | 0o644

    async def stat(path):
        return dir_attrs if path == "/d" else file_attrs

    client.stat = stat
    client.lstat = AsyncMock(return_value=file_attrs)
    client.listdir = AsyncMock(return_value=[f"f{i}" for i in range(50)])
    running = 0
    peak = 0

    async def get(remote, local):
        nonlocal running, peak
        running += 1
        peak = max(peak, running)
        await asyncio.sleep(0.01)
        running -= 1

    client.get = get

    asyncio.run(client.get_recursive("/d", str(tmp_path / "out"), max_concurrency=4))
    assert peak <= 4


def test_userauth_requires_service_request_end_to_end(tmp_path):
    """A client that skips SERVICE_REQUEST is disconnected, not authenticated."""
    from spindlex.transport.transport import Transport

    iface = RecordingServer()
    iface.check_auth_password = lambda u, p: AUTH_SUCCESSFUL  # type: ignore[method-assign]
    mgr = SSHServerManager(iface, Ed25519Key.generate(), "127.0.0.1", 0)
    mgr.start_server()
    port = mgr._server_socket.getsockname()[1]
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    transport = Transport(sock)
    try:
        transport.start_client(timeout=5)
        transport._send_message(
            UserAuthRequestMessage(
                "user", "ssh-connection", "password", b"\x00" + write_string("pw")
            )
        )
        with pytest.raises(Exception, match="(?i)disconnect|closed"):
            transport._expect_message(51, 52)
        assert not transport.authenticated
    finally:
        transport.close()
        mgr.stop_server()
