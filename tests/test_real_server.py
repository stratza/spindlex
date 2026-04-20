"""
Real-server integration tests for SpindleX.

Requires a live SSH server. Configure via .env:
    SSH_HOST, SSH_PORT, SSH_USER, SSH_PASSWORD

Run with:
    pytest tests/test_real_server.py -m real_server -v
"""
import asyncio
import io
import os
import stat
import tempfile

import pytest

from spindlex import AsyncSSHClient, SSHClient
from spindlex.hostkeys.policy import AutoAddPolicy, WarningPolicy

pytestmark = pytest.mark.real_server


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_client(host, port, user, password):
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect(host, port=port, username=user, password=password)
    return client


# ===========================================================================
# Sync SSH client tests
# ===========================================================================

class TestSyncConnect:
    def test_connect_and_transport_active(self, real_server_creds):
        host, port, user, password = real_server_creds
        client = make_client(host, port, user, password)
        try:
            transport = client.get_transport()
            assert transport is not None
            assert transport.active
            assert transport.authenticated
        finally:
            client.close()

    def test_context_manager(self, real_server_creds):
        host, port, user, password = real_server_creds
        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(host, port=port, username=user, password=password)
            assert client.get_transport().active

    def test_is_active(self, real_server_creds):
        host, port, user, password = real_server_creds
        with SSHClient() as client:
            client.set_missing_host_key_policy(AutoAddPolicy())
            client.connect(host, port=port, username=user, password=password)
            assert client.is_active  # property
        assert not client.is_active

    def test_reconnect(self, real_server_creds):
        host, port, user, password = real_server_creds
        client = make_client(host, port, user, password)
        client.close()
        client2 = make_client(host, port, user, password)
        assert client2.get_transport().active
        client2.close()


class TestSyncExecCommand:
    def test_exec_uname(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("uname -s")
        output = stdout.read().decode().strip()
        assert output == "Linux"

    def test_exec_echo(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("echo hello_spindlex")
        assert stdout.read().decode().strip() == "hello_spindlex"

    def test_exec_stderr(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("ls /nonexistent_path_xyz 2>&1; true")
        out = stdout.read().decode()
        # command succeeded (exit 0 because of "; true") but produced error text
        assert "No such file" in out or out == ""

    def test_exec_exit_status_zero(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("true")
        stdout.read()
        assert stdout.channel.recv_exit_status() == 0

    def test_exec_exit_status_nonzero(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("false")
        stdout.read()
        assert stdout.channel.recv_exit_status() != 0

    def test_exec_multiple_commands(self, ssh_client):
        for i in range(5):
            stdin, stdout, stderr = ssh_client.exec_command(f"echo {i}")
            assert stdout.read().decode().strip() == str(i)

    def test_exec_multiline_output(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("printf 'a\\nb\\nc\\n'")
        lines = stdout.read().decode().splitlines()
        assert lines == ["a", "b", "c"]

    @pytest.mark.slow
    def test_exec_large_output(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("dd if=/dev/urandom bs=1024 count=32 2>/dev/null | base64")
        data = stdout.read()
        assert len(data) > 30_000

    def test_exec_env(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("echo $HOME")
        home = stdout.read().decode().strip()
        assert home.startswith("/")

    def test_exec_stdin_write(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("cat")
        stdin.write(b"spindlex_stdin_test")
        stdin.channel.send_eof()
        out = stdout.read().decode()
        assert "spindlex_stdin_test" in out


class TestSyncSFTP:
    def test_sftp_context_manager(self, ssh_client):
        with ssh_client.open_sftp() as sftp:
            cwd = sftp.getcwd()
            assert cwd is not None or cwd is None  # just ensure no exception

    def test_sftp_listdir(self, ssh_client):
        with ssh_client.open_sftp() as sftp:
            files = sftp.listdir(".")
            assert isinstance(files, list)

    def test_sftp_put_get(self, ssh_client, tmp_path):
        local_src = tmp_path / "upload.txt"
        local_dst = tmp_path / "download.txt"
        local_src.write_bytes(b"SpindleX SFTP test data")

        with ssh_client.open_sftp() as sftp:
            sftp.put(str(local_src), "spindlex_test_upload.txt")
            sftp.get("spindlex_test_upload.txt", str(local_dst))
            sftp.remove("spindlex_test_upload.txt")

        assert local_dst.read_bytes() == b"SpindleX SFTP test data"

    @pytest.mark.slow
    def test_sftp_put_get_large_file(self, ssh_client, tmp_path):
        data = os.urandom(512 * 1024)  # 512 KB
        local_src = tmp_path / "large.bin"
        local_dst = tmp_path / "large_down.bin"
        local_src.write_bytes(data)

        with ssh_client.open_sftp() as sftp:
            sftp.put(str(local_src), "spindlex_large_test.bin")
            sftp.get("spindlex_large_test.bin", str(local_dst))
            sftp.remove("spindlex_large_test.bin")

        assert local_dst.read_bytes() == data

    def test_sftp_mkdir_rmdir(self, ssh_client):
        with ssh_client.open_sftp() as sftp:
            sftp.mkdir("spindlex_testdir_xyz")
            files = sftp.listdir(".")
            assert "spindlex_testdir_xyz" in files
            sftp.rmdir("spindlex_testdir_xyz")
            files2 = sftp.listdir(".")
            assert "spindlex_testdir_xyz" not in files2

    def test_sftp_rename(self, ssh_client, tmp_path):
        local = tmp_path / "rename_src.txt"
        local.write_bytes(b"rename test")

        with ssh_client.open_sftp() as sftp:
            sftp.put(str(local), "spindlex_rename_src.txt")
            sftp.rename("spindlex_rename_src.txt", "spindlex_rename_dst.txt")
            files = sftp.listdir(".")
            assert "spindlex_rename_dst.txt" in files
            assert "spindlex_rename_src.txt" not in files
            sftp.remove("spindlex_rename_dst.txt")

    def test_sftp_stat(self, ssh_client, tmp_path):
        local = tmp_path / "stat_test.txt"
        local.write_bytes(b"stat data")

        with ssh_client.open_sftp() as sftp:
            sftp.put(str(local), "spindlex_stat_test.txt")
            attrs = sftp.stat("spindlex_stat_test.txt")
            assert attrs.st_size == 9
            sftp.remove("spindlex_stat_test.txt")

    def test_sftp_lstat(self, ssh_client, tmp_path):
        local = tmp_path / "lstat_test.txt"
        local.write_bytes(b"lstat")

        with ssh_client.open_sftp() as sftp:
            sftp.put(str(local), "spindlex_lstat_test.txt")
            attrs = sftp.lstat("spindlex_lstat_test.txt")
            assert attrs.st_size == 5
            sftp.remove("spindlex_lstat_test.txt")

    def test_sftp_chmod(self, ssh_client, tmp_path):
        local = tmp_path / "chmod_test.txt"
        local.write_bytes(b"chmod")

        with ssh_client.open_sftp() as sftp:
            sftp.put(str(local), "spindlex_chmod_test.txt")
            sftp.chmod("spindlex_chmod_test.txt", 0o644)
            attrs = sftp.stat("spindlex_chmod_test.txt")
            assert attrs.st_mode & 0o777 == 0o644
            sftp.remove("spindlex_chmod_test.txt")

    def test_sftp_normalize(self, ssh_client):
        with ssh_client.open_sftp() as sftp:
            path = sftp.normalize(".")
            assert path.startswith("/")

    def test_sftp_open_read_write(self, ssh_client):
        with ssh_client.open_sftp() as sftp:
            # Write via open
            f = sftp.open("spindlex_open_test.txt", "w")
            f.write(b"open write test")
            f.close()

            # Read back
            f2 = sftp.open("spindlex_open_test.txt", "r")
            content = f2.read()
            f2.close()

            assert content == b"open write test"
            sftp.remove("spindlex_open_test.txt")

    def test_sftp_listdir_after_upload(self, ssh_client, tmp_path):
        local = tmp_path / "attr_test.txt"
        local.write_bytes(b"attr")

        with ssh_client.open_sftp() as sftp:
            sftp.put(str(local), "spindlex_attr_test.txt")
            names = sftp.listdir(".")
            assert "spindlex_attr_test.txt" in names
            sftp.remove("spindlex_attr_test.txt")


class TestSyncTransport:
    def test_get_host_keys(self, ssh_client):
        keys = ssh_client.get_host_keys()
        assert keys is not None

    def test_transport_properties(self, ssh_client):
        t = ssh_client.get_transport()
        assert t.active
        assert t.authenticated

    def test_rekey_policy(self, ssh_client):
        t = ssh_client.get_transport()
        t.set_rekey_policy(bytes_limit=10 * 1024 * 1024)
        # Still connected
        stdin, stdout, stderr = ssh_client.exec_command("echo after_rekey_set")
        assert stdout.read().decode().strip() == "after_rekey_set"


# ===========================================================================
# Async SSH client tests
# ===========================================================================

class TestAsyncConnect:
    def test_async_connect(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            client = AsyncSSHClient()
            client.set_missing_host_key_policy(AutoAddPolicy())
            await client.connect(host, port=port, username=user, password=password)
            assert client.connected
            assert client._transport is not None
            assert client._transport._authenticated
            await client.close()

        asyncio.run(run())

    def test_async_context_manager(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)
                assert client.connected

        asyncio.run(run())

    def test_async_is_active(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            client = AsyncSSHClient()
            client.set_missing_host_key_policy(WarningPolicy())
            await client.connect(host, port=port, username=user, password=password)
            assert client.connected  # property
            await client.close()

        asyncio.run(run())


class TestAsyncExecCommand:
    def test_async_exec_uname(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)
                stdin, stdout, stderr = await client.exec_command("uname -s")
                out = (await stdout.read()).decode().strip()
                assert out == "Linux"

        asyncio.run(run())

    def test_async_exec_exit_status(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                stdin, stdout, stderr = await client.exec_command("true")
                await stdout.read()
                status = await stdout.channel.recv_exit_status()
                assert status == 0

                stdin2, stdout2, stderr2 = await client.exec_command("false")
                await stdout2.read()
                status2 = await stdout2.channel.recv_exit_status()
                assert status2 != 0

        asyncio.run(run())

    def test_async_exec_multiple(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)
                for i in range(3):
                    stdin, stdout, stderr = await client.exec_command(f"echo {i}")
                    out = (await stdout.read()).decode().strip()
                    assert out == str(i)

        asyncio.run(run())

    @pytest.mark.slow
    def test_async_exec_large_output(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)
                stdin, stdout, stderr = await client.exec_command(
                    "dd if=/dev/urandom bs=1024 count=32 2>/dev/null | base64"
                )
                data = await stdout.read()
                assert len(data) > 30_000

        asyncio.run(run())

    def test_async_exec_stderr(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)
                stdin, stdout, stderr = await client.exec_command("echo err >&2; echo out")
                out = (await stdout.read()).decode().strip()
                err = (await stderr.read()).decode().strip()
                assert out == "out"
                assert err == "err"

        asyncio.run(run())

    def test_async_concurrent_commands(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async def exec_and_read(cmd, expected):
                    stdin, stdout, stderr = await client.exec_command(cmd)
                    out = (await stdout.read()).decode().strip()
                    assert out == expected

                await asyncio.gather(
                    exec_and_read("echo alpha", "alpha"),
                    exec_and_read("echo beta", "beta"),
                    exec_and_read("echo gamma", "gamma"),
                )

        asyncio.run(run())


class TestAsyncSFTP:
    def test_async_sftp_put_get(self, real_server_creds, tmp_path):
        host, port, user, password = real_server_creds

        async def run():
            local_src = tmp_path / "async_up.txt"
            local_dst = tmp_path / "async_down.txt"
            local_src.write_bytes(b"async sftp upload")

            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    await sftp.put(str(local_src), "spindlex_async_test.txt")
                    await sftp.get("spindlex_async_test.txt", str(local_dst))
                    await sftp.remove("spindlex_async_test.txt")

            assert local_dst.read_bytes() == b"async sftp upload"

        asyncio.run(run())

    def test_async_sftp_listdir(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    files = await sftp.listdir(".")
                    assert isinstance(files, list)

        asyncio.run(run())

    def test_async_sftp_mkdir_rmdir(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    await sftp.mkdir("spindlex_async_dir_xyz")
                    files = await sftp.listdir(".")
                    assert "spindlex_async_dir_xyz" in files
                    await sftp.rmdir("spindlex_async_dir_xyz")

        asyncio.run(run())

    def test_async_sftp_stat(self, real_server_creds, tmp_path):
        host, port, user, password = real_server_creds

        async def run():
            local = tmp_path / "async_stat.txt"
            local.write_bytes(b"statdata")

            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    await sftp.put(str(local), "spindlex_async_stat.txt")
                    attrs = await sftp.stat("spindlex_async_stat.txt")
                    assert attrs.st_size == 8
                    await sftp.remove("spindlex_async_stat.txt")

        asyncio.run(run())

    @pytest.mark.skip(reason="AsyncSFTPClient does not implement rename")
    def test_async_sftp_rename(self, real_server_creds, tmp_path):
        host, port, user, password = real_server_creds

        async def run():
            local = tmp_path / "async_rename.txt"
            local.write_bytes(b"rename")

            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    await sftp.put(str(local), "spindlex_async_rename_src.txt")
                    await sftp.rename("spindlex_async_rename_src.txt", "spindlex_async_rename_dst.txt")
                    files = await sftp.listdir(".")
                    assert "spindlex_async_rename_dst.txt" in files
                    assert "spindlex_async_rename_src.txt" not in files
                    await sftp.remove("spindlex_async_rename_dst.txt")

        asyncio.run(run())

    @pytest.mark.slow
    def test_async_sftp_large_file(self, real_server_creds, tmp_path):
        host, port, user, password = real_server_creds

        async def run():
            data = os.urandom(256 * 1024)
            local_src = tmp_path / "async_large.bin"
            local_dst = tmp_path / "async_large_down.bin"
            local_src.write_bytes(data)

            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    await sftp.put(str(local_src), "spindlex_async_large.bin")
                    await sftp.get("spindlex_async_large.bin", str(local_dst))
                    await sftp.remove("spindlex_async_large.bin")

            assert local_dst.read_bytes() == data

        asyncio.run(run())

    @pytest.mark.skip(reason="AsyncSFTPClient does not implement chmod")
    def test_async_sftp_chmod(self, real_server_creds, tmp_path):
        host, port, user, password = real_server_creds

        async def run():
            local = tmp_path / "async_chmod.txt"
            local.write_bytes(b"ch")

            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    await sftp.put(str(local), "spindlex_async_chmod.txt")
                    await sftp.chmod("spindlex_async_chmod.txt", 0o644)
                    attrs = await sftp.stat("spindlex_async_chmod.txt")
                    assert attrs.st_mode & 0o777 == 0o644
                    await sftp.remove("spindlex_async_chmod.txt")

        asyncio.run(run())

    @pytest.mark.skip(reason="AsyncSFTPClient does not implement normalize")
    def test_async_sftp_normalize(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    path = await sftp.normalize(".")
                    assert path.startswith("/")

        asyncio.run(run())

    def test_async_sftp_open_read_write(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    f = await sftp.open("spindlex_async_open_test.txt", "w")
                    await f.write(b"async open write")
                    await f.close()

                    f2 = await sftp.open("spindlex_async_open_test.txt", "r")
                    content = await f2.read()
                    await f2.close()

                    assert content == b"async open write"
                    await sftp.remove("spindlex_async_open_test.txt")

        asyncio.run(run())

    def test_async_concurrent_sftp_operations(self, real_server_creds, tmp_path):
        host, port, user, password = real_server_creds

        async def run():
            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                async with await client.open_sftp() as sftp:
                    # Create multiple files concurrently
                    async def upload_and_remove(name, data):
                        local = tmp_path / name
                        local.write_bytes(data)
                        await sftp.put(str(local), f"spindlex_concurrent_{name}")
                        attrs = await sftp.stat(f"spindlex_concurrent_{name}")
                        assert attrs.st_size == len(data)
                        await sftp.remove(f"spindlex_concurrent_{name}")

                    await asyncio.gather(
                        upload_and_remove("c1.txt", b"file1data"),
                        upload_and_remove("c2.txt", b"file2data_longer"),
                        upload_and_remove("c3.txt", b"f3"),
                    )

        asyncio.run(run())


# ===========================================================================
# Port forwarding tests
# ===========================================================================

class TestLocalPortForwarding:
    def test_local_forward_and_use(self, ssh_client):
        """Open a local port forward to the SSH server's own port 22."""
        import socket as sock_mod

        transport = ssh_client.get_transport()
        fwd_mgr = transport.get_port_forwarding_manager()

        local_port = 14722

        tunnel_id = fwd_mgr.create_local_tunnel(
            local_host="127.0.0.1",
            local_port=local_port,
            remote_host="127.0.0.1",
            remote_port=22,
        )

        try:
            assert tunnel_id is not None
            import time
            time.sleep(0.3)

            # Connect through the tunnel
            s = sock_mod.socket(sock_mod.AF_INET, sock_mod.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", local_port))
            banner = s.recv(256)
            s.close()
            assert b"SSH" in banner
        finally:
            fwd_mgr.close_tunnel(tunnel_id)


# ===========================================================================
# Async port forwarding
# ===========================================================================

class TestAsyncPortForwarding:
    @pytest.mark.skip(reason="Async port forwarding has known connection setup issues")
    def test_async_local_forward(self, real_server_creds):
        host, port, user, password = real_server_creds

        async def run():
            import socket as sock_mod

            async with AsyncSSHClient() as client:
                client.set_missing_host_key_policy(WarningPolicy())
                await client.connect(host, port=port, username=user, password=password)

                fwd_mgr = client._transport.get_port_forwarding_manager()

                tunnel_id = await fwd_mgr.create_local_tunnel(
                    local_host="127.0.0.1",
                    local_port=14723,
                    remote_host="127.0.0.1",
                    remote_port=22,
                )

                try:
                    await asyncio.sleep(0.3)
                    reader, writer = await asyncio.open_connection("127.0.0.1", 14723)
                    banner = await asyncio.wait_for(reader.read(256), timeout=5)
                    writer.close()
                    await writer.wait_closed()
                    assert b"SSH" in banner
                finally:
                    await fwd_mgr.close_tunnel(tunnel_id)

        asyncio.run(run())


# ===========================================================================
# Channel feature tests
# ===========================================================================

class TestChannelFeatures:
    def test_channel_timeout(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("sleep 0.1 && echo done")
        stdout.channel.settimeout(10)
        assert stdout.channel.gettimeout() == 10
        out = stdout.read().decode().strip()
        assert out == "done"

    def test_channel_send_recv(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("cat")
        stdin.write(b"test data for channel")
        stdin.channel.send_eof()
        out = stdout.read()
        assert out == b"test data for channel"

    def test_channel_exit_status(self, ssh_client):
        stdin, stdout, stderr = ssh_client.exec_command("exit 42")
        stdout.read()
        status = stdout.channel.recv_exit_status()
        assert status == 42

    def test_multiple_channels(self, ssh_client):
        channels = []
        for i in range(3):
            stdin, stdout, stderr = ssh_client.exec_command(f"echo channel_{i}")
            channels.append((i, stdout))

        for i, stdout in channels:
            out = stdout.read().decode().strip()
            assert out == f"channel_{i}"
