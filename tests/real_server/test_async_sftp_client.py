import pytest

from spindlex import AsyncSSHClient
from spindlex.hostkeys.policy import AutoAddPolicy

pytestmark = pytest.mark.real_server


@pytest.mark.asyncio
async def test_async_sftp_ops(ssh_server, tmp_path):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await client.connect(host, port=port, username=user, password=password)

        async with await client.open_sftp() as sftp:
            # listdir
            files = await sftp.listdir(".")
            assert isinstance(files, list)

            # put/get
            local_src = tmp_path / "async_up.txt"
            local_dst = tmp_path / "async_down.txt"
            local_src.write_bytes(b"async data")

            remote = "spindlex_async.txt"
            await sftp.put(str(local_src), remote)
            await sftp.get(remote, str(local_dst))
            await sftp.remove(remote)

            assert local_dst.read_bytes() == b"async data"


@pytest.mark.asyncio
async def test_async_sftp_mkdir_rmdir(ssh_server):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await client.connect(host, port=port, username=user, password=password)

        async with await client.open_sftp() as sftp:
            dirname = "async_test_dir"
            await sftp.mkdir(dirname)
            assert dirname in await sftp.listdir(".")
            await sftp.rmdir(dirname)
            assert dirname not in await sftp.listdir(".")


@pytest.mark.asyncio
@pytest.mark.skip(reason="Known timeout issue in async SFTP client")
async def test_async_sftp_file_open(ssh_server):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await client.connect(host, port=port, username=user, password=password)

        async with await client.open_sftp() as sftp:
            remote = "async_file_test.txt"
            async with await sftp.open(remote, "w") as f:
                await f.write(b"async open test")

            async with await sftp.open(remote, "r") as f:
                assert await f.read() == b"async open test"

            await sftp.remove(remote)
