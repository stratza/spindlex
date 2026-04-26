import pytest

from spindlex import AsyncSSHClient
from spindlex.exceptions import ChannelException
from spindlex.hostkeys.policy import AutoAddPolicy

pytestmark = pytest.mark.real_server


@pytest.fixture
async def real_async_channel(ssh_server):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await client.connect(host, port=port, username=user, password=password)
        chan = await client._transport.open_channel("session")
        yield chan
        if not chan.closed:
            await chan.close()


@pytest.mark.asyncio
async def test_async_channel_send_recv(real_async_channel):
    await real_async_channel.exec_command("cat")
    data = b"async test"
    await real_async_channel.send(data)

    # Read back
    res = await real_async_channel.recv(len(data))
    assert res == data


@pytest.mark.asyncio
async def test_async_channel_recv_exactly(real_async_channel):
    await real_async_channel.exec_command("echo '1234567890'")
    res = await real_async_channel.recv_exactly(5)
    assert res == b"12345"
    res2 = await real_async_channel.recv_exactly(5)
    assert res2 == b"67890"


@pytest.mark.asyncio
async def test_async_channel_exec_command(real_async_channel):
    await real_async_channel.exec_command("echo hello")
    out = await real_async_channel.recv(1024)
    assert b"hello" in out
    status = await real_async_channel.recv_exit_status()
    assert status == 0


@pytest.mark.asyncio
async def test_async_channel_stderr(ssh_server):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await client.connect(host, port=port, username=user, password=password)
        chan = await client._transport.open_channel("session")
        await chan.exec_command("echo 'err' >&2")
        err = await chan.recv_stderr(1024)
        assert b"err" in err
        await chan.close()


@pytest.mark.asyncio
async def test_async_channel_close(real_async_channel):
    await real_async_channel.close()
    assert real_async_channel.closed
    with pytest.raises(ChannelException, match="closed"):
        await real_async_channel.send(b"data")
