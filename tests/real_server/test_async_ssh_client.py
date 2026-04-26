import asyncio

import pytest

from spindlex import AsyncSSHClient
from spindlex.hostkeys.policy import AutoAddPolicy

pytestmark = pytest.mark.real_server


@pytest.mark.asyncio
async def test_async_ssh_client_connect(ssh_server):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await client.connect(host, port=port, username=user, password=password)
        assert client.connected
        assert client._transport is not None


@pytest.mark.asyncio
async def test_async_ssh_client_exec(ssh_server):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await client.connect(host, port=port, username=user, password=password)
        stdin, stdout, stderr = await client.exec_command("echo 'Hello Async'")
        out = (await stdout.read()).decode().strip()
        assert out == "Hello Async"


@pytest.mark.asyncio
async def test_async_ssh_client_concurrent_exec(ssh_server):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await client.connect(host, port=port, username=user, password=password)

        async def run_cmd(c):
            stdin, stdout, stderr = await client.exec_command(f"echo {c}")
            return (await stdout.read()).decode().strip()

        results = await asyncio.gather(run_cmd("A"), run_cmd("B"), run_cmd("C"))
        assert sorted(results) == ["A", "B", "C"]
