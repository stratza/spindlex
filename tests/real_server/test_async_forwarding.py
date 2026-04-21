import asyncio

import pytest
from spindlex import AsyncSSHClient
from spindlex.hostkeys.policy import AutoAddPolicy

pytestmark = pytest.mark.real_server


@pytest.mark.asyncio
@pytest.mark.xfail(
    reason="Local port forward sometimes fails to read banner on certain servers"
)
async def test_async_local_port_forward(ssh_server):
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        await client.connect(host, port=port, username=user, password=password)

        # Forward local port 22222 to server's port 22
        local_port = 22222
        tunnel_id = await client.create_local_port_forward(
            local_port, "127.0.0.1", port
        )

        try:
            # Connect to the local port
            reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
            banner = await asyncio.wait_for(reader.read(256), timeout=5.0)
            writer.close()
            await writer.wait_closed()

            assert b"SSH" in banner
        finally:
            await client.close_port_forward(tunnel_id)


@pytest.mark.asyncio
async def test_async_remote_port_forward(ssh_server):
    # This might require GatewayPorts yes on the server, but let's try
    host, port, user, password = ssh_server
    async with AsyncSSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        await client.connect(host, port=port, username=user, password=password)

        # Forward server's port 33333 back to local port 22222 (which isn't listening but that's fine for testing the request)
        # Actually, let's just test that it doesn't fail to request
        try:
            tunnel_id = await client.create_remote_port_forward(33333, "127.0.0.1", 22)
            await client.close_port_forward(tunnel_id)
        except Exception as e:
            # Some servers might forbid remote forwarding by default
            if "denied" not in str(e).lower():
                raise
