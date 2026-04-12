import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from spindlex.client.async_ssh_client import AsyncSSHClient
from spindlex.transport.async_forwarding import AsyncPortForwardingManager


@pytest.fixture
def async_ssh_client():
    client = AsyncSSHClient()
    client._connected = True
    client._transport = MagicMock()
    return client


@pytest.mark.asyncio
async def test_create_local_port_forward(async_ssh_client):
    mock_manager = AsyncMock()
    async_ssh_client._transport.get_port_forwarding_manager.return_value = mock_manager
    mock_manager.create_local_tunnel.return_value = "tunnel_1"

    tunnel_id = await async_ssh_client.create_local_port_forward(8080, "remote", 80)
    
    assert tunnel_id == "tunnel_1"
    mock_manager.create_local_tunnel.assert_called_with(8080, "remote", 80, "127.0.0.1")


@pytest.mark.asyncio
async def test_create_remote_port_forward(async_ssh_client):
    mock_manager = AsyncMock()
    async_ssh_client._transport.get_port_forwarding_manager.return_value = mock_manager
    mock_manager.create_remote_tunnel.return_value = "tunnel_2"

    tunnel_id = await async_ssh_client.create_remote_port_forward(9090, "localhost", 90)
    
    assert tunnel_id == "tunnel_2"
    mock_manager.create_remote_tunnel.assert_called_with(9090, "localhost", 90, "")


@pytest.mark.asyncio
async def test_async_local_port_forwarder_logic():
    from spindlex.transport.async_forwarding import AsyncLocalPortForwarder
    
    transport = AsyncMock()
    forwarder = AsyncLocalPortForwarder(transport)
    
    with patch("asyncio.start_server", new_callable=AsyncMock) as mock_start_server:
        mock_server = AsyncMock()
        mock_start_server.return_value = mock_server
        
        tunnel_id = await forwarder.create_tunnel(8080, "remote", 80)
        
        assert tunnel_id.startswith("local_")
        assert mock_start_server.called
        assert tunnel_id in forwarder._tunnels
