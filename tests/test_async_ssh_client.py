import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from spindlex.client.async_ssh_client import AsyncSSHClient


@pytest.fixture
def async_ssh_client():
    client = AsyncSSHClient()
    return client


@pytest.mark.asyncio
async def test_async_ssh_client_connect(async_ssh_client):
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
        mock_reader = AsyncMock()
        mock_writer = MagicMock()
        mock_open.return_value = (mock_reader, mock_writer)
        
        with patch("spindlex.transport.async_transport.AsyncTransport") as mock_trans_cls:
            mock_trans = mock_trans_cls.return_value
            mock_trans.start_client = AsyncMock()
            
            await async_ssh_client.connect("localhost", username="alice", password="password")
            assert mock_open.called
            assert mock_trans.start_client.called


@pytest.mark.asyncio
async def test_async_ssh_client_exec_command(async_ssh_client):
    transport = AsyncMock()
    async_ssh_client._transport = transport
    channel = AsyncMock()
    transport.open_channel = AsyncMock(return_value=channel)
    
    stdin, stdout, stderr = await async_ssh_client.exec_command("ls")
    assert transport.open_channel.called
    assert channel.exec_command.called


@pytest.mark.asyncio
async def test_async_ssh_client_close(async_ssh_client):
    transport = AsyncMock()
    async_ssh_client._transport = transport
    await async_ssh_client.close()
    assert transport.close.called
