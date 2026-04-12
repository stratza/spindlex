from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from spindlex.client.async_ssh_client import AsyncSSHClient
from spindlex.exceptions import BadHostKeyException


@pytest.fixture
def async_ssh_client():
    client = AsyncSSHClient()
    return client


@pytest.mark.asyncio
async def test_async_ssh_client_connect(async_ssh_client):
    from spindlex.hostkeys.policy import AutoAddPolicy
    from spindlex.hostkeys.storage import HostKeyStorage
    import os

    # Use a temporary empty storage for the test
    async_ssh_client._host_key_storage = HostKeyStorage(os.devnull)
    async_ssh_client.set_missing_host_key_policy(AutoAddPolicy())

    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
        mock_reader = AsyncMock()
        mock_reader.readline.return_value = b"SSH-2.0-spindlex_test\r\n"
        mock_writer = AsyncMock()
        mock_open.return_value = (mock_reader, mock_writer)

        with patch("spindlex.client.async_ssh_client.AsyncTransport") as mock_trans_cls:
            mock_trans = AsyncMock()
            mock_trans_cls.return_value = mock_trans
            # Ensure synchronous methods return values, not coroutines
            mock_trans.get_server_host_key = MagicMock()
            mock_trans.get_server_host_key.return_value = MagicMock()
            
            # No need to explicitly mock start_client as AsyncMock() is already a coroutine
            # but we can do it for clarity
            mock_trans.start_client = AsyncMock()
            mock_trans.connect_existing = AsyncMock()

            await async_ssh_client.connect(
                "localhost", username="alice", password="password"
            )
            assert mock_open.called
            assert mock_trans.start_client.called


@pytest.mark.asyncio
async def test_async_ssh_client_exec_command(async_ssh_client):
    transport = AsyncMock()
    async_ssh_client._transport = transport
    async_ssh_client._connected = True

    channel = AsyncMock()
    transport.open_channel = AsyncMock(return_value=channel)

    stdin, stdout, stderr = await async_ssh_client.exec_command("ls")
    assert transport.open_channel.called
    assert channel.exec_command.called


@pytest.mark.asyncio
async def test_async_ssh_client_close(async_ssh_client):
    transport = AsyncMock()
    # transport.close is automatically an AsyncMock if transport is AsyncMock
    async_ssh_client._transport = transport
    async_ssh_client._connected = True
    await async_ssh_client.close()

    assert transport.close.called


@pytest.mark.asyncio
async def test_async_ssh_client_host_key_verification_fail(async_ssh_client):
    with patch("asyncio.open_connection", new_callable=AsyncMock) as mock_open:
        mock_reader = AsyncMock()
        mock_writer = AsyncMock()
        mock_open.return_value = (mock_reader, mock_writer)

        with patch("spindlex.client.async_ssh_client.AsyncTransport") as mock_trans_cls:
            mock_trans = AsyncMock()
            mock_trans_cls.return_value = mock_trans
            mock_trans.start_client = AsyncMock()
            mock_trans.connect_existing = AsyncMock()
            mock_trans.close = AsyncMock()

            # Mock host key mismatch - ensure it returns a value, not a coroutine
            mock_trans.get_server_host_key = MagicMock()
            mock_trans.get_server_host_key.return_value = MagicMock()

            with pytest.raises(BadHostKeyException):
                await async_ssh_client.connect(
                    "localhost", username="alice", password="password"
                )

            # Ensure transport.close was called and awaited (internally by connect)
            assert mock_trans.close.called
