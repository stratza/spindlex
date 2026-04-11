import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from spindlex.client.async_sftp_client import AsyncSFTPClient, AsyncSFTPFile
from spindlex.protocol.sftp_constants import *
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPDataMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
)


@pytest.fixture
def mock_channel():
    channel = AsyncMock()
    channel.closed = False
    return channel


@pytest.fixture
def async_sftp_client(mock_channel):
    client = AsyncSFTPClient(mock_channel)
    client._initialized = True
    return client


@pytest.mark.asyncio
async def test_async_sftp_client_init(mock_channel):
    client = AsyncSFTPClient(mock_channel)

    with patch.object(client, "_send_message", new_callable=AsyncMock) as mock_send:
        with patch.object(client, "_recv_message", new_callable=AsyncMock) as mock_recv:
            mock_recv.side_effect = [
                SFTPVersionMessage(3, {}),
                asyncio.CancelledError(),
            ]

            await client._initialize()

            assert client._initialized
            assert mock_send.called
            await client.close()


@pytest.mark.asyncio
async def test_async_sftp_client_remove(async_sftp_client):
    with patch.object(
        async_sftp_client, "_wait_for_response", new_callable=AsyncMock
    ) as mock_wait:
        with patch.object(async_sftp_client, "_send_message", new_callable=AsyncMock):
            mock_wait.return_value = SFTPStatusMessage(1, SSH_FX_OK, "OK")
            await async_sftp_client.remove("file.txt")
            assert mock_wait.called


@pytest.mark.asyncio
async def test_async_sftp_client_get(async_sftp_client):
    with patch.object(async_sftp_client, "open", new_callable=AsyncMock) as mock_open:
        mock_file = AsyncMock(spec=AsyncSFTPFile)

        mock_open.return_value = mock_file
        mock_file.read.side_effect = [b"hello", b""]

        with patch("builtins.open", MagicMock()):
            await async_sftp_client.get("remote.txt", "local.txt")

            assert mock_open.called
            assert mock_file.read.call_count == 2
            assert mock_file.close.called


@pytest.mark.asyncio
async def test_async_sftp_client_put(async_sftp_client):
    with patch.object(async_sftp_client, "open", new_callable=AsyncMock) as mock_open:
        mock_file = AsyncMock(spec=AsyncSFTPFile)
        mock_open.return_value = mock_file

        with patch("builtins.open", MagicMock()) as mock_local_open:
            mock_local_open.return_value.__enter__.return_value.read.side_effect = [
                b"hello",
                b"",
            ]
            await async_sftp_client.put("local.txt", "remote.txt")

            assert mock_open.called
            assert mock_file.write.called
            assert mock_file.close.called


@pytest.mark.asyncio
async def test_async_sftp_client_listdir(async_sftp_client):
    with patch.object(
        async_sftp_client, "_opendir", new_callable=AsyncMock
    ) as mock_opendir:
        with patch.object(
            async_sftp_client, "_readdir", new_callable=AsyncMock
        ) as mock_readdir:
            with patch.object(
                async_sftp_client, "_close", new_callable=AsyncMock
            ) as mock_close:
                mock_opendir.return_value = b"handle"
                mock_readdir.side_effect = [[("file1", "", SFTPAttributes())], []]

                files = await async_sftp_client.listdir(".")
                assert files == ["file1"]
                assert mock_close.called


@pytest.mark.asyncio
async def test_async_sftp_client_stat(async_sftp_client):
    with patch.object(
        async_sftp_client, "_wait_for_response", new_callable=AsyncMock
    ) as mock_wait:
        with patch.object(async_sftp_client, "_send_message", new_callable=AsyncMock):
            attrs = SFTPAttributes()
            mock_wait.return_value = SFTPAttrsMessage(1, attrs)

            res = await async_sftp_client.stat("path")
            assert res == attrs


@pytest.mark.asyncio
async def test_async_sftp_client_mkdir(async_sftp_client):
    with patch.object(
        async_sftp_client, "_wait_for_response", new_callable=AsyncMock
    ) as mock_wait:
        with patch.object(async_sftp_client, "_send_message", new_callable=AsyncMock):
            mock_wait.return_value = SFTPStatusMessage(1, SSH_FX_OK, "OK")
            await async_sftp_client.mkdir("dir")
            assert mock_wait.called


@pytest.mark.asyncio
async def test_async_sftp_file_read_write(async_sftp_client):
    handle = b"h1"
    sfile = AsyncSFTPFile(async_sftp_client, handle, "rb")

    with patch.object(
        async_sftp_client, "_wait_for_response", new_callable=AsyncMock
    ) as mock_wait:
        with patch.object(async_sftp_client, "_send_message", new_callable=AsyncMock):
            # Test read
            mock_wait.return_value = SFTPDataMessage(1, b"data")
            assert await sfile.read(4) == b"data"

            # Test write
            mock_wait.return_value = SFTPStatusMessage(2, SSH_FX_OK, "OK")
            await sfile.write(b"more")

            # Test close
            mock_wait.return_value = SFTPStatusMessage(3, SSH_FX_OK, "OK")
            await sfile.close()
            assert sfile._closed


@pytest.mark.asyncio
async def test_async_sftp_client_dispatch_error(mock_channel):
    client = AsyncSFTPClient(mock_channel)
    client._initialized = True

    # Mock recv_message to raise error
    with patch.object(client, "_recv_message", new_callable=AsyncMock) as mock_recv:
        mock_recv.side_effect = Exception("Channel error")

        fut = asyncio.get_running_loop().create_future()
        client._pending_requests[1] = fut

        # Start dispatch loop and wait for it to finish
        await client._dispatch_loop()

        assert fut.done()
        with pytest.raises(Exception, match="Channel error"):
            await fut
        assert len(client._pending_requests) == 0


@pytest.mark.asyncio
async def test_async_sftp_client_context_manager(mock_channel):
    client = AsyncSFTPClient(mock_channel)
    client._initialized = True

    async with client as c:
        assert c == client

    assert client._channel is None
