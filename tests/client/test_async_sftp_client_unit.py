"""Unit tests for spindlex/client/async_sftp_client.py to boost coverage."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spindlex.client.async_sftp_client import AsyncSFTPClient
from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import SSH_FX_EOF, SSH_FX_FAILURE, SSH_FX_OK
from spindlex.protocol.sftp_messages import (
    SFTPAttrsMessage,
    SFTPHandleMessage,
    SFTPNameMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
)


@pytest.fixture
def mock_channel():
    ch = MagicMock()
    ch.send = AsyncMock()
    ch.recv_exactly = AsyncMock()
    ch.close = AsyncMock()
    ch.closed = False
    return ch


class TestAsyncSFTPClient:
    @pytest.mark.asyncio
    async def test_init(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)

        async def fake_recv():
            await asyncio.sleep(0.01)
            return SFTPVersionMessage(3, {})

        with patch.object(client, "_send_message", new=AsyncMock()):
            with patch.object(client, "_recv_message", side_effect=fake_recv):
                await client._initialize()

        assert client._initialized is True
        # Close without waiting for dispatch task which might still be running
        client._initialized = False
        if client._dispatch_task:
            client._dispatch_task.cancel()

    @pytest.mark.asyncio
    async def test_init_fails(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        with patch.object(
            client, "_send_message", new=AsyncMock(side_effect=Exception("fail"))
        ):
            with pytest.raises(SFTPError, match="SFTP initialization failed"):
                await client._initialize()
        if client._dispatch_task:
            client._dispatch_task.cancel()

    @pytest.mark.asyncio
    async def test_remove(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        with patch.object(client, "_send_message", new=AsyncMock()):
            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(return_value=SFTPStatusMessage(1, SSH_FX_OK, "OK", "en")),
            ):
                await client.remove("test.txt")

            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(
                    return_value=SFTPStatusMessage(1, SSH_FX_FAILURE, "Fail", "en")
                ),
            ):
                with pytest.raises(SFTPError, match="File removal failed"):
                    await client.remove("test.txt")

            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(return_value=SFTPVersionMessage(3, {})),
            ):
                with pytest.raises(SFTPError, match="Unexpected response"):
                    await client.remove("test.txt")

    @pytest.mark.asyncio
    async def test_stat_lstat(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True
        attrs = MagicMock()

        with patch.object(client, "_send_message", new=AsyncMock()):
            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(return_value=SFTPAttrsMessage(1, attrs)),
            ):
                res = await client.stat("test")
                assert res is attrs

                res = await client.lstat("test")
                assert res is attrs

            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(
                    return_value=SFTPStatusMessage(1, SSH_FX_FAILURE, "Fail", "en")
                ),
            ):
                with pytest.raises(SFTPError):
                    await client.stat("test")
                with pytest.raises(SFTPError):
                    await client.lstat("test")

    @pytest.mark.asyncio
    async def test_mkdir_rmdir(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        with patch.object(client, "_send_message", new=AsyncMock()):
            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(return_value=SFTPStatusMessage(1, SSH_FX_OK, "OK", "en")),
            ):
                await client.mkdir("test")
                await client.rmdir("test")

            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(
                    return_value=SFTPStatusMessage(1, SSH_FX_FAILURE, "Fail", "en")
                ),
            ):
                with pytest.raises(SFTPError):
                    await client.mkdir("test")
                with pytest.raises(SFTPError):
                    await client.rmdir("test")

    @pytest.mark.asyncio
    async def test_open(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        with patch.object(client, "_send_message", new=AsyncMock()):
            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(return_value=SFTPHandleMessage(1, b"handle")),
            ):
                res = await client.open("test.txt", "r")
                assert res._handle == b"handle"

            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(
                    return_value=SFTPStatusMessage(1, SSH_FX_FAILURE, "Fail", "en")
                ),
            ):
                with pytest.raises(SFTPError):
                    await client.open("test.txt", "r")

    @pytest.mark.asyncio
    async def test_rename_symlink(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        with patch.object(client, "_send_message", new=AsyncMock()):
            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(return_value=SFTPStatusMessage(1, SSH_FX_OK, "OK", "en")),
            ):
                await client.rename("old", "new")
                await client.symlink("target", "link")

            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(
                    return_value=SFTPStatusMessage(1, SSH_FX_FAILURE, "Fail", "en")
                ),
            ):
                with pytest.raises(SFTPError):
                    await client.rename("old", "new")
                with pytest.raises(SFTPError):
                    await client.symlink("target", "link")

    @pytest.mark.asyncio
    async def test_readlink_normalize(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        name_msg = SFTPNameMessage(1, [("result_path", "longname", MagicMock())])

        with patch.object(client, "_send_message", new=AsyncMock()):
            with patch.object(
                client, "_wait_for_response", new=AsyncMock(return_value=name_msg)
            ):
                assert await client.readlink("link") == "result_path"
                assert await client.normalize("path") == "result_path"

            empty_msg = SFTPNameMessage(1, [])
            with patch.object(
                client, "_wait_for_response", new=AsyncMock(return_value=empty_msg)
            ):
                with pytest.raises(SFTPError, match="Empty response"):
                    await client.readlink("link")
                with pytest.raises(SFTPError, match="Empty response"):
                    await client.normalize("path")

    @pytest.mark.asyncio
    async def test_chmod(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        with patch.object(client, "_send_message", new=AsyncMock()):
            with patch.object(
                client,
                "_wait_for_response",
                new=AsyncMock(return_value=SFTPStatusMessage(1, SSH_FX_OK, "OK", "en")),
            ):
                await client.chmod("test.txt", 0o755)

    @pytest.mark.asyncio
    async def test_listdir(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        with patch.object(client, "_opendir", new=AsyncMock(return_value=b"handle")):
            with patch.object(client, "_close", new=AsyncMock()):
                with patch.object(
                    client,
                    "_readdir",
                    new=AsyncMock(
                        side_effect=[
                            [("file1", "l", MagicMock()), (".", "l", MagicMock())],
                            [],
                        ]
                    ),
                ):
                    files = await client.listdir("dir")
                    assert files == ["file1"]

    @pytest.mark.asyncio
    async def test_wait_for_response_timeout(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        with pytest.raises(SFTPError, match="Timeout"):
            await client._wait_for_response(1, timeout=0.01)

    @pytest.mark.asyncio
    async def test_dispatch_loop_cancellation(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)

        async def fake_recv():
            await asyncio.sleep(0.01)
            raise asyncio.CancelledError()

        with patch.object(client, "_recv_message", side_effect=fake_recv):
            await client._dispatch_loop()  # should exit cleanly

    @pytest.mark.asyncio
    async def test_dispatch_loop_error_cancels_pending(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        fut = asyncio.get_running_loop().create_future()
        client._pending_requests[1] = fut

        async def fake_recv():
            await asyncio.sleep(0.01)
            raise RuntimeError("broken")

        with patch.object(client, "_recv_message", side_effect=fake_recv):
            await client._dispatch_loop()

        assert fut.done()
        with pytest.raises(RuntimeError):
            fut.result()

    @pytest.mark.asyncio
    async def test_context_manager(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client.close = AsyncMock()
        async with client as c:
            assert c is client
        client.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        remote_file = AsyncMock()
        remote_file._handle = b"handle"

        with patch.object(client, "open", new=AsyncMock(return_value=remote_file)):
            with patch("builtins.open", MagicMock()):
                with patch.object(client, "_send_message", new=AsyncMock()):
                    client._pending_requests = {}

                    async def mock_wait_and_resolve():
                        await asyncio.sleep(0.01)
                        while client._pending_requests:
                            req_id = list(client._pending_requests.keys())[0]
                            fut = client._pending_requests.pop(req_id)
                            fut.set_result(
                                SFTPStatusMessage(req_id, SSH_FX_EOF, "EOF", "en")
                            )
                            await asyncio.sleep(0.01)

                    asyncio.create_task(mock_wait_and_resolve())
                    await client.get("remote", "local")

    @pytest.mark.asyncio
    async def test_put(self, mock_channel):
        client = AsyncSFTPClient(mock_channel)
        client._initialized = True

        remote_file = AsyncMock()
        remote_file._handle = b"handle"

        mock_file = MagicMock()
        mock_file.read.side_effect = [b"data", b""]
        mock_file.__enter__.return_value = mock_file

        with patch.object(client, "open", new=AsyncMock(return_value=remote_file)):
            with patch("builtins.open", return_value=mock_file):
                with patch.object(client, "_send_message", new=AsyncMock()):

                    async def mock_wait_and_resolve():
                        await asyncio.sleep(0.01)
                        while client._pending_requests:
                            req_id = list(client._pending_requests.keys())[0]
                            fut = client._pending_requests.pop(req_id)
                            fut.set_result(
                                SFTPStatusMessage(req_id, SSH_FX_OK, "OK", "en")
                            )
                            await asyncio.sleep(0.01)

                    asyncio.create_task(mock_wait_and_resolve())
                    await client.put("local", "remote")
