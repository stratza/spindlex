"""
Unit tests for spindlex/client/async_sftp_client.py

All tests use AsyncMock / MagicMock — no real SSH/SFTP server required.
asyncio_mode = "auto" is set in pyproject.toml so no @pytest.mark.asyncio needed.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spindlex.client.async_sftp_client import AsyncSFTPClient, AsyncSFTPFile
from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import (
    SSH_FX_EOF,
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
    SSH_FX_PERMISSION_DENIED,
)
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPDataMessage,
    SFTPHandleMessage,
    SFTPNameMessage,
    SFTPStatusMessage,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ok_status(request_id: int = 1) -> SFTPStatusMessage:
    return SFTPStatusMessage(request_id, SSH_FX_OK, "OK")


def _make_err_status(
    request_id: int = 1,
    code: int = SSH_FX_NO_SUCH_FILE,
    msg: str = "no such file",
) -> SFTPStatusMessage:
    return SFTPStatusMessage(request_id, code, msg)


def _make_handle_msg(
    request_id: int = 1, handle: bytes = b"async_handle"
) -> SFTPHandleMessage:
    return SFTPHandleMessage(request_id, handle)


def _make_attrs_msg(request_id: int = 1) -> SFTPAttrsMessage:
    attrs = SFTPAttributes()
    attrs.size = 512
    return SFTPAttrsMessage(request_id, attrs)


def _make_name_msg(
    request_id: int = 1,
    names: list[tuple[str, str, SFTPAttributes]] | None = None,
) -> SFTPNameMessage:
    if names is None:
        names = [("/home/user", "/home/user", SFTPAttributes())]
    return SFTPNameMessage(request_id, names)


def _make_data_msg(request_id: int = 1, data: bytes = b"data") -> SFTPDataMessage:
    return SFTPDataMessage(request_id, data)


def _make_async_client() -> AsyncSFTPClient:
    """
    Create an AsyncSFTPClient with a mocked channel.
    _send_message and _wait_for_response are mocked to avoid real I/O.
    """
    channel = MagicMock()
    channel.closed = False
    channel.send = AsyncMock()
    channel.recv_exactly = AsyncMock()
    channel.close = AsyncMock()

    client = AsyncSFTPClient(channel)
    # Mark as initialized so _initialize() is skipped in tests that call it
    client._initialized = True
    # Patch I/O helpers
    client._send_message = AsyncMock()
    client._wait_for_response = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# AsyncSFTPClient.__init__
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientInit:
    def test_initial_state(self):
        channel = MagicMock()
        channel.closed = False
        client = AsyncSFTPClient(channel)
        assert client._channel is channel
        assert client._request_id == 0
        assert client._initialized is False
        assert client._dispatch_task is None
        assert isinstance(client._pending_requests, dict)


# ---------------------------------------------------------------------------
# AsyncSFTPClient._get_next_request_id
# ---------------------------------------------------------------------------


class TestAsyncGetNextRequestId:
    def test_increments_sequentially(self):
        client = _make_async_client()
        client._request_id = 0
        assert client._get_next_request_id() == 1
        assert client._get_next_request_id() == 2
        assert client._get_next_request_id() == 3

    def test_wraps_at_32bit(self):
        client = _make_async_client()
        client._request_id = 0xFFFFFFFF
        assert client._get_next_request_id() == 0


# ---------------------------------------------------------------------------
# AsyncSFTPClient._mode_to_flags
# ---------------------------------------------------------------------------


class TestAsyncModeToFlags:
    def test_read_mode(self):
        from spindlex.protocol.sftp_constants import SSH_FXF_READ

        client = _make_async_client()
        flags = client._mode_to_flags("r")
        assert flags & SSH_FXF_READ

    def test_write_mode(self):
        from spindlex.protocol.sftp_constants import (
            SSH_FXF_CREAT,
            SSH_FXF_TRUNC,
            SSH_FXF_WRITE,
        )

        client = _make_async_client()
        flags = client._mode_to_flags("w")
        assert flags & SSH_FXF_WRITE
        assert flags & SSH_FXF_CREAT
        assert flags & SSH_FXF_TRUNC

    def test_append_mode(self):
        from spindlex.protocol.sftp_constants import (
            SSH_FXF_APPEND,
            SSH_FXF_CREAT,
            SSH_FXF_WRITE,
        )

        client = _make_async_client()
        flags = client._mode_to_flags("a")
        assert flags & SSH_FXF_WRITE
        assert flags & SSH_FXF_CREAT
        assert flags & SSH_FXF_APPEND

    def test_exclusive_mode(self):
        from spindlex.protocol.sftp_constants import (
            SSH_FXF_CREAT,
            SSH_FXF_EXCL,
            SSH_FXF_WRITE,
        )

        client = _make_async_client()
        flags = client._mode_to_flags("x")
        assert flags & SSH_FXF_WRITE
        assert flags & SSH_FXF_CREAT
        assert flags & SSH_FXF_EXCL


# ---------------------------------------------------------------------------
# AsyncSFTPClient.open
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientOpen:
    async def test_open_read_returns_file(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg(handle=b"fh_r")
        f = await client.open("/remote/file.txt", "r")
        assert isinstance(f, AsyncSFTPFile)
        assert f._handle == b"fh_r"

    async def test_open_write_returns_file(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg(handle=b"fh_w")
        f = await client.open("/remote/file.txt", "w")
        assert isinstance(f, AsyncSFTPFile)

    async def test_open_status_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            await client.open("/remote/file.txt", "r")

    async def test_open_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_attrs_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.open("/remote/file.txt", "r")


# ---------------------------------------------------------------------------
# AsyncSFTPClient.stat
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientStat:
    async def test_stat_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_attrs_msg()
        result = await client.stat("/some/file.txt")
        assert isinstance(result, SFTPAttributes)

    async def test_stat_status_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            await client.stat("/nonexistent")

    async def test_stat_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.stat("/some/file.txt")


# ---------------------------------------------------------------------------
# AsyncSFTPClient.mkdir / rmdir
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientMkdirRmdir:
    async def test_mkdir_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_ok_status()
        await client.mkdir("/new/dir")

    async def test_mkdir_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            await client.mkdir("/forbidden/dir")

    async def test_mkdir_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.mkdir("/new/dir")

    async def test_rmdir_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_ok_status()
        await client.rmdir("/old/dir")

    async def test_rmdir_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            await client.rmdir("/nonexistent/dir")

    async def test_rmdir_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.rmdir("/old/dir")


# ---------------------------------------------------------------------------
# AsyncSFTPClient.remove
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientRemove:
    async def test_remove_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_ok_status()
        await client.remove("/file.txt")

    async def test_remove_not_found_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            await client.remove("/nonexistent.txt")

    async def test_remove_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.remove("/file.txt")


# ---------------------------------------------------------------------------
# AsyncSFTPClient.rename
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientRename:
    async def test_rename_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_ok_status()
        await client.rename("/old.txt", "/new.txt")

    async def test_rename_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            await client.rename("/old.txt", "/new.txt")

    async def test_rename_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.rename("/old.txt", "/new.txt")


# ---------------------------------------------------------------------------
# AsyncSFTPClient.chmod
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientChmod:
    async def test_chmod_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_ok_status()
        await client.chmod("/file.txt", 0o755)

    async def test_chmod_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            await client.chmod("/file.txt", 0o755)

    async def test_chmod_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.chmod("/file.txt", 0o755)


# ---------------------------------------------------------------------------
# AsyncSFTPClient.normalize
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientNormalize:
    async def test_normalize_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_name_msg(
            names=[("/abs/path", "/abs/path", SFTPAttributes())]
        )
        result = await client.normalize("/rel/path")
        assert result == "/abs/path"

    async def test_normalize_empty_names_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = SFTPNameMessage(1, [])
        with pytest.raises(SFTPError, match="Empty"):
            await client.normalize("/some/path")

    async def test_normalize_status_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            await client.normalize("/nonexistent")

    async def test_normalize_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.normalize("/some/path")


# ---------------------------------------------------------------------------
# AsyncSFTPClient.listdir
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientListdir:
    async def test_listdir_returns_names(self):
        client = _make_async_client()
        attrs = SFTPAttributes()
        # _opendir, _readdir (entries), _readdir (EOF), _close
        _make_handle_msg(handle=b"dir_h")
        SFTPNameMessage(
            1,
            [
                (".", ".", attrs),
                ("..", "..", attrs),
                ("file1.txt", "file1.txt", attrs),
            ],
        )
        SFTPError("EOF", SSH_FX_EOF)
        _make_ok_status()

        # _opendir calls _wait_for_response once, then _readdir calls it
        # We patch the private helpers for simplicity
        async def mock_opendir(path: str) -> bytes:
            return b"dir_h"

        async def mock_readdir(handle: bytes) -> list:
            # Return list first call, raise EOF second
            if not hasattr(mock_readdir, "_called"):
                mock_readdir._called = True
                return [
                    (".", ".", attrs),
                    ("..", "..", attrs),
                    ("file1.txt", "file1.txt", attrs),
                ]
            raise SFTPError("EOF", SSH_FX_EOF)

        async def mock_close(handle: bytes) -> None:
            pass

        client._opendir = mock_opendir
        client._readdir = mock_readdir
        client._close = mock_close

        result = await client.listdir("/some/dir")
        assert result == ["file1.txt"]

    async def test_listdir_error_propagates(self):
        client = _make_async_client()

        async def mock_opendir(path: str) -> bytes:
            raise SFTPError("No such directory", SSH_FX_NO_SUCH_FILE)

        client._opendir = mock_opendir
        with pytest.raises(SFTPError):
            await client.listdir("/nonexistent")


# ---------------------------------------------------------------------------
# AsyncSFTPClient._opendir / _readdir / _close (internal helpers)
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientInternalHelpers:
    async def test_opendir_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg(handle=b"dir_handle")
        handle = await client._opendir("/some/dir")
        assert handle == b"dir_handle"

    async def test_opendir_status_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_NO_SUCH_FILE
        )
        with pytest.raises(SFTPError):
            await client._opendir("/nonexistent")

    async def test_opendir_unexpected_response_raises(self):
        client = _make_async_client()
        # An SFTPAttrsMessage is not a handle or status, so it triggers the
        # "Unexpected response" branch in _opendir
        client._wait_for_response.return_value = _make_attrs_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client._opendir("/some/dir")

    async def test_readdir_returns_names(self):
        client = _make_async_client()
        attrs = SFTPAttributes()
        names = [("file.txt", "file.txt", attrs)]
        client._wait_for_response.return_value = SFTPNameMessage(1, names)
        result = await client._readdir(b"dir_handle")
        assert result == names

    async def test_readdir_eof_returns_empty(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(code=SSH_FX_EOF)
        result = await client._readdir(b"dir_handle")
        assert result == []

    async def test_readdir_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            await client._readdir(b"dir_handle")

    async def test_readdir_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client._readdir(b"dir_handle")

    async def test_close_success(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_ok_status()
        await client._close(b"some_handle")  # should not raise

    async def test_close_error_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(code=SSH_FX_FAILURE)
        with pytest.raises(SFTPError):
            await client._close(b"some_handle")

    async def test_close_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client._close(b"some_handle")


# ---------------------------------------------------------------------------
# AsyncSFTPClient.get / put (high-level)
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientGetPut:
    async def test_get_success(self, tmp_path):
        client = _make_async_client()
        local = str(tmp_path / "downloaded.txt")

        mock_file = MagicMock(spec=AsyncSFTPFile)
        mock_file.read = AsyncMock(side_effect=[b"content", b""])
        mock_file.close = AsyncMock()

        async def mock_open(path, mode="r"):
            return mock_file

        client.open = mock_open
        await client.get("/remote/file.txt", local)

        with open(local, "rb") as fh:
            assert fh.read() == b"content"

    async def test_put_success(self, tmp_path):
        client = _make_async_client()
        local = tmp_path / "upload.txt"
        local.write_bytes(b"upload data")

        mock_file = MagicMock(spec=AsyncSFTPFile)
        mock_file.write = AsyncMock()
        mock_file.close = AsyncMock()

        async def mock_open(path, mode="r"):
            return mock_file

        client.open = mock_open
        await client.put(str(local), "/remote/upload.txt")
        mock_file.write.assert_called()
        mock_file.close.assert_called_once()

    async def test_get_propagates_sftp_error(self, tmp_path):
        client = _make_async_client()
        local = str(tmp_path / "dl.txt")

        async def mock_open(path, mode="r"):
            raise SFTPError("File not found", SSH_FX_NO_SUCH_FILE)

        client.open = mock_open
        with pytest.raises(SFTPError):
            await client.get("/nonexistent.txt", local)

    async def test_put_propagates_sftp_error(self, tmp_path):
        client = _make_async_client()
        local = tmp_path / "upload.txt"
        local.write_bytes(b"data")

        async def mock_open(path, mode="r"):
            raise SFTPError("Permission denied", SSH_FX_PERMISSION_DENIED)

        client.open = mock_open
        with pytest.raises(SFTPError):
            await client.put(str(local), "/remote/upload.txt")


# ---------------------------------------------------------------------------
# AsyncSFTPClient.close / context manager
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientClose:
    async def test_close_cancels_dispatch_task(self):
        client = _make_async_client()

        # Create a real task that runs forever so we can cancel it
        async def _forever():
            try:
                await asyncio.sleep(9999)
            except asyncio.CancelledError:
                pass

        client._dispatch_task = asyncio.ensure_future(_forever())
        channel = client._channel
        await client.close()
        assert client._dispatch_task is None
        assert client._channel is None
        channel.close.assert_called_once()

    async def test_close_no_channel(self):
        client = _make_async_client()
        client._channel = None
        await client.close()  # should not raise

    async def test_close_clears_pending_requests(self):
        client = _make_async_client()
        fut = asyncio.get_running_loop().create_future()
        client._pending_requests[99] = fut
        await client.close()
        assert client._pending_requests == {}

    async def test_context_manager(self):
        client = _make_async_client()
        channel = client._channel
        async with client:
            pass
        channel.close.assert_called_once()

    async def test_context_manager_closes_on_exception(self):
        client = _make_async_client()
        channel = client._channel
        with pytest.raises(RuntimeError):
            async with client:
                raise RuntimeError("test error")
        channel.close.assert_called_once()


# ---------------------------------------------------------------------------
# AsyncSFTPFile class
# ---------------------------------------------------------------------------


class TestAsyncSFTPFile:
    def _make_file(
        self, handle: bytes = b"fh", mode: str = "r"
    ) -> tuple[AsyncSFTPFile, AsyncSFTPClient]:
        client = _make_async_client()
        f = AsyncSFTPFile(client, handle, mode)
        return f, client

    # --- __init__ ---

    def test_init_attributes(self):
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"myhandle", "rb")
        assert f._handle == b"myhandle"
        assert f._mode == "rb"
        assert f._offset == 0
        assert f._closed is False
        assert f._client is client

    # --- read ---

    async def test_read_raises_when_closed(self):
        f, _ = self._make_file()
        f._closed = True
        with pytest.raises(SFTPError, match="closed"):
            await f.read(10)

    async def test_read_returns_data(self):
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_data_msg(data=b"hello")
        result = await f.read(5)
        assert result == b"hello"
        assert f._offset == 5

    async def test_read_eof_returns_empty(self):
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_err_status(code=SSH_FX_EOF)
        result = await f.read(100)
        assert result == b""

    async def test_read_error_raises(self):
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_PERMISSION_DENIED
        )
        with pytest.raises(SFTPError):
            await f.read(10)

    async def test_read_unexpected_response_raises(self):
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await f.read(10)

    async def test_read_default_size(self):
        """read() with no size arg should use 32768."""
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_data_msg(data=b"x")
        await f.read()
        # Verify read was attempted (offset advanced)
        assert f._offset == 1

    # --- write ---

    async def test_write_raises_when_closed(self):
        f, _ = self._make_file(mode="w")
        f._closed = True
        with pytest.raises(SFTPError, match="closed"):
            await f.write(b"data")

    async def test_write_success_advances_offset(self):
        f, client = self._make_file(mode="w")
        client._wait_for_response.return_value = _make_ok_status()
        await f.write(b"hello world")
        assert f._offset == 11

    async def test_write_error_raises(self):
        f, client = self._make_file(mode="w")
        client._wait_for_response.return_value = _make_err_status(code=SSH_FX_FAILURE)
        with pytest.raises(SFTPError):
            await f.write(b"data")

    async def test_write_unexpected_response_raises(self):
        f, client = self._make_file(mode="w")
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await f.write(b"data")

    # --- close ---

    async def test_close_marks_closed(self):
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_ok_status()
        await f.close()
        assert f._closed is True

    async def test_close_idempotent(self):
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_ok_status()
        await f.close()
        await f.close()
        # Only one close request sent
        assert client._send_message.call_count == 1

    async def test_close_ignores_errors(self):
        """close() must not raise even if the underlying call fails."""
        f, client = self._make_file()
        client._send_message.side_effect = Exception("channel broken")
        await f.close()  # should not raise
        assert f._closed is True

    # --- async context manager ---

    async def test_async_context_manager_closes(self):
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_ok_status()
        async with f:
            assert f._closed is False
        assert f._closed is True

    async def test_async_context_manager_closes_on_exception(self):
        f, client = self._make_file()
        client._wait_for_response.return_value = _make_ok_status()
        with pytest.raises(ValueError):
            async with f:
                raise ValueError("oops")
        assert f._closed is True


# ---------------------------------------------------------------------------
# AsyncSFTPClient._initialize
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientInitialize:
    async def test_initialize_already_done_is_noop(self):
        client = _make_async_client()
        client._initialized = True
        # _send_message should NOT be called
        await client._initialize()
        client._send_message.assert_not_called()

    async def test_initialize_success(self):
        """_initialize should set _initialized = True on success."""
        from spindlex.protocol.sftp_messages import SFTPVersionMessage

        channel = MagicMock()
        channel.closed = False
        channel.send = AsyncMock()
        channel.recv_exactly = AsyncMock()
        channel.close = AsyncMock()

        client = AsyncSFTPClient(channel)
        assert not client._initialized

        version_msg = SFTPVersionMessage(3, {})

        # Patch _send_message to do nothing
        client._send_message = AsyncMock()

        # Simulate the dispatcher resolving the future with a version message
        async def patch_initialize():
            # Manually set result on pending future before awaiting
            client._initialized = False
            task_started = asyncio.Event()

            async def fake_dispatch():
                task_started.set()
                # Find the -1 future and resolve it
                for _ in range(100):
                    await asyncio.sleep(0)
                    if -1 in client._pending_requests:
                        fut = client._pending_requests[-1]
                        if not fut.done():
                            fut.set_result(version_msg)
                        break

            with patch(
                "asyncio.create_task",
                side_effect=lambda coro: asyncio.ensure_future(coro),
            ):
                # Replace dispatch loop with one that immediately resolves version future
                client._dispatch_loop = fake_dispatch
                with patch.object(
                    asyncio,
                    "create_task",
                    side_effect=lambda coro: asyncio.ensure_future(coro),
                ):
                    pass

            # Directly: set the future without running the dispatcher
            async def run_init():
                client._initialized = False
                # We'll manually populate the pending request before the future is awaited
                init_task = asyncio.ensure_future(client._initialize())
                # Give initialize a tick to register the future
                await asyncio.sleep(0)
                await asyncio.sleep(0)
                if -1 in client._pending_requests:
                    client._pending_requests[-1].set_result(version_msg)
                await init_task

            await run_init()

        await patch_initialize()
        assert client._initialized is True
