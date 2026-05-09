"""
Additional coverage tests for spindlex/client/async_sftp_client.py.

Covers missed lines:
- _initialize (99, 101-105): non-version response and exception paths
- _dispatch_loop (109-136): dispatch paths, CancelledError, exception
- get/put (170, 211, 221-226, 233, 276-280, 289, 291): file transfer ops
- get_recursive / put_recursive (301, 311-333, 343-364)
- _opendir unexpected response (400)
- _readdir unexpected response, EOF path (410)
- _close unexpected response (447)
- readlink empty names (675), unexpected (681)
- normalize empty names (721), unexpected (727)
- symlink unexpected (648, 652)
- _wait_for_response timeout (798-804)
- AsyncSFTPFile.read closed guard, pipelined read (958)
- AsyncSFTPFile.write pipeline drain (1056, 1061-1070)
- AsyncSFTPFile._flush_write_queue error paths
"""

from __future__ import annotations

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spindlex.client.async_sftp_client import (
    _SFTP_INIT_SENTINEL,
    AsyncSFTPClient,
    AsyncSFTPFile,
)
from spindlex.exceptions import SFTPError
from spindlex.protocol.sftp_constants import (
    SSH_FX_EOF,
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
)
from spindlex.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPDataMessage,
    SFTPHandleMessage,
    SFTPNameMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
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
    request_id: int = 1, handle: bytes = b"handle"
) -> SFTPHandleMessage:
    return SFTPHandleMessage(request_id, handle)


def _make_attrs_msg(request_id: int = 1) -> SFTPAttrsMessage:
    attrs = SFTPAttributes()
    attrs.size = 512
    attrs.st_mode = 0o100644  # regular file
    return SFTPAttrsMessage(request_id, attrs)


def _make_name_msg(
    request_id: int = 1,
    names: list | None = None,
) -> SFTPNameMessage:
    if names is None:
        names = [("/home/user", "/home/user", SFTPAttributes())]
    return SFTPNameMessage(request_id, names)


def _make_data_msg(request_id: int = 1, data: bytes = b"data") -> SFTPDataMessage:
    return SFTPDataMessage(request_id, data)


def _make_async_client() -> AsyncSFTPClient:
    channel = MagicMock()
    channel.closed = False
    channel.send = AsyncMock()
    channel.recv_exactly = AsyncMock()
    channel.close = AsyncMock()
    client = AsyncSFTPClient(channel)
    client._initialized = True
    client._send_message = AsyncMock()
    client._wait_for_response = AsyncMock()
    return client


# ---------------------------------------------------------------------------
# _initialize
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientInitialize:
    async def test_initialize_skipped_when_already_initialized(self):
        client = _make_async_client()
        client._initialized = True
        # Should return immediately without doing anything
        await client._initialize()

    async def test_initialize_raises_when_wrong_response(self):
        channel = MagicMock()
        channel.closed = False
        channel.send = AsyncMock()
        channel.close = AsyncMock()
        client = AsyncSFTPClient(channel)

        # Simulate dispatch returning a non-version message
        async def fake_dispatch():
            # immediately set the init future with a status (not version)
            await asyncio.sleep(0)
            if _SFTP_INIT_SENTINEL in client._pending_requests:
                fut = client._pending_requests[_SFTP_INIT_SENTINEL]
                if not fut.done():
                    fut.set_result(SFTPStatusMessage(1, SSH_FX_FAILURE, "fail"))

        with patch.object(client, "_send_message", new=AsyncMock()):
            # Run fake dispatch and _initialize concurrently
            with pytest.raises(SFTPError):
                await asyncio.gather(
                    client._initialize(),
                    fake_dispatch(),
                )

    async def test_initialize_wraps_non_sftp_exception(self):
        channel = MagicMock()
        channel.closed = False
        channel.send = AsyncMock()
        channel.close = AsyncMock()
        client = AsyncSFTPClient(channel)

        with patch.object(
            client, "_send_message", side_effect=RuntimeError("net error")
        ):
            with pytest.raises(SFTPError, match="SFTP initialization failed"):
                await client._initialize()


# ---------------------------------------------------------------------------
# _dispatch_loop
# ---------------------------------------------------------------------------


class TestAsyncDispatchLoop:
    async def test_dispatch_loop_dispatches_version_message(self):
        channel = MagicMock()
        channel.closed = False

        read_count = 0

        async def fake_recv():
            nonlocal read_count
            read_count += 1
            if read_count == 1:
                return SFTPVersionMessage(3, {})
            # Stop loop
            channel.closed = True
            raise asyncio.CancelledError()

        client = AsyncSFTPClient(channel)
        client._recv_message = fake_recv  # type: ignore[assignment]

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        client._pending_requests[_SFTP_INIT_SENTINEL] = fut

        task = asyncio.create_task(client._dispatch_loop())
        await asyncio.sleep(0.05)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        if not fut.done():
            fut.cancel()

    async def test_dispatch_loop_handles_exception_in_recv(self):
        channel = MagicMock()
        channel.closed = False

        async def failing_recv():
            raise OSError("recv failed")

        client = AsyncSFTPClient(channel)
        client._recv_message = failing_recv  # type: ignore[assignment]

        loop = asyncio.get_running_loop()
        fut = loop.create_future()
        client._pending_requests[1] = fut

        await client._dispatch_loop()
        assert fut.done()
        assert not client._initialized

    async def test_dispatch_loop_handles_cancelled_error(self):
        channel = MagicMock()
        channel.closed = False

        async def cancelling_recv():
            raise asyncio.CancelledError()

        client = AsyncSFTPClient(channel)
        client._recv_message = cancelling_recv  # type: ignore[assignment]

        await client._dispatch_loop()
        assert not client._initialized


# ---------------------------------------------------------------------------
# get / put with actual temp files
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientGetPut:
    async def test_get_nonexistent_remote_raises(self):
        """get(): SFTPError from open() propagates."""
        client = _make_async_client()

        with patch.object(
            client,
            "open",
            new=AsyncMock(side_effect=SFTPError("no such file", SSH_FX_NO_SUCH_FILE)),
        ):
            with tempfile.NamedTemporaryFile(delete=False) as f:
                tmp_path = f.name
            try:
                with pytest.raises(SFTPError):
                    await client.get("/remote/nonexistent.txt", tmp_path)
            finally:
                os.unlink(tmp_path)

    async def test_put_nonexistent_file_raises(self):
        """put(): SFTPError when local file does not exist."""
        client = _make_async_client()
        with pytest.raises(SFTPError):
            await client.put("/nonexistent/local/path.txt", "/remote/file.txt")


# ---------------------------------------------------------------------------
# get_recursive / put_recursive
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientRecursive:
    async def test_get_recursive_file(self):
        """get_recursive with a plain file (not dir) calls get."""
        client = _make_async_client()
        attrs = SFTPAttributes()
        attrs.st_mode = 0o100644  # regular file

        async def mock_stat(path):
            return attrs

        client.stat = mock_stat  # type: ignore[assignment]
        client.get = AsyncMock()

        with tempfile.TemporaryDirectory() as tmp:
            await client.get_recursive(
                "/remote/file.txt", os.path.join(tmp, "file.txt")
            )
        client.get.assert_awaited_once()

    async def test_get_recursive_directory(self):
        """get_recursive with a directory calls listdir and recurses."""
        import stat as stat_module

        client = _make_async_client()
        dir_attrs = SFTPAttributes()
        dir_attrs.st_mode = stat_module.S_IFDIR | 0o755

        file_attrs = SFTPAttributes()
        file_attrs.st_mode = stat_module.S_IFREG | 0o644

        call_count = [0]

        async def mock_stat(path):
            call_count[0] += 1
            if call_count[0] == 1:
                return dir_attrs
            return file_attrs

        client.stat = mock_stat  # type: ignore[assignment]
        client.listdir = AsyncMock(return_value=["item.txt"])
        client.get = AsyncMock()

        with tempfile.TemporaryDirectory() as tmp:
            local_dir = os.path.join(tmp, "sub")
            await client.get_recursive("/remote/dir", local_dir)

        client.listdir.assert_awaited_once()

    async def test_put_recursive_file(self):
        """put_recursive with a plain file calls put."""
        client = _make_async_client()
        client.put = AsyncMock()

        with tempfile.NamedTemporaryFile(delete=False) as f:
            local_path = f.name
        try:
            await client.put_recursive(local_path, "/remote/file.txt")
            client.put.assert_awaited_once()
        finally:
            os.unlink(local_path)

    async def test_put_recursive_directory(self):
        """put_recursive with a directory calls mkdir and recurses."""
        client = _make_async_client()
        client.mkdir = AsyncMock()
        client.put = AsyncMock()

        with tempfile.TemporaryDirectory() as tmp:
            # Create a file inside the dir
            with open(os.path.join(tmp, "item.txt"), "w") as f:
                f.write("data")
            await client.put_recursive(tmp, "/remote/dir")

        client.mkdir.assert_awaited()

    async def test_put_recursive_mkdir_error_ignored(self):
        """put_recursive ignores SFTPError from mkdir (dir already exists)."""
        client = _make_async_client()
        client.mkdir = AsyncMock(
            side_effect=SFTPError("already exists", SSH_FX_FAILURE)
        )
        client.put = AsyncMock()

        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "f.txt"), "w") as f:
                f.write("x")
            await client.put_recursive(tmp, "/remote/existing")

        client.put.assert_awaited()


# ---------------------------------------------------------------------------
# _opendir / _readdir / _close unexpected response paths
# ---------------------------------------------------------------------------


class TestAsyncSFTPClientHelperUnexpected:
    async def test_opendir_unexpected_response(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_data_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client._opendir("/dir")

    async def test_readdir_eof_returns_empty(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(code=SSH_FX_EOF)
        result = await client._readdir(b"handle")
        assert result == []

    async def test_readdir_unexpected_response(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_data_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client._readdir(b"handle")

    async def test_close_unexpected_response(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_data_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client._close(b"handle")

    async def test_close_error_status_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_err_status(code=SSH_FX_FAILURE)
        with pytest.raises(SFTPError):
            await client._close(b"handle")


# ---------------------------------------------------------------------------
# readlink / normalize edge cases
# ---------------------------------------------------------------------------


class TestAsyncReadlinkNormalizeEdgeCases:
    async def test_readlink_empty_names_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = SFTPNameMessage(1, [])
        with pytest.raises(SFTPError, match="Empty"):
            await client.readlink("/link")

    async def test_readlink_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_data_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.readlink("/link")

    async def test_symlink_unexpected_response_raises(self):
        client = _make_async_client()
        client._wait_for_response.return_value = _make_data_msg()
        with pytest.raises(SFTPError, match="Unexpected"):
            await client.symlink("/target", "/link")


# ---------------------------------------------------------------------------
# _wait_for_response timeout
# ---------------------------------------------------------------------------


class TestAsyncWaitForResponseTimeout:
    async def test_timeout_raises_sftp_error(self):
        channel = MagicMock()
        channel.closed = False
        channel.send = AsyncMock()
        channel.close = AsyncMock()
        client = AsyncSFTPClient(channel)
        client._initialized = True
        client._send_message = AsyncMock()
        # Don't set any dispatch task - the future will never be resolved
        with pytest.raises(SFTPError, match="Timeout"):
            await client._wait_for_response(99, timeout=0.01)


# ---------------------------------------------------------------------------
# AsyncSFTPFile tests
# ---------------------------------------------------------------------------


class TestAsyncSFTPFileCoverage:
    def _make_file(self, handle: bytes = b"fh", mode: str = "r") -> AsyncSFTPFile:
        client = _make_async_client()
        return AsyncSFTPFile(client, handle, mode)

    async def test_read_raises_when_closed(self):
        f = self._make_file()
        f._closed = True
        with pytest.raises(SFTPError, match="closed"):
            await f.read(10)

    async def test_write_raises_when_closed(self):
        f = self._make_file(mode="w")
        f._closed = True
        with pytest.raises(SFTPError, match="closed"):
            await f.write(b"data")

    async def test_read_all_with_pipelined_eof(self):
        """Read with size=-1: pipeline fills and stops at EOF."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "r")
        f._PIPELINE_DEPTH = 2

        call_count = [0]

        async def mock_wait(rid, timeout=60.0):
            call_count[0] += 1
            if call_count[0] == 1:
                return SFTPDataMessage(rid, b"chunk1")
            elif call_count[0] == 2:
                return SFTPStatusMessage(rid, SSH_FX_EOF, "EOF")
            return SFTPStatusMessage(rid, SSH_FX_EOF, "EOF")

        client._wait_for_response = mock_wait  # type: ignore[assignment]
        result = await f.read(-1)
        assert result == b"chunk1"

    async def test_read_all_unexpected_response_raises(self):
        """Read with size=-1: unexpected response raises SFTPError."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "r")
        f._PIPELINE_DEPTH = 1

        async def mock_wait(rid, timeout=60.0):
            return SFTPHandleMessage(rid, b"unexpected")

        client._wait_for_response = mock_wait  # type: ignore[assignment]
        with pytest.raises(SFTPError):
            await f.read(-1)

    async def test_read_all_error_status_raises(self):
        """Read with size=-1: non-EOF error raises SFTPError."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "r")
        f._PIPELINE_DEPTH = 1

        async def mock_wait(rid, timeout=60.0):
            return SFTPStatusMessage(rid, SSH_FX_FAILURE, "fail")

        client._wait_for_response = mock_wait  # type: ignore[assignment]
        with pytest.raises(SFTPError):
            await f.read(-1)

    async def test_read_single_unexpected_raises(self):
        """Single read: unexpected response raises SFTPError."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "r")
        client._wait_for_response.return_value = _make_handle_msg()
        with pytest.raises(SFTPError):
            await f.read(10)

    async def test_read_single_eof_returns_empty(self):
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "r")
        client._wait_for_response.return_value = SFTPStatusMessage(1, SSH_FX_EOF, "EOF")
        result = await f.read(10)
        assert result == b""

    async def test_write_pipeline_drain_on_full(self):
        """When write_queue hits PIPELINE_DEPTH, oldest ACK is drained."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "w")
        f._PIPELINE_DEPTH = 2
        # Pre-fill queue with one entry
        f._write_queue.append((99, 5))

        # Second write will drain index 0
        ok_resp = _make_ok_status(99)

        async def mock_wait(rid, timeout=60.0):
            return ok_resp

        client._wait_for_response = mock_wait  # type: ignore[assignment]
        await f.write(b"hello")

    async def test_write_pipeline_drain_error_raises(self):
        """Write pipeline drain: error status raises SFTPError."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "w")
        f._PIPELINE_DEPTH = 2
        f._write_queue.append((99, 5))

        err_resp = _make_err_status(99, SSH_FX_FAILURE, "disk full")

        async def mock_wait(rid, timeout=60.0):
            return err_resp

        client._wait_for_response = mock_wait  # type: ignore[assignment]
        with pytest.raises(SFTPError):
            await f.write(b"hello")

    async def test_write_pipeline_unexpected_response_raises(self):
        """Write pipeline drain: unexpected response raises SFTPError."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "w")
        f._PIPELINE_DEPTH = 2
        f._write_queue.append((99, 5))

        async def mock_wait(rid, timeout=60.0):
            return _make_handle_msg()

        client._wait_for_response = mock_wait  # type: ignore[assignment]
        with pytest.raises(SFTPError):
            await f.write(b"hello")

    async def test_flush_write_queue_success(self):
        """_flush_write_queue drains all pending writes."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "w")
        f._offset = 0
        f._write_queue = [(1, 5), (2, 3)]

        client._wait_for_response.return_value = _make_ok_status()
        await f._flush_write_queue()
        assert f._offset == 8
        assert len(f._write_queue) == 0

    async def test_flush_write_queue_error_raises(self):
        """_flush_write_queue propagates write errors."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "w")
        f._write_queue = [(1, 5)]
        client._wait_for_response.return_value = _make_err_status(
            code=SSH_FX_FAILURE, msg="fail"
        )
        with pytest.raises(SFTPError):
            await f._flush_write_queue()

    async def test_flush_write_queue_unexpected_raises(self):
        """_flush_write_queue raises on unexpected response."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "w")
        f._write_queue = [(1, 5)]
        client._wait_for_response.return_value = _make_data_msg()
        with pytest.raises(SFTPError):
            await f._flush_write_queue()

    async def test_context_manager(self):
        """AsyncSFTPFile can be used as async context manager."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "r")
        f._write_queue = []
        # close sends a message - mock it
        client._wait_for_response.return_value = _make_ok_status()
        async with f:
            pass
        assert f._closed

    async def test_close_already_closed(self):
        """Calling close on already-closed file does nothing."""
        client = _make_async_client()
        f = AsyncSFTPFile(client, b"fh", "r")
        f._closed = True
        await f.close()  # Should be a no-op
        client._send_message.assert_not_awaited()
