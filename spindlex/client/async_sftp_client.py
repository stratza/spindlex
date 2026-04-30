"""
Async SFTP Client Implementation

Provides asynchronous SFTP client functionality for file operations.
"""

import asyncio
import os
import struct
from typing import Any, Optional

from ..exceptions import SFTPError
from ..protocol.sftp_constants import (
    SFTP_VERSION,
    SSH_FILEXFER_ATTR_PERMISSIONS,
    SSH_FX_EOF,
    SSH_FX_OK,
    SSH_FXF_APPEND,
    SSH_FXF_CREAT,
    SSH_FXF_EXCL,
    SSH_FXF_READ,
    SSH_FXF_TRUNC,
    SSH_FXF_WRITE,
)
from ..protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPCloseMessage,
    SFTPDataMessage,
    SFTPHandleMessage,
    SFTPInitMessage,
    SFTPMessage,
    SFTPMkdirMessage,
    SFTPNameMessage,
    SFTPOpenDirMessage,
    SFTPOpenMessage,
    SFTPReadDirMessage,
    SFTPReadMessage,
    SFTPRealPathMessage,
    SFTPRenameMessage,
    SFTPRmdirMessage,
    SFTPSetStatMessage,
    SFTPStatMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
    SFTPWriteMessage,
)

# Sentinel key for the init VERSION response — intentionally outside uint32 range
_SFTP_INIT_SENTINEL: int = -2


class AsyncSFTPClient:
    """
    Async SFTP client for file transfer operations.

    Provides asynchronous versions of all SFTP operations for use
    in async/await applications and high-concurrency scenarios.
    """

    def __init__(self, channel: Any) -> None:
        """
        Initialize async SFTP client.

        Args:
            channel: SSH channel for SFTP subsystem
        """
        self._channel = channel
        self._request_id = 0
        self._pending_requests: dict[int, asyncio.Future] = {}
        self._initialized = False
        self._dispatch_task: Optional[asyncio.Task] = None
        self._lock = asyncio.Lock()

    async def _initialize(self) -> None:
        """Initialize SFTP subsystem."""
        if self._initialized:
            return

        # Start dispatcher task
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())

        # Send SFTP init message
        init_msg = SFTPInitMessage(version=SFTP_VERSION)
        await self._send_message(init_msg)

        # Wait for version response (special case in dispatcher uses ID -2)
        fut = asyncio.get_running_loop().create_future()
        self._pending_requests[_SFTP_INIT_SENTINEL] = fut

        try:
            response = await fut
            if not isinstance(response, SFTPVersionMessage):
                raise SFTPError("Expected SFTP version message")
            self._initialized = True
        except Exception as e:
            await self.close()
            raise SFTPError(f"SFTP initialization failed: {e}") from e

    async def _dispatch_loop(self) -> None:
        """Background loop to receive and dispatch SFTP messages."""
        try:
            while self._channel and not self._channel.closed:
                try:
                    response = await self._recv_message()

                    # SSH_FXP_VERSION doesn't have request_id in protocol but our class might handle it
                    # In SFTP protocol, VERSION is the only one without ID
                    request_id: Optional[int]
                    if isinstance(response, SFTPVersionMessage):
                        request_id = _SFTP_INIT_SENTINEL
                    else:
                        request_id = getattr(response, "request_id", None)

                    if request_id is not None and request_id in self._pending_requests:
                        fut = self._pending_requests.pop(request_id)
                        if not fut.done():
                            fut.set_result(response)
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    # Cancel all pending requests on error
                    for fut in list(self._pending_requests.values()):
                        if not fut.done():
                            fut.set_exception(e)
                    self._pending_requests.clear()
                    break
        finally:
            self._initialized = False

    async def remove(self, path: str) -> None:
        """
        Remove remote file asynchronously.

        Args:
            path: Remote file path to remove

        Raises:
            SFTPError: If removal fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPRemoveMessage

            # Send remove request
            remove_msg = SFTPRemoveMessage(request_id=request_id, filename=path)
            await self._send_message(remove_msg)

            # Wait for response
            response = await self._wait_for_response(request_id)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError(
                        f"File removal failed: {response.message}", response.status_code
                    )
            else:
                raise SFTPError("Unexpected response to remove request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File removal failed: {e}") from e

    async def get(self, remotepath: str, localpath: str) -> None:
        """
        Download file from remote server asynchronously.

        Args:
            remotepath: Remote file path
            localpath: Local file path

        Raises:
            SFTPError: If download fails
        """
        _CHUNK = 32768
        _WINDOW = 32
        try:
            remote_file = await self.open(remotepath, "rb")
            try:
                loop = asyncio.get_running_loop()
                with open(localpath, "wb") as local_file:
                    offset = 0
                    inflight: list[asyncio.Future] = []
                    done = False

                    while not done or inflight:
                        # Fill pipeline up to window size
                        while not done and len(inflight) < _WINDOW:
                            req_id = self._get_next_request_id()
                            fut: asyncio.Future = loop.create_future()
                            self._pending_requests[req_id] = fut
                            msg = SFTPReadMessage(
                                request_id=req_id,
                                handle=remote_file._handle,
                                offset=offset,
                                length=_CHUNK,
                            )
                            await self._send_message(msg)
                            inflight.append(fut)
                            offset += _CHUNK

                        if not inflight:
                            break

                        # Drain oldest in-order
                        response = await inflight.pop(0)
                        if isinstance(response, SFTPDataMessage):
                            local_file.write(response.data)
                        elif isinstance(response, SFTPStatusMessage):
                            if response.status_code == SSH_FX_EOF:
                                done = True
                            else:
                                raise SFTPError(
                                    f"Read failed: {response.message}",
                                    response.status_code,
                                )
                        else:
                            raise SFTPError("Unexpected response to read request")
            finally:
                await remote_file.close()

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File download failed: {e}") from e

    async def put(self, localpath: str, remotepath: str) -> None:
        """
        Upload file to remote server asynchronously.

        Args:
            localpath: Local file path
            remotepath: Remote file path

        Raises:
            SFTPError: If upload fails
        """
        _CHUNK = 32768
        _WINDOW = 32
        try:
            remote_file = await self.open(remotepath, "wb")
            try:
                loop = asyncio.get_running_loop()
                with open(localpath, "rb") as local_file:
                    offset = 0
                    inflight: list[asyncio.Future] = []

                    while True:
                        chunk = local_file.read(_CHUNK)
                        if not chunk:
                            break

                        req_id = self._get_next_request_id()
                        fut: asyncio.Future = loop.create_future()
                        self._pending_requests[req_id] = fut
                        msg = SFTPWriteMessage(
                            request_id=req_id,
                            handle=remote_file._handle,
                            offset=offset,
                            data=chunk,
                        )
                        await self._send_message(msg)
                        inflight.append(fut)
                        offset += len(chunk)

                        # Drain when window is full
                        while len(inflight) >= _WINDOW:
                            response = await inflight.pop(0)
                            if not isinstance(response, SFTPStatusMessage):
                                raise SFTPError("Unexpected response to write request")
                            if response.status_code != SSH_FX_OK:
                                raise SFTPError(
                                    f"Write failed: {response.message}",
                                    response.status_code,
                                )

                    # Drain remaining inflight
                    for fut in inflight:
                        response = await fut
                        if not isinstance(response, SFTPStatusMessage):
                            raise SFTPError("Unexpected response to write request")
                        if response.status_code != SSH_FX_OK:
                            raise SFTPError(
                                f"Write failed: {response.message}",
                                response.status_code,
                            )
            finally:
                await remote_file.close()

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File upload failed: {e}") from e

    async def get_recursive(self, remotepath: str, localpath: str) -> None:
        """
        Download directory recursively and asynchronously.

        Args:
            remotepath: Remote directory path
            localpath: Local destination path
        """
        import stat

        attrs = await self.stat(remotepath)
        if not stat.S_ISDIR(attrs.st_mode):
            await self.get(remotepath, localpath)
            return

        if not os.path.exists(localpath):
            os.makedirs(localpath)

        items = await self.listdir(remotepath)
        tasks = []
        for item in items:
            remote_item = (
                f"{remotepath}/{item}"
                if not remotepath.endswith("/")
                else f"{remotepath}{item}"
            )
            local_item = os.path.join(localpath, item)
            tasks.append(self.get_recursive(remote_item, local_item))

        if tasks:
            await asyncio.gather(*tasks)

    async def put_recursive(self, localpath: str, remotepath: str) -> None:
        """
        Upload directory recursively and asynchronously.

        Args:
            localpath: Local directory path
            remotepath: Remote destination path
        """
        if not os.path.isdir(localpath):
            await self.put(localpath, remotepath)
            return

        try:
            await self.mkdir(remotepath)
        except SFTPError:
            pass  # Directory might already exist

        items = os.listdir(localpath)
        tasks = []
        for item in items:
            local_item = os.path.join(localpath, item)
            remote_item = (
                f"{remotepath}/{item}"
                if not remotepath.endswith("/")
                else f"{remotepath}{item}"
            )
            tasks.append(self.put_recursive(local_item, remote_item))

        if tasks:
            await asyncio.gather(*tasks)

    async def listdir(self, path: str = ".") -> list[str]:
        """
        List directory contents asynchronously.

        Args:
            path: Directory path to list

        Returns:
            List of filenames in directory

        Raises:
            SFTPError: If listing fails
        """
        try:
            # Open directory handle
            handle = await self._opendir(path)

            filenames = []

            # Read directory entries
            while True:
                try:
                    entries = await self._readdir(handle)
                    if not entries:
                        break

                    for entry in entries:
                        filename = entry[0]
                        if filename not in (".", ".."):
                            filenames.append(filename)

                except SFTPError as e:
                    if e.status_code == SSH_FX_EOF:
                        break
                    raise

            # Close directory handle
            await self._close(handle)

            return filenames

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Directory listing failed: {e}") from e

    async def stat(self, path: str) -> Any:
        """
        Get file/directory attributes asynchronously.

        Args:
            path: File or directory path

        Returns:
            File attributes

        Raises:
            SFTPError: If stat fails
        """
        try:
            request_id = self._get_next_request_id()

            # Send stat request
            stat_msg = SFTPStatMessage(request_id=request_id, path=path)
            await self._send_message(stat_msg)

            # Wait for response
            response = await self._wait_for_response(request_id)

            if isinstance(response, SFTPAttrsMessage):
                return response.attrs
            elif isinstance(response, SFTPStatusMessage):
                raise SFTPError(
                    f"Stat failed: {response.message}", response.status_code
                )
            else:
                raise SFTPError("Unexpected response to stat request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Stat operation failed: {e}") from e

    async def mkdir(self, path: str, mode: int = 0o755) -> None:
        """
        Create directory asynchronously.

        Args:
            path: Directory path to create
            mode: Directory permissions

        Raises:
            SFTPError: If mkdir fails
        """
        try:
            request_id = self._get_next_request_id()

            # Create attributes with mode
            attrs = SFTPAttributes()
            attrs.st_mode = mode

            # Send mkdir request
            mkdir_msg = SFTPMkdirMessage(request_id=request_id, path=path, attrs=attrs)
            await self._send_message(mkdir_msg)

            # Wait for response
            response = await self._wait_for_response(request_id)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError(
                        f"Mkdir failed: {response.message}", response.status_code
                    )
            else:
                raise SFTPError("Unexpected response to mkdir request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Directory creation failed: {e}") from e

    async def rmdir(self, path: str) -> None:
        """
        Remove directory asynchronously.

        Args:
            path: Directory path to remove

        Raises:
            SFTPError: If rmdir fails
        """
        try:
            request_id = self._get_next_request_id()

            # Send rmdir request
            rmdir_msg = SFTPRmdirMessage(request_id=request_id, path=path)
            await self._send_message(rmdir_msg)

            # Wait for response
            response = await self._wait_for_response(request_id)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError(
                        f"Rmdir failed: {response.message}", response.status_code
                    )
            else:
                raise SFTPError("Unexpected response to rmdir request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Directory removal failed: {e}") from e

    async def open(self, filename: str, mode: str = "r") -> "AsyncSFTPFile":
        """
        Open remote file asynchronously.

        Args:
            filename: Remote file path
            mode: File open mode

        Returns:
            Async SFTP file object

        Raises:
            SFTPError: If file open fails
        """
        try:
            request_id = self._get_next_request_id()

            # Convert mode to SFTP flags
            flags = self._mode_to_flags(mode)

            # Send open request
            open_msg = SFTPOpenMessage(
                request_id=request_id,
                filename=filename,
                pflags=flags,
                attrs=SFTPAttributes(),
            )
            await self._send_message(open_msg)

            # Wait for response
            response = await self._wait_for_response(request_id)

            if isinstance(response, SFTPHandleMessage):
                return AsyncSFTPFile(self, response.handle, mode)
            elif isinstance(response, SFTPStatusMessage):
                raise SFTPError(
                    f"File open failed: {response.message}", response.status_code
                )
            else:
                raise SFTPError("Unexpected response to open request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File open failed: {e}") from e

    async def rename(self, oldpath: str, newpath: str) -> None:
        """Rename remote file or directory."""
        try:
            request_id = self._get_next_request_id()
            rename_msg = SFTPRenameMessage(
                request_id=request_id, oldpath=oldpath, newpath=newpath
            )
            await self._send_message(rename_msg)
            response = await self._wait_for_response(request_id)
            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError(
                        f"Rename failed: {response.message}", response.status_code
                    )
            else:
                raise SFTPError("Unexpected response to rename request")
        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Rename failed: {e}") from e

    async def chmod(self, path: str, mode: int) -> None:
        """Change remote file permissions."""
        try:
            attrs = SFTPAttributes()
            attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS
            attrs.permissions = mode
            request_id = self._get_next_request_id()
            setstat_msg = SFTPSetStatMessage(
                request_id=request_id, path=path, attrs=attrs
            )
            await self._send_message(setstat_msg)
            response = await self._wait_for_response(request_id)
            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError(
                        f"Chmod failed: {response.message}", response.status_code
                    )
            else:
                raise SFTPError("Unexpected response to setstat request")
        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Chmod failed: {e}") from e

    async def normalize(self, path: str) -> str:
        """Resolve remote path to its absolute canonical form."""
        try:
            request_id = self._get_next_request_id()
            realpath_msg = SFTPRealPathMessage(request_id=request_id, path=path)
            await self._send_message(realpath_msg)
            response = await self._wait_for_response(request_id)
            if isinstance(response, SFTPNameMessage):
                if response.names:
                    return response.names[0][0]
                raise SFTPError("Empty response to realpath request")
            elif isinstance(response, SFTPStatusMessage):
                raise SFTPError(
                    f"Normalize failed: {response.message}", response.status_code
                )
            else:
                raise SFTPError("Unexpected response to realpath request")
        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Normalize failed: {e}") from e

    async def close(self) -> None:
        """Close SFTP client and cleanup resources."""
        if self._dispatch_task:
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass
            self._dispatch_task = None

        if self._channel:
            await self._channel.close()
            self._channel = None

        self._initialized = False
        self._pending_requests.clear()

    async def __aenter__(self) -> "AsyncSFTPClient":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()

    def _get_next_request_id(self) -> int:
        """Get next request ID."""
        self._request_id = (self._request_id + 1) & 0xFFFFFFFF
        return self._request_id

    def _mode_to_flags(self, mode: str) -> int:
        """Convert file mode string to SFTP flags."""
        flags = 0

        if "r" in mode:
            flags |= SSH_FXF_READ
        if "w" in mode:
            flags |= SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC
        if "a" in mode:
            flags |= SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_APPEND
        if "x" in mode:
            flags |= SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL

        return flags

    async def _send_message(self, message: Any) -> None:
        """Send SFTP message through channel (with locking)."""
        data = message.pack()
        async with self._lock:
            await self._channel.send(data)

    async def _recv_message(self) -> Any:
        """Receive SFTP message from channel."""
        # Read message length
        length_data = await self._channel.recv_exactly(4)
        length = struct.unpack(">I", length_data)[0]

        # Read message data
        data = await self._channel.recv_exactly(length)

        # Parse message
        return SFTPMessage.unpack(length_data + data)

    async def _wait_for_response(self, request_id: int, timeout: float = 60.0) -> Any:
        """Wait for response to specific request using dispatcher."""
        fut = asyncio.get_running_loop().create_future()
        self._pending_requests[request_id] = fut
        try:
            return await asyncio.wait_for(asyncio.shield(fut), timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_requests.pop(request_id, None)
            raise SFTPError(f"Timeout waiting for response to request {request_id}")

    async def _opendir(self, path: str) -> bytes:
        """
        Open directory and return handle.

        Args:
            path: Directory path to open

        Returns:
            Directory handle

        Raises:
            SFTPError: If directory open fails
        """
        request_id = self._get_next_request_id()

        # Send opendir request
        opendir_msg = SFTPOpenDirMessage(request_id=request_id, path=path)
        await self._send_message(opendir_msg)

        # Wait for response
        response = await self._wait_for_response(request_id)

        if isinstance(response, SFTPHandleMessage):
            return response.handle
        elif isinstance(response, SFTPStatusMessage):
            raise SFTPError(f"Opendir failed: {response.message}", response.status_code)
        else:
            raise SFTPError("Unexpected response to opendir request")

    async def _readdir(self, handle: bytes) -> list[Any]:
        """
        Read directory entries.

        Args:
            handle: Directory handle

        Returns:
            List of directory entries

        Raises:
            SFTPError: If readdir fails
        """
        request_id = self._get_next_request_id()

        # Send readdir request
        readdir_msg = SFTPReadDirMessage(request_id=request_id, handle=handle)
        await self._send_message(readdir_msg)

        # Wait for response
        response = await self._wait_for_response(request_id)

        if isinstance(response, SFTPNameMessage):
            return response.names
        elif isinstance(response, SFTPStatusMessage):
            if response.status_code == SSH_FX_EOF:
                return []  # End of directory
            else:
                raise SFTPError(
                    f"Readdir failed: {response.message}", response.status_code
                )
        else:
            raise SFTPError("Unexpected response to readdir request")

    async def _close(self, handle: bytes) -> None:
        """
        Close file or directory handle.

        Args:
            handle: Handle to close

        Raises:
            SFTPError: If close fails
        """
        request_id = self._get_next_request_id()

        # Send close request
        close_msg = SFTPCloseMessage(request_id=request_id, handle=handle)
        await self._send_message(close_msg)

        # Wait for response
        response = await self._wait_for_response(request_id)

        if isinstance(response, SFTPStatusMessage):
            if response.status_code != SSH_FX_OK:
                raise SFTPError(
                    f"Close failed: {response.message}", response.status_code
                )
        else:
            raise SFTPError("Unexpected response to close request")


class AsyncSFTPFile:
    """Async SFTP file object for remote file operations."""

    _PIPELINE_DEPTH = 32

    def __init__(self, client: AsyncSFTPClient, handle: bytes, mode: str) -> None:
        """
        Initialize async SFTP file.

        Args:
            client: SFTP client instance
            handle: File handle from server
            mode: File open mode
        """
        self._client = client
        self._handle = handle
        self._mode = mode
        self._offset = 0
        self._closed = False
        self._write_queue: list[tuple[int, int]] = []

    async def read(self, size: int = -1) -> bytes:
        """
        Read data from file asynchronously.

        Args:
            size: Number of bytes to read (-1 for all)

        Returns:
            Read data

        Raises:
            SFTPError: If read fails
        """
        if self._closed:
            raise SFTPError("File is closed")

        try:
            if size < 0:
                # Pipelined read until EOF
                _CHUNK = 32768
                result = bytearray()
                inflight: list[int] = []
                done = False
                offset = self._offset

                while not done or inflight:
                    # Fill pipeline
                    while not done and len(inflight) < self._PIPELINE_DEPTH:
                        req_id = self._client._get_next_request_id()
                        msg = SFTPReadMessage(
                            request_id=req_id,
                            handle=self._handle,
                            offset=offset,
                            length=_CHUNK,
                        )
                        await self._client._send_message(msg)
                        inflight.append(req_id)
                        offset += _CHUNK

                    if not inflight:
                        break

                    # Collect next in-order response
                    rid = inflight.pop(0)
                    response = await self._client._wait_for_response(rid)
                    if isinstance(response, SFTPDataMessage):
                        result.extend(response.data)
                    elif isinstance(response, SFTPStatusMessage):
                        if response.status_code == SSH_FX_EOF:
                            done = True
                        else:
                            raise SFTPError(
                                f"Read failed: {response.message}",
                                response.status_code,
                            )
                    else:
                        raise SFTPError("Unexpected response to read request")

                self._offset += len(result)
                return bytes(result)

            # Single read
            request_id = self._client._get_next_request_id()
            read_msg = SFTPReadMessage(
                request_id=request_id,
                handle=self._handle,
                offset=self._offset,
                length=size,
            )
            await self._client._send_message(read_msg)

            # Wait for response
            response = await self._client._wait_for_response(request_id)

            if isinstance(response, SFTPDataMessage):
                self._offset += len(response.data)
                return response.data
            elif isinstance(response, SFTPStatusMessage):
                if response.status_code == SSH_FX_EOF:
                    return b""
                raise SFTPError(
                    f"Read failed: {response.message}", response.status_code
                )
            else:
                raise SFTPError("Unexpected response to read request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File read failed: {e}") from e

    async def write(self, data: bytes) -> None:
        """
        Write data to file asynchronously.

        Args:
            data: Data to write

        Raises:
            SFTPError: If write fails
        """
        if self._closed:
            raise SFTPError("File is closed")

        try:
            request_id = self._client._get_next_request_id()
            # Calculate offset considering pipelined writes
            send_offset = self._offset + sum(n for _, n in self._write_queue)

            # Send write request
            write_msg = SFTPWriteMessage(
                request_id=request_id,
                handle=self._handle,
                offset=send_offset,
                data=data,
            )
            await self._client._send_message(write_msg)

            # Add to pipeline
            self._write_queue.append((request_id, len(data)))

            # Drain oldest if pipeline is full
            if len(self._write_queue) >= self._PIPELINE_DEPTH:
                rid, nbytes = self._write_queue.pop(0)
                response = await self._client._wait_for_response(rid)
                if isinstance(response, SFTPStatusMessage):
                    if response.status_code == SSH_FX_OK:
                        self._offset += nbytes
                    else:
                        raise SFTPError(
                            f"Write failed: {response.message}", response.status_code
                        )
                else:
                    raise SFTPError("Unexpected response to write request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File write failed: {e}") from e

    async def _flush_write_queue(self) -> None:
        """Drain all outstanding pipelined write ACKs."""
        for rid, nbytes in self._write_queue:
            response = await self._client._wait_for_response(rid)
            if isinstance(response, SFTPStatusMessage):
                if response.status_code == SSH_FX_OK:
                    self._offset += nbytes
                else:
                    raise SFTPError(
                        f"Write failed: {response.message}", response.status_code
                    )
            else:
                raise SFTPError("Unexpected response to write request")
        self._write_queue.clear()

    async def close(self) -> None:
        """Close file handle."""
        if not self._closed:
            try:
                # Flush pending writes first
                await self._flush_write_queue()

                request_id = self._client._get_next_request_id()

                # Send close request
                close_msg = SFTPCloseMessage(request_id=request_id, handle=self._handle)
                await self._client._send_message(close_msg)

                # Wait for response
                await self._client._wait_for_response(request_id)

            except Exception:
                pass  # Ignore errors during close
            finally:
                self._closed = True

    async def __aenter__(self) -> "AsyncSFTPFile":
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Async context manager exit."""
        await self.close()
