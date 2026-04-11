"""
Async SFTP Client Implementation

Provides asynchronous SFTP client functionality for file operations.
"""

import struct
from typing import Any

from ..exceptions import SFTPError
from ..protocol.sftp_constants import *
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
    SFTPRmdirMessage,
    SFTPStatMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
    SFTPWriteMessage,
)


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
        self._pending_requests = {}
        self._initialized = False

    async def _initialize(self) -> None:
        """Initialize SFTP subsystem."""
        if self._initialized:
            return

        # Send SFTP init message
        init_msg = SFTPInitMessage(version=SFTP_VERSION)
        await self._send_message(init_msg)

        # Wait for version response
        response = await self._recv_message()
        if not isinstance(response, SFTPVersionMessage):
            raise SFTPError("Expected SFTP version message")

        self._initialized = True

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
        try:
            # Open remote file for reading
            remote_file = await self.open(remotepath, "rb")

            # Create local file
            with open(localpath, "wb") as local_file:
                # Read and write in chunks
                while True:
                    chunk = await remote_file.read(32768)
                    if not chunk:
                        break
                    local_file.write(chunk)

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
        try:
            # Open remote file for writing
            remote_file = await self.open(remotepath, "wb")

            # Read local file and upload in chunks
            with open(localpath, "rb") as local_file:
                while True:
                    chunk = local_file.read(32768)
                    if not chunk:
                        break
                    await remote_file.write(chunk)

            await remote_file.close()

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File upload failed: {e}") from e

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
                        if entry.filename not in (".", ".."):
                            filenames.append(entry.filename)

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

    async def close(self) -> None:
        """Close SFTP client and cleanup resources."""
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
        self._request_id += 1
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
        """Send SFTP message through channel."""
        data = message.pack()
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

    async def _wait_for_response(self, request_id: int) -> Any:
        """Wait for response to specific request."""
        # For now, just receive the next message
        # In a full implementation, this would handle multiple concurrent requests
        return await self._recv_message()

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
            request_id = self._client._get_next_request_id()

            # Send read request
            read_msg = SFTPReadMessage(
                request_id=request_id,
                handle=self._handle,
                offset=self._offset,
                length=size if size > 0 else 32768,
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

            # Send write request
            write_msg = SFTPWriteMessage(
                request_id=request_id,
                handle=self._handle,
                offset=self._offset,
                data=data,
            )
            await self._client._send_message(write_msg)

            # Wait for response
            response = await self._client._wait_for_response(request_id)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code == SSH_FX_OK:
                    self._offset += len(data)
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

    async def close(self) -> None:
        """Close file handle."""
        if not self._closed:
            try:
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
