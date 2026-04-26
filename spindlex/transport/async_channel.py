"""
Async SSH Channel Implementation

Provides asynchronous SSH channel functionality for command execution and data transfer.
"""

import asyncio
from typing import Any, Union

from ..exceptions import ChannelException
from ..protocol.constants import (
    DEFAULT_WINDOW_SIZE,
    SSH_EXTENDED_DATA_STDERR,
)
from ..protocol.utils import write_string
from .channel import Channel


class AsyncChannel(Channel):
    """
    Async SSH channel for command execution and data transfer.

    Extends the base Channel class to provide asynchronous operations
    for use in async/await applications and high-concurrency scenarios.
    """

    def __init__(self, transport: Any, channel_id: int) -> None:
        """
        Initialize async channel.

        Args:
            transport: Async transport instance
            channel_id: Local channel ID
        """
        super().__init__(transport, channel_id)
        self._send_queue: asyncio.Queue[Any] = asyncio.Queue()
        self._recv_queue: asyncio.Queue[Any] = asyncio.Queue()
        self._closed_event = asyncio.Event()

        # Override parent's deque buffers with bytes for async
        self._recv_buffer: bytes = b""
        self._stderr_buffer: bytes = b""
        import threading

        self._buffer_lock = threading.Lock()

    def _handle_data(self, data: bytes) -> None:
        """Handle incoming channel data."""
        with self._buffer_lock:
            self._recv_buffer += data

    def _handle_extended_data(self, data_type: int, data: bytes) -> None:
        """Handle incoming channel extended data."""
        if data_type == SSH_EXTENDED_DATA_STDERR:
            with self._buffer_lock:
                self._stderr_buffer += data

    def _handle_eof(self) -> None:
        """Handle incoming channel EOF."""
        self._eof_received = True

    async def send(self, data: Union[bytes, str]) -> int:  # type: ignore[override]
        """
        Send data through channel asynchronously.

        Args:
            data: Data to send (bytes or string)

        Returns:
            Number of bytes sent

        Raises:
            ChannelException: If send fails
        """
        if self.closed:
            raise ChannelException("Channel is closed")

        if not data:
            return 0

        # Convert string to bytes if needed
        if isinstance(data, str):
            from ..protocol.constants import SSH_STRING_ENCODING

            data = data.encode(SSH_STRING_ENCODING)

        total_sent = 0

        try:
            # Check if we have enough window space
            while len(data) > 0:
                if self._remote_window_size == 0:
                    # Wait for window adjustment by pumping the transport
                    await self._transport._pump_async()
                    continue

                # Send what we can fit in the window and max packet size
                chunk_size = min(
                    len(data), self._remote_window_size, self._remote_max_packet_size
                )
                if (
                    chunk_size == 0
                ):  # Should be handled by self._remote_window_size == 0 check above but just in case
                    await self._transport._pump_async()
                    continue

                chunk = data[:chunk_size]
                await self._transport._send_channel_data_async(self._channel_id, chunk)

                data = data[chunk_size:]
                self._remote_window_size -= chunk_size
                total_sent += chunk_size

            return total_sent

        except Exception as e:
            if isinstance(e, ChannelException):
                raise
            raise ChannelException(f"Send failed: {e}") from e

    async def sendall(self, data: Union[bytes, str]) -> None:  # type: ignore[override]
        """
        Send all data through channel asynchronously.

        Args:
            data: Data to send
        """
        await self.send(data)

    async def recv(self, nbytes: int) -> bytes:  # type: ignore[override]
        """
        Receive data from channel asynchronously.

        Args:
            nbytes: Maximum number of bytes to receive

        Returns:
            Received data

        Raises:
            ChannelException: If receive fails
        """
        try:
            # Wait for data or channel close
            while True:
                if self._recv_buffer:
                    # Return available data
                    if nbytes <= 0:
                        data = self._recv_buffer
                        self._recv_buffer = b""
                    else:
                        data = self._recv_buffer[:nbytes]
                        self._recv_buffer = self._recv_buffer[nbytes:]

                    # Adjust window if needed
                    if len(data) > 0:
                        await self._adjust_window_async(len(data))

                    return bytes(data)

                if self.eof_received:
                    return b""

                if self.closed:
                    raise ChannelException("Channel is closed")

                # Wait for more data by pumping the transport
                await self._transport._pump_async()

        except Exception as e:
            if isinstance(e, ChannelException):
                raise
            raise ChannelException(f"Receive failed: {e}") from e

    async def recv_exactly(self, nbytes: int) -> bytes:  # type: ignore[override]
        """
        Receive exactly nbytes from channel asynchronously.

        Args:
            nbytes: Number of bytes to receive

        Returns:
            Received data

        Raises:
            ChannelException: If receive fails or channel closed
        """
        data = b""
        while len(data) < nbytes:
            chunk = await self.recv(nbytes - len(data))
            if not chunk:
                raise ChannelException("Connection closed while waiting for data")
            data += chunk
        return data

    async def recv_stderr(self, nbytes: int) -> bytes:  # type: ignore[override]
        """
        Receive stderr data from channel asynchronously.

        Args:
            nbytes: Maximum number of bytes to receive

        Returns:
            Received data

        Raises:
            ChannelException: If receive fails
        """
        if self.closed and not self._stderr_buffer:
            raise ChannelException("Channel is closed")

        try:
            # Wait for data or channel close
            while True:
                if not self._stderr_buffer and self.eof_received:
                    return b""

                if self._stderr_buffer:
                    # Return available data
                    if nbytes <= 0:
                        data = self._stderr_buffer
                        self._stderr_buffer = b""
                    else:
                        data = self._stderr_buffer[:nbytes]
                        self._stderr_buffer = self._stderr_buffer[nbytes:]

                    # Adjust window if needed
                    if len(data) > 0:
                        await self._adjust_window_async(len(data))

                    return bytes(data)

                # Wait for more data by pumping the transport
                await self._transport._pump_async()

        except Exception as e:
            if isinstance(e, ChannelException):
                raise
            raise ChannelException(f"Receive failed: {e}") from e

    async def _wait_for_channel_request_result(self) -> bool:
        """Pump until MSG_CHANNEL_SUCCESS/FAILURE is dispatched to this channel.
        Returns True on success, False on failure."""
        self._request_event.clear()
        while not self._request_event.is_set():
            await self._transport._pump_async()
        return bool(self._request_success)

    async def exec_command(self, command: str) -> None:  # type: ignore[override]
        """
        Execute command on channel asynchronously.

        Args:
            command: Command to execute

        Raises:
            ChannelException: If command execution fails
        """
        if self.closed:
            raise ChannelException("Channel is closed")

        try:
            request_data = bytearray()
            request_data.extend(write_string(command))
            await self._transport._send_channel_request_async(
                self._channel_id, "exec", True, bytes(request_data)
            )
            if not await self._wait_for_channel_request_result():
                raise ChannelException(f"Command execution failed: {command}")

        except Exception as e:
            if isinstance(e, ChannelException):
                raise
            raise ChannelException(f"Command execution failed: {e}") from e

    async def invoke_shell(self) -> None:  # type: ignore[override]
        """
        Invoke shell on channel asynchronously.

        Raises:
            ChannelException: If shell invocation fails
        """
        if self.closed:
            raise ChannelException("Channel is closed")

        try:
            await self._transport._send_channel_request_async(
                self._channel_id, "shell", True, b""
            )
            if not await self._wait_for_channel_request_result():
                raise ChannelException("Shell invocation failed")

        except Exception as e:
            if isinstance(e, ChannelException):
                raise
            raise ChannelException(f"Shell invocation failed: {e}") from e

    async def invoke_subsystem(self, subsystem: str) -> None:  # type: ignore[override]
        """
        Invoke subsystem on channel asynchronously.

        Args:
            subsystem: Subsystem name (e.g., "sftp")

        Raises:
            ChannelException: If subsystem invocation fails
        """
        if self.closed:
            raise ChannelException("Channel is closed")

        try:
            request_data = bytearray()
            request_data.extend(write_string(subsystem))
            await self._transport._send_channel_request_async(
                self._channel_id, "subsystem", True, bytes(request_data)
            )
            if not await self._wait_for_channel_request_result():
                raise ChannelException(f"Subsystem invocation failed: {subsystem}")

        except Exception as e:
            if isinstance(e, ChannelException):
                raise
            raise ChannelException(f"Subsystem invocation failed: {e}") from e

    async def send_exit_status(self, status: int) -> None:  # type: ignore[override]
        """
        Send command exit status to remote side asynchronously.

        Args:
            status: Exit status code (typically 0 for success)

        Raises:
            ChannelException: If send fails
        """
        from ..protocol.utils import write_uint32

        try:
            # Build exit-status request data (4-byte unsigned integer)
            request_data = write_uint32(status)

            # Send exit-status request (no reply wanted for this type)
            await self._transport._send_channel_request_async(
                self._channel_id, "exit-status", False, request_data
            )
        except Exception as e:
            raise ChannelException(f"Failed to send exit status: {e}") from e

    async def recv_exit_status(self) -> int:  # type: ignore[override]
        """
        Wait for and return command exit status asynchronously.

        Returns:
            Exit status code
        """
        while self._exit_status is None and not self._closed:
            try:
                await self._transport._pump_async()
            except Exception:
                break
        return self.get_exit_status()

    async def close(self) -> None:  # type: ignore[override]
        """Close channel asynchronously."""
        if not self._closed:
            try:
                # Send EOF first
                await self._transport._send_channel_eof_async(self._channel_id)

                # Send close
                await self._transport._send_channel_close_async(self._channel_id)

            except Exception:
                pass  # Ignore errors during close
            finally:
                # Remove from transport
                if (
                    hasattr(self._transport, "_channels")
                    and self._channel_id in self._transport._channels
                ):
                    async with getattr(self._transport, "_state_lock", asyncio.Lock()):
                        if self._channel_id in self._transport._channels:
                            del self._transport._channels[self._channel_id]

                self._closed = True
                self._closed_event.set()

    async def wait_closed(self) -> None:
        """Wait for channel to be closed."""
        await self._closed_event.wait()

    async def _adjust_window_async(self, bytes_consumed: int) -> None:
        """
        Adjust local window size asynchronously.

        Args:
            bytes_consumed: Number of bytes consumed from buffer
        """
        self._local_window_size -= bytes_consumed

        # Send window adjust if needed
        if self._local_window_size < DEFAULT_WINDOW_SIZE // 2:
            bytes_to_add = DEFAULT_WINDOW_SIZE - self._local_window_size
            await self._transport._send_channel_window_adjust_async(
                self._channel_id, bytes_to_add
            )
            self._local_window_size += bytes_to_add

    def makefile(self, mode: str = "r", bufsize: int = -1) -> Any:
        """
        Create file-like object for channel.

        Args:
            mode: File mode
            bufsize: Buffer size

        Returns:
            File-like object for channel
        """
        return AsyncChannelFile(self, mode, bufsize)

    def makefile_stderr(self, mode: str = "r", bufsize: int = -1) -> Any:
        """
        Create file-like object for channel stderr.

        Args:
            mode: File mode
            bufsize: Buffer size

        Returns:
            File-like object for channel stderr
        """
        return AsyncChannelFile(self, mode, bufsize, is_stderr=True)


class AsyncChannelFile:
    """
    Async file-like object for SSH channel operations.

    Provides a file-like interface for reading from and writing to
    SSH channels in asynchronous applications.
    """

    def __init__(
        self,
        channel: AsyncChannel,
        mode: str = "r",
        bufsize: int = -1,
        is_stderr: bool = False,
    ) -> None:
        """
        Initialize async channel file.

        Args:
            channel: Async channel instance
            mode: File mode
            bufsize: Buffer size
            is_stderr: Whether this file object is for stderr
        """
        self._channel = channel
        self._mode = mode
        self._bufsize = bufsize
        self._is_stderr = is_stderr
        self._closed = False

    async def read(self, size: int = -1) -> bytes:
        """
        Read data from channel asynchronously.

        Args:
            size: Number of bytes to read

        Returns:
            Read data
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        if size == 0:
            return b""

        res = b""
        while True:
            # How many bytes to request in this iteration
            if size < 0:
                chunk_size = -1
            else:
                chunk_size = size - len(res)
                if chunk_size == 0:
                    break

            if self._is_stderr:
                chunk = await self._channel.recv_stderr(chunk_size)
            else:
                chunk = await self._channel.recv(chunk_size)

            if not chunk:
                break

            res += chunk

        return res

    def get_exit_status(self) -> int:
        """
        Get command exit status.

        Returns:
            Exit status code, or -1 if not available
        """
        return self._channel.get_exit_status()

    async def recv_exit_status(self) -> int:
        """
        Wait for and return command exit status asynchronously.

        Returns:
            Exit status code
        """
        return await self._channel.recv_exit_status()

    def __aiter__(self) -> "AsyncChannelFile":
        """
        Make object async iterable for line-by-line reading.

        Returns:
            Self as async iterator
        """
        return self

    async def __anext__(self) -> str:
        """
        Read next line from channel asynchronously.

        Returns:
            Next line of data

        Raises:
            StopAsyncIteration: If EOF reached
        """
        line = await self.readline()
        if not line:
            raise StopAsyncIteration
        return line

    async def readline(self) -> str:
        """
        Read a single line from the channel asynchronously.

        Returns:
            Read line
        """
        result = bytearray()
        while True:
            char = await self.read(1)
            if not char:
                break
            result.extend(char)
            if char == b"\n":
                break
        return result.decode("utf-8", errors="replace")

    async def write(self, data: bytes) -> int:
        """
        Write data to channel asynchronously.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        if self._closed:
            raise ValueError("I/O operation on closed file")

        return await self._channel.send(data)

    @property
    def channel(self) -> "AsyncChannel":
        """Get underlying SSH channel."""
        return self._channel

    async def close(self) -> None:
        """Close file object."""
        if not self._closed:
            self._closed = True

    def closed(self) -> bool:
        """Check if file is closed."""
        return self._closed
