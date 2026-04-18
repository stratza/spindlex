"""
Async SSH Channel Implementation

Provides asynchronous SSH channel functionality for command execution and data transfer.
"""

import asyncio
from typing import Any, Union

from ..exceptions import ChannelException
from ..protocol.constants import (
    DEFAULT_WINDOW_SIZE,
    MSG_CHANNEL_FAILURE,
    MSG_CHANNEL_SUCCESS,
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

    def _handle_data(self, data: bytes) -> None:
        """Handle incoming channel data."""
        self._recv_buffer += data

    def _handle_extended_data(self, data_type: int, data: bytes) -> None:
        """Handle incoming channel extended data."""
        if data_type == SSH_EXTENDED_DATA_STDERR:
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
        if self.closed and not self._recv_buffer:
            raise ChannelException("Channel is closed")

        try:
            # Wait for data or channel close
            while True:
                if not self._recv_buffer and self.eof_received:
                    return b""

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
            # Build exec request data
            request_data = bytearray()
            request_data.extend(write_string(command))

            # Send channel request
            await self._transport._send_channel_request_async(
                self._channel_id, "exec", True, bytes(request_data)
            )

            # Wait for response
            res = await self._transport._expect_message_async(
                MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE, channel_id=self._channel_id
            )
            if res.msg_type == MSG_CHANNEL_FAILURE:
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
            # Send shell request
            await self._transport._send_channel_request_async(
                self._channel_id, "shell", True, b""
            )

            # Wait for response
            res = await self._transport._expect_message_async(
                MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE, channel_id=self._channel_id
            )
            if res.msg_type == MSG_CHANNEL_FAILURE:
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
            # Build subsystem request data
            request_data = bytearray()
            request_data.extend(write_string(subsystem))

            # Send subsystem request
            await self._transport._send_channel_request_async(
                self._channel_id, "subsystem", True, bytes(request_data)
            )

            # Wait for response
            res = await self._transport._expect_message_async(
                MSG_CHANNEL_SUCCESS, MSG_CHANNEL_FAILURE, channel_id=self._channel_id
            )
            if res.msg_type == MSG_CHANNEL_FAILURE:
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

        if self._is_stderr:
            return await self._channel.recv_stderr(size)
        return await self._channel.recv(size)

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
