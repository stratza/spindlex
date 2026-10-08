"""
Async SSH Channel Implementation

Provides asynchronous SSH channel functionality for command execution and data transfer.
"""

import asyncio
import threading
from typing import Any, Optional, Union

from ..exceptions import ChannelException
from ..protocol.constants import DEFAULT_WINDOW_SIZE, SSH_EXTENDED_DATA_STDERR
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

        # Override parent's deque buffers with flat byte buffers for the async
        # I/O path. bytearray appends in place and deleting from the front is
        # amortised O(1) in CPython, so draining a large buffer in small reads
        # (readline) stays linear.
        self._recv_buffer = bytearray()
        self._stderr_buffer = bytearray()
        self._buffer_lock = threading.Lock()

    def _handle_close(self) -> None:
        """Handle incoming channel-close message.

        The transport replies with our CLOSE (if not sent yet) and releases the
        channel number; on the event loop that send is scheduled rather than
        awaited.
        """
        self._closed = True
        self._close_received = True
        self._closed_event.set()

    def _handle_data(self, data: bytes) -> None:
        """Handle incoming channel data."""
        if self._closed:
            return
        # Enforce the advertised receive window (a peer overrunning it is
        # violating flow control and would otherwise grow our buffer without
        # bound).
        with self._lock:
            overrun = self._check_inbound_window(len(data))
        if overrun:
            self._close_after_overrun()
            return
        with self._buffer_lock:
            self._recv_buffer = self._as_bytearray(self._recv_buffer)
            self._recv_buffer += data

    def _handle_extended_data(self, data_type: int, data: bytes) -> None:
        """Handle incoming channel extended data."""
        if data_type != SSH_EXTENDED_DATA_STDERR or self._closed:
            return
        with self._lock:
            overrun = self._check_inbound_window(len(data))
        if overrun:
            self._close_after_overrun()
            return
        with self._buffer_lock:
            self._stderr_buffer = self._as_bytearray(self._stderr_buffer)
            self._stderr_buffer += data

    @staticmethod
    def _as_bytearray(buf: Any) -> bytearray:
        return buf if isinstance(buf, bytearray) else bytearray(buf)

    def _take_buffered(
        self, stderr: bool, nbytes: int, until_newline: bool = False
    ) -> Optional[bytes]:
        """Remove and return up to ``nbytes`` buffered bytes (all if
        ``nbytes <= 0``; up to and including the first newline if
        ``until_newline``), or None if nothing is buffered."""
        name = "_stderr_buffer" if stderr else "_recv_buffer"
        with self._buffer_lock:
            buf = self._as_bytearray(getattr(self, name))
            setattr(self, name, buf)
            if not buf:
                return None
            end = len(buf) if nbytes <= 0 else min(nbytes, len(buf))
            if until_newline:
                newline = buf.find(b"\n", 0, end)
                if newline != -1:
                    end = newline + 1
            data = bytes(buf[:end])
            del buf[:end]
            return data

    async def _recv_stream(
        self, stderr: bool, nbytes: int, until_newline: bool = False
    ) -> bytes:
        try:
            while True:
                data = self._take_buffered(stderr, nbytes, until_newline)
                if data is not None:
                    await self._adjust_window_async(len(data))
                    return data

                # Nothing buffered: EOF, or the channel is closed.
                if self.eof_received or self.closed:
                    return b""

                # Wait for more data by pumping the transport
                await self._transport._pump_async()

        except Exception as e:
            if isinstance(e, ChannelException):
                raise
            raise ChannelException(f"Receive failed: {e}") from e

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
        # Slice a memoryview: re-slicing the bytes object on every packet would
        # copy the remainder each time (quadratic for large sends).
        view = memoryview(data)

        try:
            # Check if we have enough window space
            while len(view) > 0:
                if self._remote_window_size == 0:
                    # Wait for window adjustment by pumping the transport
                    await self._transport._pump_async()
                    continue

                # Send what we can fit in the window and max packet size
                chunk_size = min(
                    len(view), self._remote_window_size, self._remote_max_packet_size
                )
                if (
                    chunk_size == 0
                ):  # Should be handled by self._remote_window_size == 0 check above but just in case
                    await self._transport._pump_async()
                    continue

                chunk = bytes(view[:chunk_size])
                await self._transport._send_channel_data_async(self._channel_id, chunk)

                view = view[chunk_size:]
                self._remote_window_size -= chunk_size
                total_sent += chunk_size

            return total_sent

        except Exception as e:
            if isinstance(e, ChannelException):
                raise
            raise ChannelException(f"Send failed: {e}") from e

    async def send_eof(self) -> None:  # type: ignore[override]
        """Send EOF (half-close): the peer can still send to us."""
        if self._eof_sent or self._closed:
            return
        self._eof_sent = True
        await self._transport._send_channel_eof_async(self._channel_id)

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
        return await self._recv_stream(False, nbytes)

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
        data = bytearray()
        while len(data) < nbytes:
            chunk = await self.recv(nbytes - len(data))
            if not chunk:
                raise ChannelException("Connection closed while waiting for data")
            data += chunk
        return bytes(data)

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
        return await self._recv_stream(True, nbytes)

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
        """Close channel asynchronously.

        Sends EOF and CLOSE unless CLOSE was already sent (for example as the
        reply to the peer's close). The channel number is released once both
        sides have sent CLOSE.
        """
        if not self._close_sent:
            self._close_sent = True
            try:
                if not self._eof_sent and not self._close_received:
                    await self._transport._send_channel_eof_async(self._channel_id)
                    self._eof_sent = True
                await self._transport._send_channel_close_async(self._channel_id)
            except Exception as e:
                self._logger.debug(f"Error during async channel close: {e}")

        if self._close_received or self._remote_channel_id is None:
            channels = getattr(self._transport, "_channels", None)
            if channels is not None and self._channel_id in channels:
                async with getattr(self._transport, "_state_lock", asyncio.Lock()):
                    channels.pop(self._channel_id, None)

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
            # Credit the same amount back to the inbound-overrun accounting.
            if self._inbound_window_remaining is not None:
                self._inbound_window_remaining += bytes_to_add

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

        res = bytearray()
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

        return bytes(res)

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
        if self._closed:
            raise ValueError("I/O operation on closed file")
        result = bytearray()
        while True:
            chunk = await self._channel._recv_stream(
                self._is_stderr, 65536, until_newline=True
            )
            if not chunk:
                break
            result += chunk
            if chunk.endswith(b"\n"):
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
