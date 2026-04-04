"""
SSH Channel Implementation

Represents individual communication channels within SSH connections
with support for different channel types and operations.
"""

import threading
import time
from collections import deque
from typing import Any, Deque, Optional

from ..exceptions import ChannelException


class Channel:
    """
    SSH channel for communication within SSH connection.

    Handles data transmission, flow control, and channel-specific
    operations like command execution and shell access.
    """

    def __init__(self, transport: Any, channel_id: int) -> None:
        """
        Initialize channel with transport and ID.

        Args:
            transport: SSH transport instance
            channel_id: Unique channel identifier
        """
        self._transport = transport
        self._channel_id = channel_id
        self._closed = False
        self._exit_status: Optional[int] = None

        # Remote channel info (set by transport after channel open)
        self._remote_channel_id: Optional[int] = None
        self._remote_window_size = 0
        self._remote_max_packet_size = 0

        # Local channel info
        self._local_window_size = 0
        self._local_max_packet_size = 0

        # Data buffers
        self._recv_buffer: Deque[bytes] = deque()
        self._stderr_buffer: Deque[bytes] = deque()

        # Flow control
        self._eof_received = False
        self._eof_sent = False

        # Request handling
        self._request_success: Optional[bool] = None

        # Threading
        self._lock = threading.RLock()
        self._data_event = threading.Event()
        self._request_event = threading.Event()

    def send(self, data: bytes) -> int:
        """
        Send data through channel.

        Args:
            data: Data to send

        Returns:
            Number of bytes sent

        Raises:
            ChannelException: If send operation fails
        """
        if not data:
            return 0

        with self._lock:
            if self._closed:
                raise ChannelException("Channel is closed")

            if self._eof_sent:
                raise ChannelException("EOF already sent on channel")

            if self._remote_channel_id is None:
                raise ChannelException("Channel not properly opened")

            # Check flow control - don't send more than remote window allows
            if len(data) > self._remote_window_size:
                # Send only what fits in the window
                data = data[: self._remote_window_size]

            # Check maximum packet size
            if len(data) > self._remote_max_packet_size:
                data = data[: self._remote_max_packet_size]

            if len(data) == 0:
                return 0

            try:
                # Send data through transport
                self._transport._send_channel_data(self._channel_id, data)

                # Update remote window size
                self._remote_window_size -= len(data)

                return len(data)

            except Exception as e:
                raise ChannelException(f"Failed to send data: {e}")

    def recv(self, nbytes: int) -> bytes:
        """
        Receive data from channel.

        Args:
            nbytes: Maximum bytes to receive

        Returns:
            Received data

        Raises:
            ChannelException: If receive operation fails
        """
        if nbytes <= 0:
            return b""

        while True:
            with self._lock:
                # Check if we have data in buffer
                if self._recv_buffer:
                    # Get data from buffer
                    data_chunk = self._recv_buffer.popleft()

                    if len(data_chunk) <= nbytes:
                        # Return entire chunk
                        return data_chunk
                    else:
                        # Split chunk and put remainder back
                        result = data_chunk[:nbytes]
                        remainder = data_chunk[nbytes:]
                        self._recv_buffer.appendleft(remainder)
                        return result

                # No data available in buffer
                if self._eof_received:
                    return b""  # EOF reached and buffer is empty

                # Reset data event before waiting
                self._data_event.clear()

            # Wait outside the lock to avoid blocking other operations
            # If we are in a synchronous implementation, we might need to poll transport
            if not self._data_event.wait(timeout=0.1):
                # Timeout, poll transport once to see if data arrived
                try:
                    self._transport._recv_message()
                except Exception:
                    # Connection might have closed, but we check _eof_received in next loop
                    pass

    def exec_command(self, command: str) -> None:
        """
        Execute command on channel.

        Args:
            command: Command to execute

        Raises:
            ChannelException: If command execution fails
        """
        if not command:
            raise ChannelException("Command cannot be empty")

        # Build exec request data using SSH string format
        from ..protocol.utils import write_string

        request_data = write_string(command)

        # Send exec request
        success = self.send_channel_request("exec", want_reply=True, data=request_data)

        if not success:
            raise ChannelException(f"Failed to execute command: {command}")

    def invoke_shell(self) -> None:
        """
        Start interactive shell on channel.

        Raises:
            ChannelException: If shell invocation fails
        """
        # Send shell request (no additional data needed)
        success = self.send_channel_request("shell", want_reply=True)

        if not success:
            raise ChannelException("Failed to invoke shell")

    def invoke_subsystem(self, subsystem: str) -> None:
        """
        Invoke subsystem on channel.

        Args:
            subsystem: Name of subsystem to invoke (e.g., "sftp")

        Raises:
            ChannelException: If subsystem invocation fails
        """
        if not subsystem:
            raise ChannelException("Subsystem name cannot be empty")

        # Build subsystem request data using SSH string format
        from ..protocol.utils import write_string

        request_data = write_string(subsystem)

        # Send subsystem request
        success = self.send_channel_request(
            "subsystem", want_reply=True, data=request_data
        )

        if not success:
            raise ChannelException(f"Failed to invoke subsystem: {subsystem}")

    def request_pty(
        self,
        term: str = "xterm",
        width: int = 80,
        height: int = 24,
        width_pixels: int = 0,
        height_pixels: int = 0,
        modes: bytes = b"",
    ) -> None:
        """
        Request pseudo-terminal for channel.

        Args:
            term: Terminal type (e.g., "xterm", "vt100")
            width: Terminal width in characters
            height: Terminal height in characters
            width_pixels: Terminal width in pixels (0 if unknown)
            height_pixels: Terminal height in pixels (0 if unknown)
            modes: Terminal modes (encoded as per RFC 4254)

        Raises:
            ChannelException: If PTY request fails
        """
        # Build pty-req request data using SSH protocol format
        from ..protocol.utils import write_string, write_uint32

        request_data = bytearray()

        # Terminal type
        request_data.extend(write_string(term))

        # Terminal dimensions
        request_data.extend(write_uint32(width))
        request_data.extend(write_uint32(height))
        request_data.extend(write_uint32(width_pixels))
        request_data.extend(write_uint32(height_pixels))

        # Terminal modes
        request_data.extend(write_string(modes))

        # Send pty-req request
        success = self.send_channel_request(
            "pty-req", want_reply=True, data=bytes(request_data)
        )

        if not success:
            raise ChannelException("Failed to request PTY")

    def get_exit_status(self) -> int:
        """
        Get command exit status.

        Returns:
            Exit status code, or -1 if not available
        """
        return self._exit_status if self._exit_status is not None else -1

    def send_channel_request(
        self, request_type: str, want_reply: bool = True, data: bytes = b""
    ) -> bool:
        """
        Send channel request.

        Args:
            request_type: Type of request (exec, shell, subsystem, etc.)
            want_reply: Whether to wait for reply
            data: Request-specific data

        Returns:
            True if request succeeded (when want_reply=True)

        Raises:
            ChannelException: If request fails
        """
        with self._lock:
            if self._closed:
                raise ChannelException("Channel is closed")

            if self._remote_channel_id is None:
                raise ChannelException("Channel not properly opened")

            try:
                # Send channel request through transport
                self._transport._send_channel_request(
                    self._channel_id, request_type, want_reply, data
                )

                if want_reply:
                    # Reset request event and wait for response
                    self._request_success = None
                    self._request_event.clear()

                # Release lock before waiting
                pass

            except Exception as e:
                raise ChannelException(f"Failed to send channel request: {e}")

        if want_reply:
            # Wait for response outside the lock
            timeout = getattr(
                self, "_test_timeout", 30.0
            )  # Allow tests to set shorter timeout
            start_time = time.time()

            while time.time() - start_time < timeout:
                if self._request_event.is_set():
                    with self._lock:
                        return self._request_success is True

                try:
                    # In a synchronous implementation without a background thread,
                    # we must manually receive and dispatch messages.
                    # We use a short timeout on the socket if possible, or just call _recv_message
                    # if it's non-blocking. But here _recv_message is blocking.
                    # However, since we are waiting for a response to OUR request,
                    # it's likely to arrive soon.
                    self._transport._recv_message()
                except Exception as e:
                    # If it's a timeout, just continue. Otherwise, it might be a real error.
                    if "Timeout" in str(e):
                        continue
                    raise ChannelException(
                        f"Error waiting for channel request response: {e}"
                    )

            raise ChannelException("Timeout waiting for channel request response")

        return True  # No reply requested

    def send_eof(self) -> None:
        """
        Send EOF to remote side.

        Raises:
            ChannelException: If EOF send fails
        """
        with self._lock:
            if self._closed:
                raise ChannelException("Channel is closed")

            if self._eof_sent:
                return  # Already sent

            if self._remote_channel_id is None:
                raise ChannelException("Channel not properly opened")

            try:
                self._transport._send_channel_eof(self._channel_id)
                self._eof_sent = True
            except Exception as e:
                raise ChannelException(f"Failed to send EOF: {e}")

    def recv_stderr(self, nbytes: int) -> bytes:
        """
        Receive stderr data from channel.

        Args:
            nbytes: Maximum bytes to receive

        Returns:
            Received stderr data

        Raises:
            ChannelException: If receive operation fails
        """
        if nbytes <= 0:
            return b""

        with self._lock:
            if self._closed:
                raise ChannelException("Channel is closed")

            # Check if we have stderr data in buffer
            if self._stderr_buffer:
                # Get data from buffer
                data_chunk = self._stderr_buffer.popleft()

                if len(data_chunk) <= nbytes:
                    # Return entire chunk
                    return data_chunk
                else:
                    # Split chunk and put remainder back
                    result = data_chunk[:nbytes]
                    remainder = data_chunk[nbytes:]
                    self._stderr_buffer.appendleft(remainder)
                    return result

            # No stderr data available
            return b""

    def close(self) -> None:
        """Close channel and cleanup resources."""
        with self._lock:
            if not self._closed:
                self._closed = True
                # Notify transport to close channel
                self._transport._close_channel(self._channel_id)

    def _handle_data(self, data: bytes) -> None:
        """
        Handle incoming data from transport.

        Args:
            data: Received data
        """
        with self._lock:
            if not self._closed:
                self._recv_buffer.append(data)
                self._data_event.set()

                # Send window adjust if buffer is getting full
                if len(self._recv_buffer) > 10:  # Simple flow control
                    self._transport._send_channel_window_adjust(
                        self._channel_id, len(data)
                    )

    def _handle_extended_data(self, data_type: int, data: bytes) -> None:
        """
        Handle incoming extended data (stderr) from transport.

        Args:
            data_type: Extended data type
            data: Received data
        """
        with self._lock:
            if not self._closed and data_type == 1:  # SSH_EXTENDED_DATA_STDERR
                self._stderr_buffer.append(data)
                self._data_event.set()

    def _handle_eof(self) -> None:
        """Handle EOF from remote side."""
        with self._lock:
            self._eof_received = True
            self._data_event.set()

    def _handle_close(self) -> None:
        """Handle close from remote side."""
        with self._lock:
            self._closed = True
            self._data_event.set()

    def _handle_window_adjust(self, bytes_to_add: int) -> None:
        """
        Handle window adjust from remote side.

        Args:
            bytes_to_add: Bytes to add to remote window
        """
        with self._lock:
            self._remote_window_size += bytes_to_add

    def _handle_request_success(self) -> None:
        """Handle request success from remote side."""
        with self._lock:
            self._request_success = True
            self._request_event.set()

    def _handle_request_failure(self) -> None:
        """Handle request failure from remote side."""
        with self._lock:
            self._request_success = False
            self._request_event.set()

    def _handle_exit_status(self, exit_status: int) -> None:
        """
        Handle exit status from remote side.

        Args:
            exit_status: Command exit status
        """
        with self._lock:
            self._exit_status = exit_status

    def _handle_exit_signal(
        self, signal_name: str, core_dumped: bool, error_message: str, language_tag: str
    ) -> None:
        """
        Handle exit signal from remote side.

        Args:
            signal_name: Signal name that caused termination
            core_dumped: Whether core was dumped
            error_message: Error message
            language_tag: Language tag for error message
        """
        with self._lock:
            # Set exit status to indicate signal termination
            # Use convention: 128 + signal number (approximation)
            self._exit_status = 128
            # Store signal info for debugging
            self._exit_signal = {
                "signal_name": signal_name,
                "core_dumped": core_dumped,
                "error_message": error_message,
                "language_tag": language_tag,
            }

    @property
    def closed(self) -> bool:
        """Check if channel is closed."""
        return self._closed

    @property
    def channel_id(self) -> int:
        """Get channel ID."""
        return self._channel_id

    @property
    def eof_received(self) -> bool:
        """Check if EOF was received."""
        return self._eof_received
