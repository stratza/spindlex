"""
SSH Channel Implementation

Represents individual communication channels within SSH connections
with support for different channel types and operations.
"""

import threading
import time
from collections import deque
from typing import Any, Optional, Union

from ..exceptions import ChannelException, ProtocolException
from ..protocol.constants import (
    DEFAULT_WINDOW_SIZE,
    SSH_STRING_ENCODING,
)
from ..protocol.utils import (
    read_boolean,
    read_string,
    read_uint32,
)


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
        self._recv_buffer: Any = deque()
        self._stderr_buffer: Any = deque()

        # Flow control
        self._eof_received = False
        self._eof_sent = False

        # Request handling
        self._request_success: Optional[bool] = None

        # Threading
        self._lock = threading.RLock()
        self._data_event = threading.Event()
        self._window_event = threading.Event()
        self._request_event = threading.Event()
        self._timeout: Optional[float] = None

    def settimeout(self, timeout: Optional[float]) -> None:
        """
        Set timeout for channel operations.

        Args:
            timeout: Timeout in seconds, or None for no timeout
        """
        self._timeout = timeout

    def gettimeout(self) -> Optional[float]:
        """
        Get channel timeout.

        Returns:
            Current timeout in seconds
        """
        return self._timeout

    def send(self, data: Union[bytes, str], timeout: Optional[float] = None) -> int:
        """
        Send data through channel.

        Args:
            data: Data to send (bytes or string)
            timeout: Optional timeout for this operation (overrides channel timeout)

        Returns:
            Number of bytes sent

        Raises:
            ChannelException: If send operation fails
        """
        if not data:
            return 0

        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode(SSH_STRING_ENCODING)

        start_time = time.time()

        # Use effective timeout
        effective_timeout = timeout if timeout is not None else self._timeout

        with self._lock:
            if self._closed:
                raise ChannelException("Channel is closed")

            if self._eof_sent:
                raise ChannelException("EOF already sent on channel")

            if self._remote_channel_id is None:
                raise ChannelException("Channel not properly opened")

            # Wait for window space if it's empty
            while self._remote_window_size <= 0:
                # Check timeout
                if effective_timeout is not None:
                    elapsed = time.time() - start_time
                    if elapsed >= effective_timeout:
                        raise ChannelException("Timeout waiting for window space")
                # Release lock and wait for window adjust or close
                self._window_event.clear()
                self._lock.release()
                try:
                    # If we're waiting for window space, we MUST pump the transport
                    # to process any incoming WINDOW_ADJUST messages from the server.
                    # Otherwise, we will wait forever in a single-threaded environment.
                    if not self._window_event.wait(timeout=0.1):
                        self._transport._pump()
                except Exception as e:
                    # Ignore timeout errors from pump
                    if "timeout" not in str(e).lower():
                        raise ChannelException(
                            f"Transport error during send: {e}"
                        ) from e
                finally:
                    self._lock.acquire()

                # Re-check channel state after waking up
                if self._closed:
                    raise ChannelException("Channel is closed while waiting")

            # We have some window space
            # Send at most one packet (to match standard send() behavior)
            can_send = min(
                len(data), self._remote_window_size, self._remote_max_packet_size
            )

            if can_send <= 0:
                return 0

            chunk = data[:can_send]

            try:
                # Send data through transport
                self._transport._send_channel_data(self._channel_id, chunk)

                # Update remote window size
                self._remote_window_size -= len(chunk)

                return len(chunk)

            except Exception as e:
                raise ChannelException(f"Failed to send data: {e}") from e

    def sendall(self, data: Union[bytes, str], timeout: Optional[float] = None) -> None:
        """
        Send all data through channel, retrying until all sent.

        Args:
            data: Data to send
            timeout: Optional timeout
        """
        if isinstance(data, str):
            data = data.encode(SSH_STRING_ENCODING)

        total_sent = 0
        while total_sent < len(data):
            sent = self.send(data[total_sent:], timeout=timeout)
            if sent <= 0:
                raise ChannelException("Failed to send data")
            total_sent += sent

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

        start_time = time.time()
        while True:
            with self._lock:
                # Check if we have data in buffer
                if self._recv_buffer:
                    # Get data from buffer
                    data_chunk = self._recv_buffer.popleft()

                    if len(data_chunk) <= nbytes:
                        # Return entire chunk
                        result = bytes(data_chunk)
                        self._adjust_window(len(result))
                        return result
                    else:
                        # Split chunk and put remainder back
                        result = data_chunk[:nbytes]
                        remainder = data_chunk[nbytes:]
                        self._recv_buffer.appendleft(remainder)
                        self._adjust_window(len(result))
                        return bytes(result)

                # No data available in buffer
                if self._eof_received or not self._transport.active:
                    return b""  # EOF reached or transport inactive

                # Check total timeout
                if self._timeout is not None:
                    elapsed = time.time() - start_time
                    if elapsed >= self._timeout:
                        raise ChannelException("Timeout receiving data")

                # Clear event before we start waiting
                self._data_event.clear()

            # If a background thread is pumping the transport (e.g. during
            # rekey or in async mode), wait for it to deliver data via the
            # event.  Otherwise drive _pump() directly — without this,
            # sync-mode recv() pays 100ms of dead wait time per packet.
            has_bg_thread = getattr(self._transport, "_kex_thread", None) is not None

            if has_bg_thread:
                wait_timeout = 0.1
                if self._timeout is not None:
                    elapsed = time.time() - start_time
                    wait_timeout = max(0, min(0.1, self._timeout - elapsed))
                self._data_event.wait(timeout=wait_timeout)
                continue

            try:
                # When a channel timeout is active, bound the socket wait via
                # select() so the deadline is honoured.  When there is no
                # channel timeout, _pump() blocks on socket.recv() until a
                # packet arrives — which is what we want.
                if self._timeout is not None:
                    elapsed = time.time() - start_time
                    remaining = self._timeout - elapsed
                    if remaining <= 0:
                        raise ChannelException("Timeout receiving data")

                    has_buffered = bool(getattr(self._transport, "_packet_buffer", b""))
                    if not has_buffered:
                        import select as _select

                        sock = getattr(self._transport, "_socket", None)
                        if sock is not None:
                            try:
                                r, _, _ = _select.select(
                                    [sock], [], [], min(1.0, remaining)
                                )
                                if not r:
                                    continue  # no data yet, loop back
                            except Exception:
                                pass  # fall through to _pump()

                self._transport._pump()
            except Exception as e:
                if "timeout" not in str(e).lower():
                    raise
                # Loop back so the channel-timeout check at the top fires.

    def recv_exactly(self, nbytes: int) -> bytes:
        """
        Receive exactly nbytes from channel.

        Args:
            nbytes: Number of bytes to receive

        Returns:
            Received data

        Raises:
            ChannelException: If receive fails or channel closed
        """
        data = b""
        while len(data) < nbytes:
            chunk = self.recv(nbytes - len(data))
            if not chunk:
                raise ChannelException("Connection closed while waiting for data")
            data += chunk
        return data

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

    def recv_exit_status(self) -> int:
        """
        Wait for and return command exit status.

        Returns:
            Exit status code
        """
        while self._exit_status is None and not self._closed:
            try:
                self._transport._pump()
            except Exception:
                break
        return self.get_exit_status()

    def send_exit_status(self, status: int) -> None:
        """
        Send command exit status to remote side.

        Args:
            status: Exit status code (typically 0 for success)

        Raises:
            ChannelException: If send fails
        """
        from ..protocol.utils import write_uint32

        # Build exit-status request data (4-byte unsigned integer)
        request_data = write_uint32(status)

        # Send exit-status request (no reply wanted for this type)
        self.send_channel_request("exit-status", want_reply=False, data=request_data)

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
                if want_reply:
                    self._request_success = None
                    self._request_event.clear()

                self._transport._send_channel_request(
                    self._channel_id, request_type, want_reply, data
                )
            except Exception as e:
                raise ChannelException(f"Failed to send channel request: {e}") from e

        if not want_reply:
            return True

        start_time = time.time()
        while True:
            with self._lock:
                if self._request_success is not None:
                    return self._request_success
                if self._closed:
                    raise ChannelException(
                        "Channel closed while waiting for request response"
                    )

            if self._timeout is not None:
                elapsed = time.time() - start_time
                if elapsed >= self._timeout:
                    raise ChannelException(
                        "Timeout waiting for channel request response"
                    )

            has_bg_thread = getattr(self._transport, "_kex_thread", None) is not None

            if has_bg_thread:
                wait_timeout = 0.1
                if self._timeout is not None:
                    elapsed = time.time() - start_time
                    wait_timeout = max(0, min(0.1, self._timeout - elapsed))
                self._request_event.wait(timeout=wait_timeout)
                continue

            try:
                self._transport._pump()
            except Exception as e:
                if "timeout" not in str(e).lower():
                    raise ChannelException(
                        f"Transport error during request: {e}"
                    ) from e

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
                raise ChannelException(f"Failed to send EOF: {e}") from e

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

        start_time = time.time()
        while True:
            with self._lock:
                if self._closed:
                    raise ChannelException("Channel is closed")

                # Check if we have stderr data in buffer
                if self._stderr_buffer:
                    # Get data from buffer
                    data_chunk = self._stderr_buffer.popleft()

                    if len(data_chunk) <= nbytes:
                        # Return entire chunk
                        result = bytes(data_chunk)
                        self._adjust_window(len(result))
                        return result
                    else:
                        # Split chunk and put remainder back
                        result = data_chunk[:nbytes]
                        remainder = data_chunk[nbytes:]
                        self._stderr_buffer.appendleft(remainder)
                        self._adjust_window(len(result))
                        return bytes(result)

                # No stderr data available in buffer
                if self._eof_received:
                    return b""  # EOF reached and buffer is empty

                # Check total timeout
                if self._timeout is not None:
                    elapsed = time.time() - start_time
                    if elapsed >= self._timeout:
                        raise ChannelException("Timeout receiving stderr data")

                # Clear event before we start waiting
                self._data_event.clear()

            # Same fast path as recv(): in sync mode, drive _pump() directly
            # rather than waiting on _data_event (which nothing else sets).
            has_bg_thread = getattr(self._transport, "_kex_thread", None) is not None

            if has_bg_thread:
                wait_timeout = 0.1
                if self._timeout is not None:
                    elapsed = time.time() - start_time
                    wait_timeout = max(0, min(0.1, self._timeout - elapsed))
                self._data_event.wait(timeout=wait_timeout)
                continue

            try:
                if self._timeout is not None:
                    elapsed = time.time() - start_time
                    remaining = self._timeout - elapsed
                    if remaining <= 0:
                        raise ChannelException("Timeout receiving stderr data")

                    has_buffered = bool(getattr(self._transport, "_packet_buffer", b""))
                    if not has_buffered:
                        import select as _select

                        sock = getattr(self._transport, "_socket", None)
                        if sock is not None:
                            try:
                                r, _, _ = _select.select(
                                    [sock], [], [], min(1.0, remaining)
                                )
                                if not r:
                                    continue
                            except Exception:
                                pass

                self._transport._pump()
            except Exception as e:
                if "timeout" not in str(e).lower():
                    raise

    def close(self) -> None:
        """Close channel and cleanup resources."""
        with self._lock:
            if not self._closed:
                self._closed = True
                # Notify transport to close channel
                self._transport._close_channel(self._channel_id)

    def __enter__(self) -> "Channel":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def _adjust_window(self, bytes_consumed: int) -> None:
        """
        Adjust local window size.

        Args:
            bytes_consumed: Number of bytes consumed from buffer
        """
        with self._lock:
            self._local_window_size -= bytes_consumed

            # Send window adjust if needed.  _send_channel_window_adjust
            # increments _local_window_size itself — do not double-count here.
            if self._local_window_size < DEFAULT_WINDOW_SIZE // 2:
                bytes_to_add = DEFAULT_WINDOW_SIZE - self._local_window_size
                self._transport._send_channel_window_adjust(
                    self._channel_id, bytes_to_add
                )

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
            self._window_event.set()

    def _handle_window_adjust(self, bytes_to_add: int) -> None:
        """
        Handle window adjust from remote side.

        Args:
            bytes_to_add: Bytes to add to remote window
        """
        with self._lock:
            self._remote_window_size += bytes_to_add
            self._window_event.set()

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

    def _handle_request(self, request_type: str, data: bytes) -> bool:
        """
        Handle incoming channel request from remote side.

        Args:
            request_type: Type of request (e.g., "shell", "exec")
            data: Request-specific data

        Returns:
            True if request was accepted, False otherwise
        """
        if request_type == "exit-status":
            if len(data) >= 4:
                status, _ = read_uint32(data, 0)
                self._handle_exit_status(status)
            return True

        if request_type == "exit-signal":
            if len(data) >= 4:
                try:
                    offset = 0
                    signal_name_bytes, offset = read_string(data, offset)
                    core_dumped, offset = read_boolean(data, offset)
                    error_msg_bytes, offset = read_string(data, offset)
                    lang_tag_bytes, offset = read_string(data, offset)

                    signal_name = signal_name_bytes.decode(SSH_STRING_ENCODING)
                    error_msg = error_msg_bytes.decode(SSH_STRING_ENCODING)
                    lang_tag = lang_tag_bytes.decode(SSH_STRING_ENCODING)

                    self._handle_exit_signal(
                        signal_name, core_dumped, error_msg, lang_tag
                    )
                except (ProtocolException, UnicodeDecodeError):
                    pass
            return True

        if not self._transport._server_mode or not self._transport._server_interface:
            return False

        server = self._transport._server_interface

        try:
            if request_type == "shell":
                return bool(server.check_channel_shell_request(self))

            elif request_type == "exec":
                command_bytes, _ = read_string(data, 0)
                return bool(server.check_channel_exec_request(self, command_bytes))

            elif request_type == "subsystem":
                subsystem_bytes, _ = read_string(data, 0)
                subsystem = subsystem_bytes.decode(SSH_STRING_ENCODING)
                return bool(server.check_channel_subsystem_request(self, subsystem))

            elif request_type == "pty-req":
                offset = 0
                term_bytes, offset = read_string(data, offset)
                term = term_bytes.decode(SSH_STRING_ENCODING)
                width, offset = read_uint32(data, offset)
                height, offset = read_uint32(data, offset)
                pixelwidth, offset = read_uint32(data, offset)
                pixelheight, offset = read_uint32(data, offset)
                modes, offset = read_string(data, offset)

                return bool(
                    server.check_channel_pty_request(
                        self, term, width, height, pixelwidth, pixelheight, modes
                    )
                )

            elif request_type == "window-change":
                offset = 0
                width, offset = read_uint32(data, offset)
                height, offset = read_uint32(data, offset)
                pixelwidth, offset = read_uint32(data, offset)
                pixelheight, offset = read_uint32(data, offset)

                return bool(
                    server.check_channel_window_change_request(
                        self, width, height, pixelwidth, pixelheight
                    )
                )

            elif request_type == "env":
                offset = 0
                variable_name_bytes, offset = read_string(data, offset)
                variable_value_bytes, offset = read_string(data, offset)
                name = variable_name_bytes.decode(SSH_STRING_ENCODING)
                value = variable_value_bytes.decode(SSH_STRING_ENCODING)

                return bool(server.check_channel_env_request(self, name, value))

            elif request_type == "x11-req":
                offset = 0
                single_connection, offset = read_boolean(data, offset)
                auth_protocol_bytes, offset = read_string(data, offset)
                auth_cookie_bytes, offset = read_string(data, offset)
                screen_number, offset = read_uint32(data, offset)

                auth_protocol = auth_protocol_bytes.decode(SSH_STRING_ENCODING)

                return bool(
                    server.check_channel_x11_request(
                        self,
                        single_connection,
                        auth_protocol,
                        auth_cookie_bytes,
                        screen_number,
                    )
                )

            # Unknown request type
            return False

        except Exception:
            return False

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
