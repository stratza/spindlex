"""
SSH Channel Implementation

Represents individual communication channels within SSH connections
with support for different channel types and operations.
"""

import logging
import socket
import threading
import time
from collections import deque
from typing import Any, Optional, Union

from ..exceptions import ChannelException, ProtocolException
from ..protocol.constants import (
    DEFAULT_WINDOW_SIZE,
    SSH_EXTENDED_DATA_STDERR,
    SSH_STRING_ENCODING,
)
from ..protocol.utils import read_boolean, read_string, read_uint32


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
        # Bytes the peer may still send before it must wait for a
        # WINDOW_ADJUST. Seeded lazily from the local window on first data,
        # decremented as data arrives, replenished when we send an adjust. A
        # peer that overruns it is violating RFC 4254 flow control and is cut
        # off rather than allowed to grow our buffer without bound.
        self._inbound_window_remaining: Optional[int] = None

        # Data buffers - declared as Any because AsyncChannel overrides these with
        # plain bytes (flat buffer, sliceable) vs the deque[bytes] used here.
        self._recv_buffer: Any = deque()
        self._stderr_buffer: Any = deque()

        # Flow control
        self._eof_received = False
        self._eof_sent = False

        # Close handshake (RFC 4254 s5.3): each side sends exactly one
        # SSH_MSG_CHANNEL_CLOSE, and the channel number may only be reused once
        # both have been exchanged.
        self._close_sent = False
        self._close_received = False
        # Set by the transport while a peer's channel request is being handled,
        # so a close() from inside the request callback is sent after the reply.
        self._handling_request = False
        self._close_deferred = False
        # A window adjust is being sent by another reader of this channel.
        self._window_adjust_pending = False

        # Request handling
        self._request_success: Optional[bool] = None

        # Threading.
        # Lock order: the transport's reader dispatches incoming packets while
        # holding the transport lock and then takes this channel's ``_lock``
        # (transport -> channel). So this channel must never call into the
        # transport while holding ``_lock``; outgoing operations are serialised
        # by ``_send_lock`` instead, which the transport never takes.
        self._lock = threading.RLock()
        self._send_lock = threading.Lock()
        self._data_event = threading.Event()
        self._window_event = threading.Event()
        self._request_event = threading.Event()
        self._exit_status_event = threading.Event()
        self._timeout: Optional[float] = None
        self._logger = logging.getLogger(__name__)

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

    def fileno(self) -> int:
        """Return -1: channels have no OS file descriptor.

        Required so that a Channel can be passed as the ``sock`` argument to
        :class:`~spindlex.transport.transport.Transport` and used as a ProxyJump
        socket for bastion-host connections.  The transport guards all
        ``fcntl``/``select`` paths with ``fileno() != -1`` checks, so returning
        -1 safely bypasses those paths while still allowing ``send``/``recv``
        to work normally.
        """
        return -1

    def getsockname(self) -> tuple[str, int]:
        """Return a dummy local address; channels have no bound port."""
        return ("", 0)

    def getpeername(self) -> tuple[str, int]:
        """Return a dummy remote address; channels carry no peer IP directly."""
        return ("", 0)

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
        return self._send_chunk(data, timeout, None)

    def send_stderr(
        self, data: Union[bytes, str], timeout: Optional[float] = None
    ) -> int:
        """
        Send data on the stderr stream (SSH_MSG_CHANNEL_EXTENDED_DATA).

        Typically used by servers for a command's error output. Like send(),
        sends at most one packet and returns the number of bytes sent.
        """
        return self._send_chunk(data, timeout, SSH_EXTENDED_DATA_STDERR)

    def sendall_stderr(
        self, data: Union[bytes, str], timeout: Optional[float] = None
    ) -> None:
        """Send all of ``data`` on the stderr stream."""
        if isinstance(data, str):
            data = data.encode(SSH_STRING_ENCODING)
        total_sent = 0
        while total_sent < len(data):
            sent = self.send_stderr(data[total_sent:], timeout=timeout)
            if sent <= 0:
                raise ChannelException("Failed to send data")
            total_sent += sent

    def _send_chunk(
        self,
        data: Union[bytes, str],
        timeout: Optional[float],
        data_type: Optional[int],
    ) -> int:
        """Send one packet's worth of data (extended data if data_type set)."""
        if not data:
            return 0

        # Convert string to bytes if needed
        if isinstance(data, str):
            data = data.encode(SSH_STRING_ENCODING)

        start_time = time.monotonic()

        # Use effective timeout
        effective_timeout = timeout if timeout is not None else self._timeout

        deadline = (
            start_time + effective_timeout if effective_timeout is not None else None
        )

        with self._send_lock:
            while True:
                with self._lock:
                    if self._closed:
                        raise ChannelException("Channel is closed")

                    if self._eof_sent:
                        raise ChannelException("EOF already sent on channel")

                    if self._remote_channel_id is None:
                        raise ChannelException("Channel not properly opened")

                    if self._remote_window_size > 0:
                        # Send at most one packet (to match standard send() behavior)
                        can_send = min(
                            len(data),
                            self._remote_window_size,
                            self._remote_max_packet_size,
                        )
                        break

                    # Check timeout
                    if deadline is not None and time.monotonic() >= deadline:
                        raise ChannelException("Timeout waiting for window space")
                    self._window_event.clear()

                # Wait for a window adjust (or close) without holding _lock
                try:
                    self._wait_for_transport(self._window_event, deadline)
                except socket.timeout:
                    pass  # Retry after window adjust
                except Exception as e:
                    raise ChannelException(f"Transport error during send: {e}") from e

            if can_send <= 0:
                return 0

            chunk = data[:can_send]

            try:
                # Send data through transport (window can only have grown
                # since it was checked: other senders are excluded).
                if data_type is None:
                    self._transport._send_channel_data(self._channel_id, chunk)
                else:
                    self._transport._send_channel_extended_data(
                        self._channel_id, chunk, data_type
                    )
            except Exception as e:
                raise ChannelException(f"Failed to send data: {e}") from e

            with self._lock:
                self._remote_window_size -= len(chunk)
            return len(chunk)

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

        start_time = time.monotonic()
        while True:
            result: Optional[bytes] = None
            with self._lock:
                # Check if we have data in buffer
                if self._recv_buffer:
                    # Get data from buffer
                    data_chunk = self._recv_buffer.popleft()

                    if len(data_chunk) <= nbytes:
                        # Return entire chunk
                        result = bytes(data_chunk)
                    else:
                        # Split chunk and put remainder back
                        result = bytes(data_chunk[:nbytes])
                        self._recv_buffer.appendleft(data_chunk[nbytes:])
            if result is not None:
                self._adjust_window(len(result))
                return result

            with self._lock:
                if self._recv_buffer:
                    continue  # data arrived since the check above

                # No data available in buffer
                if self._eof_received or self._closed or not self._transport.active:
                    return b""  # EOF, channel closed, or transport inactive

                # Check total timeout
                if self._timeout is not None:
                    elapsed = time.monotonic() - start_time
                    if elapsed >= self._timeout:
                        raise ChannelException("Timeout receiving data")

                # Clear event before we start waiting
                self._data_event.clear()

            deadline = start_time + self._timeout if self._timeout is not None else None
            try:
                self._wait_for_transport(self._data_event, deadline)
            except socket.timeout:
                pass  # Loop back so the channel-timeout check at the top fires.

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

    def recv_exit_status(self, timeout: Optional[float] = None) -> int:
        """
        Wait for and return command exit status.

        Args:
            timeout: Optional timeout in seconds. If None, uses channel timeout.

        Returns:
            Exit status code

        Raises:
            ChannelException: If timeout reached
        """
        effective_timeout = timeout if timeout is not None else self._timeout

        if self._exit_status is not None:
            return self.get_exit_status()

        start_time = time.monotonic()
        deadline = (
            start_time + effective_timeout if effective_timeout is not None else None
        )
        while self._exit_status is None and not self._closed:
            if deadline is not None and time.monotonic() >= deadline:
                raise ChannelException("Timeout waiting for exit status")
            try:
                self._wait_for_transport(self._exit_status_event, deadline)
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
        with self._send_lock:
            with self._lock:
                if self._closed:
                    raise ChannelException("Channel is closed")

                if self._remote_channel_id is None:
                    raise ChannelException("Channel not properly opened")

                if want_reply:
                    self._request_success = None
                    self._request_event.clear()

            try:
                self._transport._send_channel_request(
                    self._channel_id, request_type, want_reply, data
                )
            except Exception as e:
                raise ChannelException(f"Failed to send channel request: {e}") from e

        if not want_reply:
            return True

        start_time = time.monotonic()
        while True:
            with self._lock:
                if self._request_success is not None:
                    return self._request_success
                if self._closed:
                    raise ChannelException(
                        "Channel closed while waiting for request response"
                    )

            if self._timeout is not None:
                elapsed = time.monotonic() - start_time
                if elapsed >= self._timeout:
                    raise ChannelException(
                        "Timeout waiting for channel request response"
                    )

            deadline = start_time + self._timeout if self._timeout is not None else None
            try:
                self._wait_for_transport(self._request_event, deadline)
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
        with self._send_lock:
            with self._lock:
                if self._closed:
                    raise ChannelException("Channel is closed")

                if self._eof_sent:
                    return  # Already sent

                if self._remote_channel_id is None:
                    raise ChannelException("Channel not properly opened")

            try:
                self._transport._send_channel_eof(self._channel_id)
            except Exception as e:
                raise ChannelException(f"Failed to send EOF: {e}") from e
            with self._lock:
                self._eof_sent = True

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

        start_time = time.monotonic()
        while True:
            result: Optional[bytes] = None
            with self._lock:
                # Check if we have stderr data in buffer
                if self._stderr_buffer:
                    # Get data from buffer
                    data_chunk = self._stderr_buffer.popleft()

                    if len(data_chunk) <= nbytes:
                        # Return entire chunk
                        result = bytes(data_chunk)
                    else:
                        # Split chunk and put remainder back
                        result = bytes(data_chunk[:nbytes])
                        self._stderr_buffer.appendleft(data_chunk[nbytes:])
            if result is not None:
                self._adjust_window(len(result))
                return result

            with self._lock:
                if self._stderr_buffer:
                    continue  # data arrived since the check above

                # No stderr data available in buffer. Data that arrived before
                # the peer closed the channel is still returned above.
                if self._eof_received or self._closed or not self._transport.active:
                    return b""  # EOF reached and buffer is empty

                # Check total timeout
                if self._timeout is not None:
                    elapsed = time.monotonic() - start_time
                    if elapsed >= self._timeout:
                        raise ChannelException("Timeout receiving stderr data")

                # Clear event before we start waiting
                self._data_event.clear()

            deadline = start_time + self._timeout if self._timeout is not None else None
            try:
                self._wait_for_transport(self._data_event, deadline)
            except Exception as e:
                if "timeout" not in str(e).lower():
                    raise

    def close(self) -> None:
        """Close channel and cleanup resources.

        Sends SSH_MSG_CHANNEL_CLOSE unless it was already sent (for example as
        the reply to the peer's close).
        """
        with self._lock:
            self._closed = True
            already_sent = self._close_sent
            self._data_event.set()
            self._window_event.set()
        # Call into the transport without holding the channel lock: the
        # transport's reader takes the transport lock before the channel's.
        if not already_sent:
            self._transport._close_channel(self._channel_id)

    def _wait_for_transport(
        self, event: threading.Event, deadline: Optional[float]
    ) -> None:
        """Wait until ``event`` may have been set, reading the transport if no
        other thread is.

        Only one thread can read the socket at a time. If another thread holds
        the transport's read lock (a server connection loop, another channel's
        recv(), ...) it dispatches incoming packets for every channel, so this
        thread waits on its own event instead of queueing up behind a reader
        that may be blocked in socket.recv() indefinitely.
        """
        transport = self._transport
        remaining: Optional[float] = None
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return
        slice_ = 0.1 if remaining is None else min(0.1, remaining)

        # A key exchange is being driven by a background thread; it delivers
        # channel traffic as it reads.
        if getattr(transport, "_kex_thread", None) is not None:
            event.wait(timeout=slice_)
            return

        read_lock = getattr(transport, "_read_lock", None)
        if read_lock is not None and not read_lock.acquire(blocking=False):
            event.wait(timeout=slice_)
            return
        try:
            if remaining is not None and not getattr(transport, "_packet_buffer", b""):
                # Bound the socket wait so the caller's deadline is honoured.
                sock = getattr(transport, "_socket", None)
                if sock is not None:
                    import select as _select

                    try:
                        readable, _, _ = _select.select(
                            [sock], [], [], min(1.0, remaining)
                        )
                    except (OSError, ValueError, TypeError) as e:
                        self._logger.debug(f"Select error (expected on close): {e}")
                        readable = [sock]
                    if not readable:
                        return
            transport._pump()
        finally:
            if read_lock is not None:
                read_lock.release()

    def shutdown(self, how: int) -> None:
        """
        Shutdown channel (socket-compatible).

        Args:
            how: ``socket.SHUT_WR`` sends EOF (the peer can still send to
                us), ``socket.SHUT_RD`` stops delivering further data to this
                end, ``socket.SHUT_RDWR`` closes the channel.
        """
        if how == socket.SHUT_WR:
            self.send_eof()
        elif how == socket.SHUT_RD:
            with self._lock:
                self._eof_received = True
                self._recv_buffer.clear()
                self._data_event.set()
        else:
            self.close()

    def shutdown_write(self) -> None:
        """Send EOF; the peer may still send data to us."""
        self.shutdown(socket.SHUT_WR)

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
        bytes_to_add = 0
        with self._lock:
            self._local_window_size -= bytes_consumed
            if (
                self._local_window_size < DEFAULT_WINDOW_SIZE // 2
                and not self._window_adjust_pending
            ):
                bytes_to_add = DEFAULT_WINDOW_SIZE - self._local_window_size
                self._window_adjust_pending = True

        if not bytes_to_add:
            return
        # Send without holding _lock (see the lock-order note in __init__).
        # _send_channel_window_adjust increments _local_window_size itself -
        # do not double-count here.
        try:
            self._transport._send_channel_window_adjust(self._channel_id, bytes_to_add)
        finally:
            with self._lock:
                self._window_adjust_pending = False
                # Credit the same amount back to the inbound-overrun accounting.
                if self._inbound_window_remaining is not None:
                    self._inbound_window_remaining += bytes_to_add

    def _handle_data(self, data: bytes) -> None:
        """
        Handle incoming data from transport.

        Args:
            data: Received data
        """
        overrun = False
        with self._lock:
            if not self._closed:
                overrun = self._check_inbound_window(len(data))
                if not overrun:
                    self._recv_buffer.append(data)
                    self._data_event.set()
        if overrun:
            self._close_after_overrun()

    def _check_inbound_window(self, nbytes: int) -> bool:
        """Account for inbound bytes against the advertised window.

        Returns True if the peer overran the window (the channel is closed as a
        side effect) and the data must be dropped.
        """
        # Only enforce when a real local window has been advertised. If the
        # window is unset (0), flow control is not in effect for this channel
        # and we must not drop data.
        if not self._local_window_size:
            return False
        if self._inbound_window_remaining is None:
            self._inbound_window_remaining = self._local_window_size
        self._inbound_window_remaining -= nbytes
        # Allow one max-packet of slack for adjust timing, then treat an overrun
        # as a protocol violation.
        slack = self._local_max_packet_size or 0
        if self._inbound_window_remaining < -slack:
            self._logger.warning(
                "Channel %d peer exceeded advertised window; closing",
                self._channel_id,
            )
            self._closed = True
            self._data_event.set()
            self._window_event.set()
            return True
        return False

    def _close_after_overrun(self) -> None:
        """Tell the peer the channel is closed after it overran our window."""
        try:
            self._transport._close_channel(self._channel_id)
        except Exception as e:  # best effort; the channel is unusable anyway
            self._logger.debug(f"Close after window overrun failed: {e}")

    def _handle_extended_data(self, data_type: int, data: bytes) -> None:
        """
        Handle incoming extended data (stderr) from transport.

        Args:
            data_type: Extended data type
            data: Received data
        """
        overrun = False
        with self._lock:
            if not self._closed and data_type == 1:  # SSH_EXTENDED_DATA_STDERR
                overrun = self._check_inbound_window(len(data))
                if not overrun:
                    self._stderr_buffer.append(data)
                    self._data_event.set()
        if overrun:
            self._close_after_overrun()

    def _handle_eof(self) -> None:
        """Handle EOF from remote side."""
        with self._lock:
            self._eof_received = True
            self._data_event.set()

    def _handle_close(self) -> None:
        """Handle close from remote side."""
        with self._lock:
            self._closed = True
            self._close_received = True
            self._data_event.set()
            self._window_event.set()
            self._request_event.set()

    def _handle_window_adjust(self, bytes_to_add: int) -> None:
        """
        Handle window adjust from remote side.

        Args:
            bytes_to_add: Bytes to add to remote window
        """
        with self._lock:
            # RFC 4254 section 5.2: the window must not exceed 2^32 - 1.
            self._remote_window_size = min(
                self._remote_window_size + bytes_to_add, 0xFFFFFFFF
            )
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
        self._exit_status_event.set()

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

        except Exception as e:
            # Malformed request data or a failing server callback must not
            # kill the transport loop, but it must not be silent either.
            self._logger.warning(
                f"Channel request {request_type!r} handling failed: {e}"
            )
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
            # Map signal names to numbers (standard SSH signals as per RFC 4254)
            signals = {
                "ABRT": 6,
                "ALRM": 14,
                "FPE": 8,
                "HUP": 1,
                "ILL": 4,
                "INT": 2,
                "KILL": 9,
                "PIPE": 13,
                "QUIT": 3,
                "SEGV": 11,
                "TERM": 15,
                "USR1": 10,
                "USR2": 12,
            }
            # Remove SIG prefix if present (some implementations add it)
            clean_name = signal_name.upper()
            if clean_name.startswith("SIG"):
                clean_name = clean_name[3:]

            signum = signals.get(clean_name, 0)

            # Set exit status to indicate signal termination
            # Convention: 128 + signal number
            self._exit_status = 128 + signum
            self._exit_status_event.set()
            # Store signal info for debugging
            self._exit_signal = {
                "signal_name": signal_name,
                "core_dumped": core_dumped,
                "error_message": error_message,
                "language_tag": language_tag,
            }

    def get_exit_signal(self) -> Optional[dict[str, Any]]:
        """
        Get exit signal information if command was terminated by signal.

        Returns:
            Dictionary with signal info or None
        """
        with self._lock:
            return getattr(self, "_exit_signal", None)

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
