"""
SFTP Client Implementation

Provides SFTP (SSH File Transfer Protocol) client functionality for
secure file operations over SSH connections.
"""

import logging
import os
import struct
import threading
import time
from typing import Any, Optional

from ..exceptions import SFTPError, SSHException
from ..protocol.sftp_constants import (
    SFTP_MAX_READ_SIZE,
    SFTP_SUBSYSTEM,
    SFTP_VERSION,
    SSH_FILEXFER_ATTR_PERMISSIONS,
    SSH_FILEXFER_ATTR_SIZE,
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
    SFTPCloseMessage,
    SFTPDataMessage,
    SFTPExtendedMessage,
    SFTPExtendedReplyMessage,
    SFTPHandleMessage,
    SFTPInitMessage,
    SFTPMessage,
    SFTPOpenMessage,
    SFTPReadMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
    SFTPWriteMessage,
)
from ..transport.channel import Channel
from ..transport.transport import Transport

# Read/write chunk sizes when the server does not advertise its limits via
# limits@openssh.com. 32 KiB is the largest size every SFTP server must accept
# (draft-ietf-secsh-filexfer); bigger requests may be truncated or refused.
_DEFAULT_MAX_WRITE = 32768
_DEFAULT_MAX_READ = 32768


# Recursive transfers stop below this many directory levels.
_MAX_RECURSION_DEPTH = 64


def _mode_to_flags(mode: str) -> int:
    """Convert a Python file mode string to SFTP open flags.

    ``r`` read, ``w`` create/truncate, ``a`` create/append, ``x`` exclusive
    create; ``+`` adds the other direction (so ``r+`` can write and ``w+``
    can read).
    """
    flags = 0
    if "r" in mode:
        flags |= SSH_FXF_READ
    if "w" in mode:
        flags |= SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC
    if "a" in mode:
        flags |= SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_APPEND
    if "x" in mode:
        flags |= SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_EXCL
    if "+" in mode:
        flags |= SSH_FXF_READ | SSH_FXF_WRITE
    return flags


def _is_unsafe_remote_name(name: str) -> bool:
    """Return True if a server-supplied directory entry must not be joined
    into a local path.

    A malicious or compromised server controls the names returned by READDIR.
    A name containing a path separator, a drive letter, a leading slash, or a
    parent reference can escape the intended download directory (CVE-2019-6111
    class). On Windows ``\\`` is a separator too, so reject both. Callers use
    this to skip entries during recursive download.
    """
    if name in ("", ".", ".."):
        return True
    if "/" in name or "\\" in name or "\x00" in name:
        return True
    # Drive-relative ("C:...") or any absolute form.
    if os.path.isabs(name) or (len(name) >= 2 and name[1] == ":"):
        return True
    return False


class SFTPFile:
    """SFTP file object for remote file operations.

    Reads and writes share one file position (like a local file object);
    writes are pipelined and their acknowledgements collected lazily, so a
    read or seek first waits for outstanding writes.
    """

    _PIPELINE_DEPTH = 32

    def __init__(self, client: "SFTPClient", handle: bytes, mode: str) -> None:
        """
        Initialize SFTP file.

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
        self._write_queue: list[tuple[int, int]] = []  # (request_id, data_length)

    def tell(self) -> int:
        """Return the current file position."""
        return self._offset

    def seek(self, offset: int, whence: int = 0) -> int:
        """
        Move the file position.

        Args:
            offset: Position (whence=0), delta from the current position
                (whence=1) or from the end of the file (whence=2)
            whence: os.SEEK_SET, os.SEEK_CUR or os.SEEK_END

        Returns:
            The new position
        """
        if self._closed:
            raise SFTPError("File is closed")
        self._flush_write_queue()
        if whence == 0:
            new = offset
        elif whence == 1:
            new = self._offset + offset
        elif whence == 2:
            new = (self.stat().st_size or 0) + offset
        else:
            raise ValueError(f"Invalid whence: {whence}")
        if new < 0:
            raise ValueError("Negative seek position")
        self._offset = new
        return new

    def stat(self) -> SFTPAttributes:
        """Return the attributes of the open file (SSH_FXP_FSTAT)."""
        from ..protocol.sftp_messages import SFTPAttrsMessage, SFTPFStatMessage

        self._flush_write_queue()
        rid = self._client._get_next_request_id()
        response = self._client._send_request_and_wait_response(
            SFTPFStatMessage(rid, self._handle)
        )
        if isinstance(response, SFTPAttrsMessage):
            return response.attrs
        if isinstance(response, SFTPStatusMessage):
            raise SFTPError.from_status(response.status_code, response.message)
        raise SFTPError("Unexpected response to fstat request")

    def read(self, size: int = -1) -> bytes:
        """
        Read data from remote file.

        Args:
            size: Number of bytes to read (-1 for all)

        Returns:
            Read data
        """
        if self._closed:
            raise SFTPError("File is closed")

        # Outstanding writes must land before reading the same region.
        self._flush_write_queue()

        if size < 0:
            # Read until EOF using a pipelined window of concurrent requests.
            _CHUNK = self._client._max_read_len
            result = bytearray()
            in_flight: list[tuple[int, int]] = []  # (request_id, requested_len)
            eof = False
            offset = self._offset
            # Size of a short read that may be a server cap; only a cap if
            # more data follows (a short read can also just be the file's end).
            possible_cap = 0

            while not eof or in_flight:
                # After a short read, probe with a single request: at the end
                # of the file a full pipeline would only collect EOF replies.
                depth = 1 if possible_cap else self._PIPELINE_DEPTH
                while not eof and len(in_flight) < depth:
                    rid = self._client._get_next_request_id()
                    self._client._send_message(
                        SFTPReadMessage(rid, self._handle, offset, _CHUNK)
                    )
                    in_flight.append((rid, _CHUNK))
                    offset += _CHUNK

                if not in_flight:
                    break

                rid, requested = in_flight.pop(0)
                response = self._client._receive_message_for_id(rid)

                if isinstance(response, SFTPDataMessage):
                    result.extend(response.data)
                    if possible_cap and response.data:
                        # Data after the short read: the server caps reads.
                        self._client._note_short_read(possible_cap)
                        possible_cap = 0
                    if len(response.data) < requested:
                        # Short read (allowed by the SFTP spec): the remaining
                        # in-flight requests now target offsets past a gap.
                        # Drain and discard their responses, then restart the
                        # pipeline at the true end of the data received.
                        for stale_rid, _ in in_flight:
                            self._client._receive_message_for_id(stale_rid)
                        in_flight.clear()
                        offset = self._offset + len(result)
                        if not response.data:
                            eof = True
                        elif len(response.data) < _CHUNK:
                            # Either the end of the file or a server cap below
                            # our chunk size. Use the smaller size for the rest
                            # of this read; remember it for later reads only if
                            # more data follows (see above).
                            _CHUNK = possible_cap = len(response.data)
                elif isinstance(response, SFTPStatusMessage):
                    if response.status_code == SSH_FX_EOF:
                        eof = True
                    else:
                        raise SFTPError.from_status(
                            response.status_code, response.message
                        )
                else:
                    raise SFTPError("Unexpected response to read request")

            self._offset += len(result)
            return bytes(result)

        request_id = self._client._get_next_request_id()
        read_msg = SFTPReadMessage(request_id, self._handle, self._offset, size)

        response = self._client._send_request_and_wait_response(read_msg)

        if isinstance(response, SFTPDataMessage):
            self._offset += len(response.data)
            return response.data
        elif isinstance(response, SFTPStatusMessage):
            if response.status_code == SSH_FX_EOF:
                return b""
            raise SFTPError.from_status(response.status_code, response.message)
        else:
            raise SFTPError("Unexpected response to read request")

    def write(self, data: bytes) -> int:
        """
        Write data to remote file at the current position.

        Args:
            data: Data to write

        Returns:
            Number of bytes written
        """
        if self._closed:
            raise SFTPError("File is closed")

        _MAX_CHUNK = self._client._max_write_len
        offset = 0
        while offset < len(data):
            chunk = data[offset : offset + _MAX_CHUNK]
            request_id = self._client._get_next_request_id()
            write_msg = SFTPWriteMessage(request_id, self._handle, self._offset, chunk)
            self._client._send_message(write_msg)
            chunk_len = len(chunk)
            self._offset += chunk_len
            self._write_queue.append((request_id, chunk_len))

            # Collect the oldest pending ACK when the pipeline is full so we
            # surface write errors promptly and keep memory usage bounded.
            if len(self._write_queue) >= self._PIPELINE_DEPTH:
                rid, _nbytes = self._write_queue.pop(0)
                self._check_write_ack(self._client._receive_message_for_id(rid))

            offset += chunk_len

        return len(data)

    @staticmethod
    def _check_write_ack(response: SFTPMessage) -> None:
        if isinstance(response, SFTPStatusMessage):
            if response.status_code != SSH_FX_OK:
                raise SFTPError.from_status(response.status_code, response.message)
        else:
            raise SFTPError("Unexpected response to write request")

    def _flush_write_queue(self) -> None:
        """Drain all outstanding pipelined write ACKs."""
        queue, self._write_queue = self._write_queue, []
        for rid, _nbytes in queue:
            self._check_write_ack(self._client._receive_message_for_id(rid))

    def flush(self) -> None:
        """Wait until all written data has been acknowledged by the server."""
        self._flush_write_queue()

    def close(self) -> None:
        """Close remote file."""
        if not self._closed:
            self._closed = True
            try:
                self._flush_write_queue()
            finally:
                request_id = self._client._get_next_request_id()
                close_msg = SFTPCloseMessage(request_id, self._handle)
                self._client._send_request_and_wait_response(close_msg)

    def __enter__(self) -> "SFTPFile":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()


class SFTPClient:
    """
    SFTP client for secure file operations.

    Implements SFTP protocol for file transfer, directory operations,
    and file attribute management over SSH connections.
    """

    def __init__(self, transport: Transport) -> None:
        """
        Initialize SFTP client with SSH transport.

        Args:
            transport: SSH transport instance

        Raises:
            SFTPError: If SFTP initialization fails
        """
        self._transport = transport
        self._channel: Optional[Channel] = None
        self._request_id = 0
        self._request_lock = threading.Lock()
        self._logger = logging.getLogger(__name__)
        self._server_version: Optional[int] = None
        self._server_extensions: dict[str, str] = {}
        self._pending_responses: dict[int, SFTPMessage] = {}
        self._max_write_len: int = _DEFAULT_MAX_WRITE
        self._max_read_len: int = _DEFAULT_MAX_READ

        # Initialize SFTP session
        self._initialize_sftp()

    def _initialize_sftp(self) -> None:
        """
        Initialize SFTP subsystem and perform version negotiation.

        Raises:
            SFTPError: If SFTP initialization fails
        """
        try:
            # Open channel for SFTP subsystem
            self._channel = self._transport.open_channel("session")
            if not self._channel:
                raise SFTPError("Failed to open channel for SFTP")

            # Prevent recv() from spinning forever when no response arrives
            self._channel.settimeout(30.0)

            # Request SFTP subsystem
            self._channel.invoke_subsystem(SFTP_SUBSYSTEM)

            # Send SFTP init message
            init_msg = SFTPInitMessage(SFTP_VERSION)
            self._send_message(init_msg)

            # Wait for version response
            response = self._receive_message()
            if not isinstance(response, SFTPVersionMessage):
                raise SFTPError("Expected SFTP version message")

            self._server_version = response.version
            self._server_extensions = response.extensions

            if self._server_version < SFTP_VERSION:
                self._logger.warning(
                    f"Server SFTP version {self._server_version} < {SFTP_VERSION}"
                )

            # Query server limits via limits@openssh.com extension.
            # This allows much larger write chunks (e.g. 255 KB) instead of
            # the protocol default of 64 KB, cutting round trips for large uploads.
            if self._server_extensions.get("limits@openssh.com") == "1":
                self._query_limits()

            self._logger.debug(
                f"SFTP initialized, server version: {self._server_version}, "
                f"max_write_len: {self._max_write_len}"
            )

        except Exception as e:
            if self._channel:
                self._channel.close()
                self._channel = None
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"SFTP initialization failed: {e}") from e

    def _query_limits(self) -> None:
        """Query limits via limits@openssh.com; update read/write chunk sizes."""
        try:
            request_id = self._get_next_request_id()
            self._send_message(SFTPExtendedMessage(request_id, "limits@openssh.com"))
            response = self._receive_message_for_id(request_id, timeout=10.0)
            if isinstance(response, SFTPExtendedReplyMessage):
                data = response.extended_data
                if len(data) >= 32:
                    _max_pkt, max_read, max_write, _max_handles = struct.unpack(
                        ">QQQQ", data[:32]
                    )
                    if max_write > 0:
                        self._max_write_len = int(max_write)
                    if max_read > 0:
                        self._max_read_len = int(max_read)
                    else:
                        # 0 means "no limit": use the largest size we request.
                        self._max_read_len = SFTP_MAX_READ_SIZE
        except (SFTPError, SSHException, struct.error, OSError):
            pass  # non-fatal: server does not support limits@openssh.com

    def _note_short_read(self, length: int) -> None:
        """A read came back short and more data followed it: the server caps
        reads at ``length``, so request that much from now on. (A short read
        at the end of a file says nothing about the server's limit.)"""
        if 0 < length < self._max_read_len:
            self._max_read_len = length

    def _get_next_request_id(self) -> int:
        """Get next request ID for SFTP messages."""
        with self._request_lock:
            self._request_id += 1
            return self._request_id

    def _send_message(self, message: SFTPMessage) -> None:
        """
        Send SFTP message over channel.

        Args:
            message: SFTP message to send

        Raises:
            SFTPError: If message sending fails
        """
        if not self._channel:
            raise SFTPError("SFTP channel not available")

        try:
            data = message.pack()
            self._channel.sendall(data)
        except Exception as e:
            raise SFTPError(f"Failed to send SFTP message: {e}") from e

    def _receive_message(self) -> SFTPMessage:
        """
        Receive SFTP message from channel.

        Returns:
            Received SFTP message

        Raises:
            SFTPError: If message receiving fails
        """
        if not self._channel:
            raise SFTPError("SFTP channel not available")

        try:
            # Read message length first (4 bytes)
            length_data = self._channel.recv_exactly(4)
            msg_length = int.from_bytes(length_data, "big")

            # Read message content (msg_length bytes)
            # The payload does NOT include the length itself in SFTP packets
            # but SFTPMessage.unpack expects the length-prefixed data or just the payload?
            # Let's check SFTPMessage.unpack.
            payload = self._channel.recv_exactly(msg_length)
            msg_data = length_data + payload

            return SFTPMessage.unpack(msg_data)
        except Exception as e:
            raise SFTPError(f"Failed to receive SFTP message: {e}") from e

    def _receive_message_for_id(
        self, target_id: int, timeout: float = 60.0
    ) -> SFTPMessage:
        """
        Receive the SFTP response matching target_id, buffering any others.

        Enables pipelining by allowing out-of-order response collection.
        """
        if target_id in self._pending_responses:
            return self._pending_responses.pop(target_id)
        deadline = time.monotonic() + timeout
        while True:
            if time.monotonic() > deadline:
                raise SFTPError(f"Timeout waiting for response to request {target_id}")
            msg = self._receive_message()
            if msg.request_id == target_id:
                return msg
            if msg.request_id is not None:
                self._pending_responses[msg.request_id] = msg

    def _send_request_and_wait_response(self, request: SFTPMessage) -> SFTPMessage:
        """
        Send SFTP request and wait for response.

        Args:
            request: SFTP request message

        Returns:
            SFTP response message

        Raises:
            SFTPError: If request fails or response indicates error
        """
        self._send_message(request)
        if request.request_id is None:
            raise SFTPError("Request has no ID assigned")
        return self._receive_message_for_id(request.request_id)

    def get(self, remotepath: str, localpath: str) -> None:
        """
        Download file from remote server.

        Args:
            remotepath: Path to remote file
            localpath: Path for local file

        Raises:
            SFTPError: If file download fails
        """
        try:
            # Open remote file for reading
            request_id = self._get_next_request_id()
            attrs = SFTPAttributes()
            open_msg = SFTPOpenMessage(request_id, remotepath, SSH_FXF_READ, attrs)

            response = self._send_request_and_wait_response(open_msg)
            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
                else:
                    raise SFTPError("Unexpected status response to open request")
            elif not isinstance(response, SFTPHandleMessage):
                raise SFTPError("Expected handle message for file open")

            handle = response.handle

            try:
                # Open local file for writing
                _CHUNK = self._max_read_len
                _DEPTH = 32
                with open(localpath, "wb") as local_file:
                    offset = 0
                    in_flight: list[tuple[int, int]] = []  # (id, requested_len)
                    eof = False
                    # Size of a short read that may be a server cap; only a
                    # cap if more data follows (it can also be the file's end).
                    possible_cap = 0

                    while not eof or in_flight:
                        # Issue read requests to fill the pipeline
                        # After a short read, probe with a single request: at
                        # the end of the file a full pipeline would only
                        # collect EOF replies.
                        depth = 1 if possible_cap else _DEPTH
                        while not eof and len(in_flight) < depth:
                            request_id = self._get_next_request_id()
                            read_msg = SFTPReadMessage(
                                request_id, handle, offset, _CHUNK
                            )
                            self._send_message(read_msg)
                            in_flight.append((request_id, _CHUNK))
                            offset += _CHUNK

                        if not in_flight:
                            break

                        # Collect the next in-order response
                        rid, requested = in_flight.pop(0)
                        response = self._receive_message_for_id(rid)

                        if isinstance(response, SFTPDataMessage):
                            local_file.write(response.data)
                            if possible_cap and response.data:
                                # Data after the short read: the server caps
                                # reads at that size.
                                self._note_short_read(possible_cap)
                                possible_cap = 0
                            if len(response.data) < requested:
                                # Short read (allowed by the SFTP spec): the
                                # remaining in-flight requests now target
                                # offsets past a gap. Drain and discard their
                                # responses, then restart the pipeline at the
                                # true end of the data written so far.
                                for stale_rid, _ in in_flight:
                                    self._receive_message_for_id(stale_rid)
                                in_flight.clear()
                                offset = local_file.tell()
                                if not response.data:
                                    eof = True
                                elif len(response.data) < _CHUNK:
                                    # End of file or a server cap: use the
                                    # smaller size for the rest of this
                                    # transfer, and remember it only if more
                                    # data follows (see above).
                                    _CHUNK = possible_cap = len(response.data)
                        elif isinstance(response, SFTPStatusMessage):
                            if response.status_code == SSH_FX_EOF:
                                eof = True
                            else:
                                raise SFTPError.from_status(
                                    response.status_code, response.message
                                )
                        else:
                            raise SFTPError("Unexpected response to read request")

            finally:
                # Close remote file
                request_id = self._get_next_request_id()
                close_msg = SFTPCloseMessage(request_id, handle)
                self._send_request_and_wait_response(close_msg)

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File download failed: {e}", filename=remotepath) from e

    def put(self, localpath: str, remotepath: str) -> None:
        """
        Upload file to remote server.

        Args:
            localpath: Path to local file
            remotepath: Path for remote file

        Raises:
            SFTPError: If file upload fails
        """
        try:
            # Get local file size
            file_size = os.path.getsize(localpath)

            # Create attributes with file size
            attrs = SFTPAttributes()
            attrs.flags = SSH_FILEXFER_ATTR_SIZE
            attrs.size = file_size

            # Open remote file for writing
            request_id = self._get_next_request_id()
            pflags = SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC
            open_msg = SFTPOpenMessage(request_id, remotepath, pflags, attrs)

            response = self._send_request_and_wait_response(open_msg)
            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
                else:
                    raise SFTPError("Unexpected status response to open request")
            elif not isinstance(response, SFTPHandleMessage):
                raise SFTPError("Expected handle message for file open")

            handle = response.handle

            try:
                _CHUNK = self._max_write_len
                _DEPTH = 32
                with open(localpath, "rb") as local_file:
                    offset = 0
                    in_flight: list[int] = []

                    while True:
                        # Fill the pipeline with write requests
                        while len(in_flight) < _DEPTH:
                            chunk = local_file.read(_CHUNK)
                            if not chunk:
                                break
                            request_id = self._get_next_request_id()
                            write_msg = SFTPWriteMessage(
                                request_id, handle, offset, chunk
                            )
                            self._send_message(write_msg)
                            in_flight.append(request_id)
                            offset += len(chunk)

                        if not in_flight:
                            break

                        # Collect one ACK before refilling
                        rid = in_flight.pop(0)
                        response = self._receive_message_for_id(rid)
                        if isinstance(response, SFTPStatusMessage):
                            if response.status_code != SSH_FX_OK:
                                raise SFTPError.from_status(
                                    response.status_code, response.message
                                )
                        else:
                            raise SFTPError("Unexpected response to write request")

            finally:
                # Close remote file
                request_id = self._get_next_request_id()
                close_msg = SFTPCloseMessage(request_id, handle)
                self._send_request_and_wait_response(close_msg)

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File upload failed: {e}", filename=localpath)

    def get_recursive(self, remotepath: str, localpath: str, _depth: int = 0) -> None:
        """
        Download directory recursively.

        Symbolic links to directories are not followed (a server could
        otherwise point a link at an ancestor and make the download endless);
        links to files are downloaded as files.

        Args:
            remotepath: Remote directory path
            localpath: Local destination path
        """
        import stat

        if _depth > _MAX_RECURSION_DEPTH:
            raise SFTPError(f"Directory tree too deep at {remotepath}")

        attrs = self.stat(remotepath)
        if not stat.S_ISDIR(attrs.st_mode or 0):
            self.get(remotepath, localpath)
            return

        if not os.path.exists(localpath):
            os.makedirs(localpath)

        for item in self.listdir(remotepath):
            # Never let a server-supplied name escape the download directory.
            if _is_unsafe_remote_name(item):
                self._logger.warning(
                    "Skipping unsafe remote directory entry during recursive "
                    "download: %r",
                    item,
                )
                continue
            # SFTP paths always use forward slash
            remote_item = (
                f"{remotepath}/{item}"
                if not remotepath.endswith("/")
                else f"{remotepath}{item}"
            )
            local_item = os.path.join(localpath, item)
            link_attrs = self.lstat(remote_item)
            if stat.S_ISLNK(link_attrs.st_mode or 0):
                target = self.stat(remote_item)
                if stat.S_ISDIR(target.st_mode or 0):
                    self._logger.warning(
                        "Not following symlinked directory during recursive "
                        "download: %r",
                        remote_item,
                    )
                    continue
                self.get(remote_item, local_item)
                continue
            self.get_recursive(remote_item, local_item, _depth + 1)

    def put_recursive(self, localpath: str, remotepath: str) -> None:
        """
        Upload directory recursively.

        Args:
            localpath: Local directory path
            remotepath: Remote destination path
        """
        if not os.path.isdir(localpath):
            self.put(localpath, remotepath)
            return

        try:
            self.mkdir(remotepath)
        except SFTPError as e:
            if e.sftp_code != SFTPError.SSH_FX_FAILURE:
                raise

        for item in os.listdir(localpath):
            local_item = os.path.join(localpath, item)
            remote_item = (
                f"{remotepath}/{item}"
                if not remotepath.endswith("/")
                else f"{remotepath}{item}"
            )
            self.put_recursive(local_item, remote_item)

    def listdir(self, path: str = ".") -> list[str]:
        """
        List directory contents.

        Args:
            path: Directory path to list

        Returns:
            List of filenames in directory

        Raises:
            SFTPError: If directory listing fails
        """
        try:
            # Open directory
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPOpenDirMessage

            opendir_msg = SFTPOpenDirMessage(request_id, path)

            response = self._send_request_and_wait_response(opendir_msg)
            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
                else:
                    raise SFTPError("Unexpected status response to opendir request")
            elif not isinstance(response, SFTPHandleMessage):
                raise SFTPError("Expected handle message for directory open")

            handle = response.handle
            filenames = []

            try:
                while True:
                    # Read directory entries
                    request_id = self._get_next_request_id()
                    from ..protocol.sftp_messages import SFTPReadDirMessage

                    readdir_msg = SFTPReadDirMessage(request_id, handle)

                    response = self._send_request_and_wait_response(readdir_msg)

                    if isinstance(response, SFTPStatusMessage):
                        if response.status_code == SSH_FX_EOF:
                            break  # End of directory reached
                        else:
                            raise SFTPError.from_status(
                                response.status_code, response.message
                            )
                    else:
                        from ..protocol.sftp_messages import SFTPNameMessage

                        if isinstance(response, SFTPNameMessage):
                            for filename, _longname, _attrs in response.names:
                                # Skip . and .. entries
                                if filename not in (".", ".."):
                                    filenames.append(filename)
                        else:
                            raise SFTPError("Unexpected response to readdir request")

            finally:
                # Close directory handle
                request_id = self._get_next_request_id()
                close_msg = SFTPCloseMessage(request_id, handle)
                response = self._send_request_and_wait_response(close_msg)
                if isinstance(response, SFTPStatusMessage):
                    if response.status_code != SSH_FX_OK:
                        raise SFTPError.from_status(
                            response.status_code, response.message
                        )

            return filenames

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Directory listing failed: {e}", filename=path)

    def stat(self, path: str) -> SFTPAttributes:
        """
        Get file/directory attributes.

        Args:
            path: Path to file or directory

        Returns:
            SFTPAttributes object with file information

        Raises:
            SFTPError: If stat operation fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPStatMessage

            stat_msg = SFTPStatMessage(request_id, path)

            response = self._send_request_and_wait_response(stat_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
                else:
                    raise SFTPError("Unexpected status response to stat request")
            else:
                from ..protocol.sftp_messages import SFTPAttrsMessage

                if isinstance(response, SFTPAttrsMessage):
                    return response.attrs
                else:
                    raise SFTPError("Unexpected response to stat request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Stat operation failed: {e}", filename=path)

    def lstat(self, path: str) -> SFTPAttributes:
        """
        Get file/directory attributes (don't follow symlinks).

        Args:
            path: Path to file or directory

        Returns:
            SFTPAttributes object with file information

        Raises:
            SFTPError: If lstat operation fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPLStatMessage

            lstat_msg = SFTPLStatMessage(request_id, path)

            response = self._send_request_and_wait_response(lstat_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
                else:
                    raise SFTPError("Unexpected status response to lstat request")
            else:
                from ..protocol.sftp_messages import SFTPAttrsMessage

                if isinstance(response, SFTPAttrsMessage):
                    return response.attrs
                else:
                    raise SFTPError("Unexpected response to lstat request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Lstat operation failed: {e}", filename=path)

    def chmod(self, path: str, mode: int) -> None:
        """
        Change file permissions.

        Args:
            path: Path to file
            mode: New permission mode

        Raises:
            SFTPError: If chmod operation fails
        """
        try:
            # Create attributes with new permissions
            attrs = SFTPAttributes()
            attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS
            attrs.permissions = mode

            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPSetStatMessage

            setstat_msg = SFTPSetStatMessage(request_id, path, attrs)

            response = self._send_request_and_wait_response(setstat_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
            else:
                raise SFTPError("Unexpected response to setstat request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Chmod operation failed: {e}", filename=path)

    def truncate(self, path: str, size: int) -> None:
        """
        Truncate (or extend) a remote file to the given size in bytes.

        Args:
            path: Remote file path
            size: Target size in bytes (0 empties the file)

        Raises:
            SFTPError: If the operation fails
        """
        try:
            attrs = SFTPAttributes()
            attrs.flags = SSH_FILEXFER_ATTR_SIZE
            attrs.size = size

            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPSetStatMessage

            setstat_msg = SFTPSetStatMessage(request_id, path, attrs)
            response = self._send_request_and_wait_response(setstat_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
            else:
                raise SFTPError("Unexpected response to truncate request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Truncate operation failed: {e}", filename=path) from e

    def mkdir(self, path: str, mode: int = 0o777) -> None:
        """
        Create directory.

        Args:
            path: Directory path to create
            mode: Directory permissions

        Raises:
            SFTPError: If directory creation fails
        """
        try:
            # Create attributes with permissions
            attrs = SFTPAttributes()
            attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS
            attrs.permissions = mode

            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPMkdirMessage

            mkdir_msg = SFTPMkdirMessage(request_id, path, attrs)

            response = self._send_request_and_wait_response(mkdir_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
            else:
                raise SFTPError("Unexpected response to mkdir request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Directory creation failed: {e}", filename=path)

    def rmdir(self, path: str) -> None:
        """
        Remove directory.

        Args:
            path: Directory path to remove

        Raises:
            SFTPError: If directory removal fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPRmdirMessage

            rmdir_msg = SFTPRmdirMessage(request_id, path)

            response = self._send_request_and_wait_response(rmdir_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
            else:
                raise SFTPError("Unexpected response to rmdir request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Directory removal failed: {e}", filename=path)

    def remove(self, path: str) -> None:
        """
        Remove file.

        Args:
            path: File path to remove

        Raises:
            SFTPError: If file removal fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPRemoveMessage

            remove_msg = SFTPRemoveMessage(request_id, path)

            response = self._send_request_and_wait_response(remove_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
            else:
                raise SFTPError("Unexpected response to remove request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File removal failed: {e}", filename=path)

    def rename(self, oldpath: str, newpath: str) -> None:
        """
        Rename file or directory.

        Args:
            oldpath: Current path
            newpath: New path

        Raises:
            SFTPError: If rename operation fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPRenameMessage

            rename_msg = SFTPRenameMessage(request_id, oldpath, newpath)

            response = self._send_request_and_wait_response(rename_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
            else:
                raise SFTPError("Unexpected response to rename request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Rename operation failed: {e}") from e

    def getcwd(self) -> str:
        """
        Get current working directory.

        Returns:
            Current working directory path

        Raises:
            SFTPError: If operation fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPRealPathMessage

            realpath_msg = SFTPRealPathMessage(request_id, ".")

            response = self._send_request_and_wait_response(realpath_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
                else:
                    raise SFTPError("Unexpected status response to realpath request")
            else:
                from ..protocol.sftp_messages import SFTPNameMessage

                if isinstance(response, SFTPNameMessage):
                    if response.names:
                        return response.names[0][0]  # First filename in response
                    else:
                        raise SFTPError("Empty response to realpath request")
                else:
                    raise SFTPError("Unexpected response to realpath request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Get current directory failed: {e}") from e

    def normalize(self, path: str) -> str:
        """
        Normalize path (resolve . and .. components).

        Args:
            path: Path to normalize

        Returns:
            Normalized path

        Raises:
            SFTPError: If operation fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPRealPathMessage

            realpath_msg = SFTPRealPathMessage(request_id, path)

            response = self._send_request_and_wait_response(realpath_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
                else:
                    raise SFTPError("Unexpected status response to realpath request")
            else:
                from ..protocol.sftp_messages import SFTPNameMessage

                if isinstance(response, SFTPNameMessage):
                    if response.names:
                        return response.names[0][0]  # First filename in response
                    else:
                        raise SFTPError("Empty response to realpath request")
                else:
                    raise SFTPError("Unexpected response to realpath request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Path normalization failed: {e}", filename=path) from e

    def symlink(self, targetpath: str, linkpath: str) -> None:
        """
        Create symbolic link.

        Args:
            targetpath: Target path for the link
            linkpath: Path where link should be created

        Raises:
            SFTPError: If symlink creation fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPSymlinkMessage

            symlink_msg = SFTPSymlinkMessage(request_id, targetpath, linkpath)

            response = self._send_request_and_wait_response(symlink_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
            else:
                raise SFTPError("Unexpected response to symlink request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Symlink creation failed: {e}") from e

    def readlink(self, path: str) -> str:
        """
        Read symbolic link.

        Args:
            path: Path to symbolic link

        Returns:
            Target path of the link

        Raises:
            SFTPError: If operation fails
        """
        try:
            request_id = self._get_next_request_id()
            from ..protocol.sftp_messages import SFTPReadLinkMessage

            readlink_msg = SFTPReadLinkMessage(request_id, path)

            response = self._send_request_and_wait_response(readlink_msg)

            if isinstance(response, SFTPStatusMessage):
                if response.status_code != SSH_FX_OK:
                    raise SFTPError.from_status(response.status_code, response.message)
                else:
                    raise SFTPError("Unexpected status response to readlink request")
            else:
                from ..protocol.sftp_messages import SFTPNameMessage

                if isinstance(response, SFTPNameMessage):
                    if response.names:
                        return response.names[0][0]  # Target path
                    else:
                        raise SFTPError("Empty response to readlink request")
                else:
                    raise SFTPError("Unexpected response to readlink request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"Readlink failed: {e}", filename=path) from e

    def open(self, filename: str, mode: str = "r") -> "SFTPFile":
        """
        Open remote file.

        Args:
            filename: Remote file path
            mode: File open mode (r, w, a, rb, wb, ab)

        Returns:
            SFTPFile object

        Raises:
            SFTPError: If file open fails
        """
        try:
            flags = self._mode_to_flags(mode)
            attrs = SFTPAttributes()
            request_id = self._get_next_request_id()

            open_msg = SFTPOpenMessage(request_id, filename, flags, attrs)
            response = self._send_request_and_wait_response(open_msg)

            if isinstance(response, SFTPHandleMessage):
                return SFTPFile(self, response.handle, mode)
            elif isinstance(response, SFTPStatusMessage):
                raise SFTPError.from_status(response.status_code, response.message)
            else:
                raise SFTPError("Unexpected response to open request")

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File open failed: {e}", filename=filename)

    def _mode_to_flags(self, mode: str) -> int:
        """Convert a Python file mode string (r, w, a, x, optionally with +
        and b) to SFTP open flags."""
        return _mode_to_flags(mode)

    def close(self) -> None:
        """Close SFTP session and cleanup resources."""
        if self._channel:
            try:
                self._channel.close()
            except Exception as e:
                self._logger.warning(f"Error closing SFTP channel: {e}")
            finally:
                self._channel = None

    def __enter__(self) -> "SFTPClient":
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()
