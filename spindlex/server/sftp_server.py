"""
SFTP Server Implementation

Provides server-side SFTP functionality with file system operations
and customizable authorization hooks.
"""

import logging
import os
import stat
import threading
from typing import BinaryIO, Optional

from ..exceptions import SFTPError
from ..protocol.sftp_constants import (
    MAX_SFTP_HANDLES,
    SFTP_MAX_READ_SIZE,
    SFTP_VERSION,
    SSH_FILEXFER_ATTR_ACMODTIME,
    SSH_FILEXFER_ATTR_PERMISSIONS,
    SSH_FILEXFER_ATTR_SIZE,
    SSH_FILEXFER_ATTR_UIDGID,
    SSH_FX_BAD_MESSAGE,
    SSH_FX_EOF,
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
    SSH_FX_OP_UNSUPPORTED,
    SSH_FX_PERMISSION_DENIED,
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
    SFTPFStatMessage,
    SFTPHandleMessage,
    SFTPInitMessage,
    SFTPLStatMessage,
    SFTPMessage,
    SFTPMkdirMessage,
    SFTPNameMessage,
    SFTPOpenDirMessage,
    SFTPOpenMessage,
    SFTPReadDirMessage,
    SFTPReadMessage,
    SFTPRealPathMessage,
    SFTPRemoveMessage,
    SFTPRenameMessage,
    SFTPRmdirMessage,
    SFTPSetStatMessage,
    SFTPStatMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
    SFTPWriteMessage,
)
from ..transport.channel import Channel


class SFTPHandle:
    """
    SFTP file handle for managing open files.

    Represents an open file or directory on the server side.
    """

    def __init__(
        self,
        handle_id: bytes,
        path: str,
        flags: int,
        file_obj: Optional[BinaryIO] = None,
    ) -> None:
        """
        Initialize SFTP handle.

        Args:
            handle_id: Unique handle identifier
            path: File/directory path
            flags: Open flags
            file_obj: File object for file handles (None for directory handles)
        """
        self.handle_id = handle_id
        self.path = path
        self.flags = flags
        self.file_obj = file_obj
        self.is_directory = file_obj is None
        self.position = 0
        self.dir_entries: Optional[list[tuple]] = None
        self.dir_index = 0

    def read(self, length: int) -> bytes:
        """
        Read data from file handle.

        Args:
            length: Number of bytes to read

        Returns:
            Read data

        Raises:
            SFTPError: If handle is not readable or read fails
        """
        if self.is_directory:
            raise SFTPError("Cannot read from directory handle", SSH_FX_FAILURE)

        if not (self.flags & SSH_FXF_READ):
            raise SFTPError("Handle not open for reading", SSH_FX_PERMISSION_DENIED)

        if self.file_obj is None:
            raise SFTPError("File object not available", SSH_FX_FAILURE)

        try:
            return self.file_obj.read(length)
        except Exception as e:
            raise SFTPError(f"Read failed: {e}", SSH_FX_FAILURE)

    def write(self, data: bytes) -> int:
        """
        Write data to file handle.

        Args:
            data: Data to write

        Returns:
            Number of bytes written

        Raises:
            SFTPError: If handle is not writable or write fails
        """
        if self.is_directory:
            raise SFTPError("Cannot write to directory handle", SSH_FX_FAILURE)

        if not (self.flags & (SSH_FXF_WRITE | SSH_FXF_APPEND)):
            raise SFTPError("Handle not open for writing", SSH_FX_PERMISSION_DENIED)

        if self.file_obj is None:
            raise SFTPError("File object not available", SSH_FX_FAILURE)

        try:
            return self.file_obj.write(data)
        except Exception as e:
            raise SFTPError(f"Write failed: {e}", SSH_FX_FAILURE)

    def seek(self, offset: int) -> None:
        """
        Seek to position in file.

        Args:
            offset: Byte offset to seek to

        Raises:
            SFTPError: If seek fails
        """
        if self.is_directory:
            raise SFTPError("Cannot seek in directory handle", SSH_FX_FAILURE)

        if self.file_obj is None:
            raise SFTPError("File object not available", SSH_FX_FAILURE)

        try:
            self.file_obj.seek(offset)
            self.position = offset
        except Exception as e:
            raise SFTPError(f"Seek failed: {e}", SSH_FX_FAILURE)

    def close(self) -> None:
        """Close the handle and cleanup resources."""
        if self.file_obj:
            try:
                self.file_obj.close()
            except Exception:
                pass
            finally:
                self.file_obj = None


class SFTPServer:
    """
    Base SFTP server implementation.

    Provides hooks for file system operations that can be overridden
    to implement custom SFTP server behavior and authorization.
    """

    def __init__(
        self, channel: "Channel", root_path: str = "/", start_thread: bool = True
    ) -> None:
        """
        Initialize SFTP server with channel and root path.

        Args:
            channel: SSH channel for SFTP communication
            root_path: Root directory for SFTP operations (default: "/")
            start_thread: Whether to start the message processing thread (default: True)
        """
        self._channel = channel
        # Resolve the root once, up front: every subsequent path check compares
        # realpath(candidate) against this canonical root, so a symlinked root
        # cannot be sidestepped later by replacing it mid-session.
        self._root_path = os.path.realpath(os.path.abspath(root_path))
        self._handles: dict[bytes, SFTPHandle] = {}
        self._handle_counter = 0
        self._handle_lock = threading.Lock()
        self._logger = logging.getLogger(__name__)
        self._client_version: Optional[int] = None
        self._client_extensions: dict[str, str] = {}

        if start_thread:
            # Start SFTP session in a separate thread to avoid blocking
            self._thread = threading.Thread(
                target=self._run_server,
                name=f"SFTPServer-{channel.channel_id}",
                daemon=True,
            )
            self._thread.start()

    def _run_server(self) -> None:
        """Run the SFTP server session."""
        try:
            self._start_sftp_session()
        except Exception as e:
            self._logger.error(f"SFTP server session error: {e}")
            self.close()

    def _start_sftp_session(self) -> None:
        """
        Start SFTP session and handle version negotiation.

        Raises:
            SFTPError: If SFTP initialization fails
        """
        try:
            # Bound recv() waits so the SFTP thread exits promptly when the
            # client disconnects instead of blocking for the full socket timeout.
            self._channel.settimeout(30.0)

            # Wait for client init message
            init_msg = self._receive_message()
            if not isinstance(init_msg, SFTPInitMessage):
                raise SFTPError("Expected SFTP init message", SSH_FX_BAD_MESSAGE)

            self._client_version = init_msg.version

            # Send version response
            version_msg = SFTPVersionMessage(SFTP_VERSION, {})
            self._send_message(version_msg)

            self._logger.debug(
                f"SFTP session started, client version: {self._client_version}"
            )

            # Start message processing loop
            self._process_messages()

        except Exception as e:
            self._logger.error(f"SFTP session initialization failed: {e}")
            raise SFTPError(f"SFTP initialization failed: {e}") from e

    def _generate_handle(self) -> bytes:
        """
        Generate unique handle identifier.

        Returns:
            Unique handle bytes
        """
        with self._handle_lock:
            self._handle_counter += 1
            return f"handle_{self._handle_counter}".encode()

    def _send_message(self, message: SFTPMessage) -> None:
        """
        Send SFTP message over channel.

        Args:
            message: SFTP message to send

        Raises:
            SFTPError: If message sending fails
        """
        try:
            data = message.pack()
            self._channel.send(data)
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
        try:
            # Read message length first (4 bytes)
            length_data = self._channel.recv_exactly(4)
            msg_length = int.from_bytes(length_data, "big")

            # Read message content (msg_length bytes)
            payload = self._channel.recv_exactly(msg_length)
            msg_data = length_data + payload

            return SFTPMessage.unpack(msg_data)
        except Exception as e:
            raise SFTPError(f"Failed to receive SFTP message: {e}") from e

    def _process_messages(self) -> None:
        """
        Process incoming SFTP messages in a loop.

        Handles all SFTP protocol messages and dispatches to appropriate handlers.
        """
        message = None
        while True:
            try:
                message = self._receive_message()
                self._handle_message(message)
            except Exception as e:
                err = str(e).lower()
                # Treat EOF / connection-closed as a clean shutdown, not an error
                if any(
                    k in err
                    for k in (
                        "connection closed",
                        "eof",
                        "closed",
                        "bad file descriptor",
                        "timeout",
                    )
                ):
                    self._logger.debug(f"SFTP session ended: {e}")
                else:
                    self._logger.error(f"Error processing SFTP message: {e}")
                    try:
                        if (
                            message is not None
                            and hasattr(message, "request_id")
                            and message.request_id is not None
                        ):
                            error_msg = SFTPStatusMessage(
                                message.request_id, SSH_FX_FAILURE, str(e)
                            )
                            self._send_message(error_msg)
                    except Exception:
                        pass
                break

    def _handle_message(self, message: SFTPMessage) -> None:
        """
        Handle individual SFTP message.

        Args:
            message: SFTP message to handle
        """
        # Dispatch based on message type
        if isinstance(message, SFTPInitMessage):
            self._handle_init(message)
        elif isinstance(message, SFTPOpenMessage):
            self._handle_open(message)
        elif isinstance(message, SFTPCloseMessage):
            self._handle_close(message)
        elif isinstance(message, SFTPReadMessage):
            self._handle_read(message)
        elif isinstance(message, SFTPWriteMessage):
            self._handle_write(message)
        elif isinstance(message, SFTPStatMessage):
            self._handle_stat(message)
        elif isinstance(message, SFTPLStatMessage):
            self._handle_lstat(message)
        elif isinstance(message, SFTPFStatMessage):
            self._handle_fstat(message)
        elif isinstance(message, SFTPSetStatMessage):
            self._handle_setstat(message)
        elif isinstance(message, SFTPOpenDirMessage):
            self._handle_opendir(message)
        elif isinstance(message, SFTPReadDirMessage):
            self._handle_readdir(message)
        elif isinstance(message, SFTPMkdirMessage):
            self._handle_mkdir(message)
        elif isinstance(message, SFTPRmdirMessage):
            self._handle_rmdir(message)
        elif isinstance(message, SFTPRemoveMessage):
            self._handle_remove(message)
        elif isinstance(message, SFTPRenameMessage):
            self._handle_rename(message)
        elif isinstance(message, SFTPRealPathMessage):
            self._handle_realpath(message)
        else:
            # Unsupported operation
            if hasattr(message, "request_id") and message.request_id is not None:
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_OP_UNSUPPORTED, "Operation not supported"
                )
                self._send_message(error_msg)

    def _handle_init(self, message: SFTPInitMessage) -> None:
        """Handle SFTP init message (should not happen after session start)."""
        # This should not happen after session initialization
        pass

    def _resolve_path(self, path: str) -> str:
        """
        Resolve relative path to absolute path within root.

        Args:
            path: Path to resolve

        Returns:
            Absolute path within server root

        Raises:
            SFTPError: If path is outside root directory
        """
        # Reject NUL bytes outright — they can truncate paths in some native
        # APIs and have no legitimate use in SFTP paths.
        if "\x00" in path:
            raise SFTPError("Invalid path", SSH_FX_PERMISSION_DENIED)

        # Normalize SFTP path (always use forward slashes in SFTP)
        path = path.replace("\\", "/")

        # Check if this is an SFTP absolute path (starts with /)
        if path.startswith("/"):
            # Strip leading slash and treat as relative to root
            path = path.lstrip("/")

        # Join with root path
        full_path = os.path.normpath(os.path.join(self._root_path, path))

        # Fully resolve path (resolve symlinks and ..)
        resolved = os.path.realpath(full_path)
        root_real = self._root_path  # already realpath()'d in __init__

        # Check if resolved path is within root. Using prefix comparison with a
        # trailing separator avoids the classic /var/www vs /var/wwwbad bypass
        # and sidesteps commonpath's ValueError on mixed drives (Windows).
        resolved_norm = os.path.normcase(resolved)
        root_norm = os.path.normcase(root_real)
        root_with_sep = root_norm.rstrip(os.sep) + os.sep

        if resolved_norm != root_norm and not resolved_norm.startswith(root_with_sep):
            raise SFTPError("Path outside root directory", SSH_FX_PERMISSION_DENIED)

        return resolved

    def _path_to_attrs(self, path: str) -> SFTPAttributes:
        """
        Convert file system path to SFTP attributes.

        Args:
            path: File system path

        Returns:
            SFTPAttributes object

        Raises:
            SFTPError: If stat fails
        """
        try:
            st = os.stat(path)
            attrs = SFTPAttributes()

            attrs.flags = (
                SSH_FILEXFER_ATTR_SIZE
                | SSH_FILEXFER_ATTR_PERMISSIONS
                | SSH_FILEXFER_ATTR_ACMODTIME
                | SSH_FILEXFER_ATTR_UIDGID
            )
            attrs.size = st.st_size
            attrs.permissions = st.st_mode
            attrs.atime = int(st.st_atime)
            attrs.mtime = int(st.st_mtime)
            attrs.uid = st.st_uid
            attrs.gid = st.st_gid

            return attrs
        except OSError as e:
            if e.errno == 2:  # No such file or directory
                raise SFTPError("No such file or directory", SSH_FX_NO_SUCH_FILE)
            else:
                raise SFTPError(f"Stat failed: {e}", SSH_FX_FAILURE)

    # Message handlers
    def _handle_open(self, message: SFTPOpenMessage) -> None:
        """Handle file open request."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.filename)

            # Check authorization
            if message.pflags & (SSH_FXF_WRITE | SSH_FXF_APPEND | SSH_FXF_CREAT):
                if not self.check_file_access(resolved_path, "w"):
                    error_msg = SFTPStatusMessage(
                        message.request_id,
                        SSH_FX_PERMISSION_DENIED,
                        "Read access denied",
                    )
                    self._send_message(error_msg)
                    return

            else:
                if not self.check_file_access(resolved_path, "r"):
                    error_msg = SFTPStatusMessage(
                        message.request_id,
                        SSH_FX_PERMISSION_DENIED,
                        "Read access denied",
                    )
                    self._send_message(error_msg)
                    return

            # Determine file mode
            mode = ""
            if message.pflags & SSH_FXF_READ and message.pflags & SSH_FXF_WRITE:
                mode = "r+b"
            elif message.pflags & SSH_FXF_WRITE:
                if message.pflags & SSH_FXF_CREAT:
                    if message.pflags & SSH_FXF_EXCL:
                        mode = "xb"  # Exclusive create
                    elif message.pflags & SSH_FXF_TRUNC:
                        mode = "wb"  # Create or truncate
                    else:
                        mode = "ab"  # Create or append
                else:
                    mode = "r+b"  # Write to existing file
            elif message.pflags & SSH_FXF_APPEND:
                mode = "ab"
            else:
                mode = "rb"  # Read only

            # Open file
            file_obj = None
            try:
                file_obj = open(resolved_path, mode)

                # Create handle
                handle_id = self._generate_handle()
                from typing import BinaryIO, cast

                handle = SFTPHandle(
                    handle_id,
                    resolved_path,
                    message.pflags,
                    file_obj=cast(BinaryIO, file_obj),
                )

                with self._handle_lock:
                    # Bug #12 Fixed: Enforce limit on open file handles
                    if len(self._handles) >= MAX_SFTP_HANDLES:
                        error_msg = SFTPStatusMessage(
                            message.request_id,
                            SSH_FX_FAILURE,
                            "Too many open handles",
                        )
                        self._send_message(error_msg)
                        return

                    self._handles[handle_id] = handle

                # Send handle response
                handle_msg = SFTPHandleMessage(message.request_id, handle_id)
                self._send_message(handle_msg)

            except Exception as e:
                if file_obj:
                    try:
                        file_obj.close()
                    except Exception:
                        pass
                if isinstance(e, FileNotFoundError):
                    error_msg = SFTPStatusMessage(
                        int(message.request_id), SSH_FX_NO_SUCH_FILE, "File not found"
                    )
                elif isinstance(e, PermissionError):
                    error_msg = SFTPStatusMessage(
                        int(message.request_id),
                        SSH_FX_PERMISSION_DENIED,
                        "Permission denied",
                    )
                elif isinstance(e, FileExistsError):
                    error_msg = SFTPStatusMessage(
                        int(message.request_id), SSH_FX_FAILURE, "File already exists"
                    )
                else:
                    error_msg = SFTPStatusMessage(
                        int(message.request_id), SSH_FX_FAILURE, f"Open failed: {e}"
                    )
                self._send_message(error_msg)
                return

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_close(self, message: SFTPCloseMessage) -> None:
        """Handle file close request."""
        assert message.request_id is not None
        try:
            with self._handle_lock:
                handle = self._handles.get(message.handle)
                if handle is None:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, "Invalid handle"
                    )
                    self._send_message(error_msg)
                    return

                # Close and remove handle
                handle.close()
                del self._handles[message.handle]

            # Send success response
            status_msg = SFTPStatusMessage(message.request_id, SSH_FX_OK, "")
            self._send_message(status_msg)

        except Exception as e:
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_read(self, message: SFTPReadMessage) -> None:
        """Handle file read request."""
        assert message.request_id is not None
        try:
            with self._handle_lock:
                handle = self._handles.get(message.handle)
                if handle is None:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, "Invalid handle"
                    )
                    self._send_message(error_msg)
                    return

            # Seek to requested offset
            handle.seek(message.offset)

            # Read data (limit to max read size)
            read_length = min(message.length, SFTP_MAX_READ_SIZE)
            data = handle.read(read_length)

            if len(data) == 0:
                # End of file
                status_msg = SFTPStatusMessage(message.request_id, SSH_FX_EOF, "")
                self._send_message(status_msg)
            else:
                # Send data response
                data_msg = SFTPDataMessage(message.request_id, data)
                self._send_message(data_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_write(self, message: SFTPWriteMessage) -> None:
        """Handle file write request."""
        assert message.request_id is not None
        try:
            with self._handle_lock:
                handle = self._handles.get(message.handle)
                if handle is None:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, "Invalid handle"
                    )
                    self._send_message(error_msg)
                    return

            # Seek to requested offset
            handle.seek(message.offset)

            # Write data
            handle.write(message.data)

            # Flush to ensure data is written
            if handle.file_obj:
                handle.file_obj.flush()

            # Send success response
            status_msg = SFTPStatusMessage(message.request_id, SSH_FX_OK, "")
            self._send_message(status_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_stat(self, message: SFTPStatMessage) -> None:
        """Handle stat request."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.path)

            # Check authorization
            if not self.check_file_access(resolved_path, "r"):
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_PERMISSION_DENIED, "Access denied"
                )
                self._send_message(error_msg)
                return

            # Get file attributes
            attrs = self._path_to_attrs(resolved_path)

            # Send attributes response
            attrs_msg = SFTPAttrsMessage(message.request_id, attrs)
            self._send_message(attrs_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_lstat(self, message: SFTPLStatMessage) -> None:
        """Handle lstat request (don't follow symlinks)."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.path)

            # Check authorization
            if not self.check_file_access(resolved_path, "r"):
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_PERMISSION_DENIED, "Access denied"
                )
                self._send_message(error_msg)
                return

            # Get file attributes (lstat doesn't follow symlinks)
            try:
                st = os.lstat(resolved_path)
                attrs = SFTPAttributes()

                attrs.flags = (
                    SSH_FILEXFER_ATTR_SIZE
                    | SSH_FILEXFER_ATTR_PERMISSIONS
                    | SSH_FILEXFER_ATTR_ACMODTIME
                    | SSH_FILEXFER_ATTR_UIDGID
                )
                attrs.size = st.st_size
                attrs.permissions = st.st_mode
                attrs.atime = int(st.st_atime)
                attrs.mtime = int(st.st_mtime)
                attrs.uid = st.st_uid
                attrs.gid = st.st_gid

            except OSError as e:
                if e.errno == 2:  # No such file or directory
                    raise SFTPError("No such file or directory", SSH_FX_NO_SUCH_FILE)
                else:
                    raise SFTPError(f"Lstat failed: {e}", SSH_FX_FAILURE)

            # Send attributes response
            attrs_msg = SFTPAttrsMessage(message.request_id, attrs)
            self._send_message(attrs_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_fstat(self, message: SFTPFStatMessage) -> None:
        """Handle fstat request (get attributes of open file)."""
        assert message.request_id is not None
        try:
            with self._handle_lock:
                handle = self._handles.get(message.handle)
                if handle is None:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, "Invalid handle"
                    )
                    self._send_message(error_msg)
                    return

            # Get file attributes for the open file
            attrs = self._path_to_attrs(handle.path)

            # Send attributes response
            attrs_msg = SFTPAttrsMessage(message.request_id, attrs)
            self._send_message(attrs_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_setstat(self, message: SFTPSetStatMessage) -> None:
        """Handle setstat request (set file attributes)."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.path)

            # Check authorization
            if not self.check_file_access(resolved_path, "w"):
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_PERMISSION_DENIED, "Write access denied"
                )
                self._send_message(error_msg)
                return

            attrs = message.attrs

            # Set permissions
            if (
                attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS
                and attrs.permissions is not None
            ):
                try:
                    os.chmod(resolved_path, attrs.permissions)
                except OSError as e:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, f"Chmod failed: {e}"
                    )
                    self._send_message(error_msg)
                    return

            # Set access and modification times
            if (
                attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME
                and attrs.atime is not None
                and attrs.mtime is not None
            ):
                try:
                    os.utime(resolved_path, (attrs.atime, attrs.mtime))
                except OSError as e:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, f"Utime failed: {e}"
                    )
                    self._send_message(error_msg)
                    return

            # Set ownership (if supported and authorized)
            if attrs.flags & SSH_FILEXFER_ATTR_UIDGID:
                try:
                    if hasattr(os, "chown"):
                        uid = attrs.uid if attrs.uid is not None else -1
                        gid = attrs.gid if attrs.gid is not None else -1
                        os.chown(resolved_path, uid, gid)
                except (OSError, AttributeError):
                    # chown may not be supported on all platforms
                    # or user may not have permission
                    pass

            # Send success response
            status_msg = SFTPStatusMessage(message.request_id, SSH_FX_OK, "")
            self._send_message(status_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_opendir(self, message: SFTPOpenDirMessage) -> None:
        """Handle directory open request."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.path)

            # Check authorization
            if not self.check_directory_access(resolved_path, "r"):
                assert message.request_id is not None
                error_msg = SFTPStatusMessage(
                    message.request_id,
                    SSH_FX_PERMISSION_DENIED,
                    "Read access denied",
                )
                self._send_message(error_msg)
                return

            # Check if path is a directory
            if not os.path.isdir(resolved_path):
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_NO_SUCH_FILE, "Not a directory"
                )
                self._send_message(error_msg)
                return

            # Read directory entries
            try:
                entries = []
                for name in os.listdir(resolved_path):
                    entry_path = os.path.join(resolved_path, name)
                    try:
                        attrs = self._path_to_attrs(entry_path)
                        # Create long name (ls -l style)
                        longname = self._format_longname(name, attrs)
                        entries.append((name, longname, attrs))
                    except Exception:
                        # Skip entries we can't stat
                        continue

            except OSError:
                error_msg = SFTPStatusMessage(
                    message.request_id,
                    SSH_FX_PERMISSION_DENIED,
                    "Read access denied",
                )
                self._send_message(error_msg)
                return

            # Create directory handle
            handle_id = self._generate_handle()
            handle = SFTPHandle(handle_id, resolved_path, 0)  # Directory handle
            handle.dir_entries = entries
            handle.dir_index = 0

            with self._handle_lock:
                self._handles[handle_id] = handle

            # Send handle response
            handle_msg = SFTPHandleMessage(message.request_id, handle_id)
            self._send_message(handle_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_readdir(self, message: SFTPReadDirMessage) -> None:
        """Handle directory read request."""
        assert message.request_id is not None
        try:
            with self._handle_lock:
                handle = self._handles.get(message.handle)
                if handle is None:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, "Invalid handle"
                    )
                    self._send_message(error_msg)
                    return

                if not handle.is_directory:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, "Handle is not a directory"
                    )
                    self._send_message(error_msg)
                    return

            # Check if we've reached the end of directory
            if handle.dir_entries is None or handle.dir_index >= len(
                handle.dir_entries
            ):
                status_msg = SFTPStatusMessage(message.request_id, SSH_FX_EOF, "")
                self._send_message(status_msg)
                return

            # Return a batch of entries (limit to avoid large messages)
            batch_size = 50  # Reasonable batch size
            start_index = handle.dir_index
            end_index = min(start_index + batch_size, len(handle.dir_entries))

            batch_entries = handle.dir_entries[start_index:end_index]
            handle.dir_index = end_index

            # Send name response
            name_msg = SFTPNameMessage(message.request_id, batch_entries)
            self._send_message(name_msg)

        except Exception as e:
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_mkdir(self, message: SFTPMkdirMessage) -> None:
        """Handle directory creation request."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.path)

            # Check authorization
            parent_dir = os.path.dirname(resolved_path)
            if not self.check_directory_access(parent_dir, "w"):
                error_msg = SFTPStatusMessage(
                    message.request_id,
                    SSH_FX_PERMISSION_DENIED,
                    "Read access denied",
                )
                self._send_message(error_msg)
                return

            # Get permissions from attributes or use default
            mode = self.get_directory_permissions(resolved_path)
            if (
                message.attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS
                and message.attrs.permissions is not None
            ):
                mode = message.attrs.permissions

            # Create directory
            try:
                os.mkdir(resolved_path, mode)
            except FileExistsError:
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_FAILURE, "Directory already exists"
                )
                self._send_message(error_msg)
                return
            except OSError as e:
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_FAILURE, f"Mkdir failed: {e}"
                )
                self._send_message(error_msg)
                return

            # Set additional attributes if specified
            if message.attrs.flags & SSH_FILEXFER_ATTR_UIDGID:
                try:
                    if hasattr(os, "chown"):
                        uid = message.attrs.uid if message.attrs.uid is not None else -1
                        gid = message.attrs.gid if message.attrs.gid is not None else -1
                        os.chown(resolved_path, uid, gid)
                except (OSError, AttributeError):
                    # chown may not be supported or user may not have permission
                    pass

            # Send success response
            status_msg = SFTPStatusMessage(message.request_id, SSH_FX_OK, "")
            self._send_message(status_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_rmdir(self, message: SFTPRmdirMessage) -> None:
        """Handle directory removal request."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.path)

            # Check authorization
            parent_dir = os.path.dirname(resolved_path)
            if not self.check_directory_access(parent_dir, "w"):
                error_msg = SFTPStatusMessage(
                    message.request_id,
                    SSH_FX_PERMISSION_DENIED,
                    "Read access denied",
                )
                self._send_message(error_msg)
                return

            # Remove directory
            try:
                os.rmdir(resolved_path)
            except FileNotFoundError:
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_NO_SUCH_FILE, "Directory not found"
                )
                self._send_message(error_msg)
                return
            except OSError as e:
                if e.errno == 39:  # Directory not empty
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, "Directory not empty"
                    )
                else:
                    error_msg = SFTPStatusMessage(
                        message.request_id, SSH_FX_FAILURE, f"Rmdir failed: {e}"
                    )
                self._send_message(error_msg)
                return

            # Send success response
            status_msg = SFTPStatusMessage(message.request_id, SSH_FX_OK, "")
            self._send_message(status_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_remove(self, message: SFTPRemoveMessage) -> None:
        """Handle file removal request."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.filename)

            # Check authorization
            if not self.check_file_access(resolved_path, "w"):
                error_msg = SFTPStatusMessage(
                    message.request_id,
                    SSH_FX_PERMISSION_DENIED,
                    "Read access denied",
                )
                self._send_message(error_msg)
                return

            # Remove file
            try:
                os.unlink(resolved_path)
            except FileNotFoundError:
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_NO_SUCH_FILE, "File not found"
                )
                self._send_message(error_msg)
                return
            except OSError as e:
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_FAILURE, f"Remove failed: {e}"
                )
                self._send_message(error_msg)
                return

            # Send success response
            status_msg = SFTPStatusMessage(message.request_id, SSH_FX_OK, "")
            self._send_message(status_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_rename(self, message: SFTPRenameMessage) -> None:
        """Handle file rename request."""
        assert message.request_id is not None
        try:
            # Resolve and validate paths
            old_path = self._resolve_path(message.oldpath)
            new_path = self._resolve_path(message.newpath)

            # Check authorization for both paths
            if not self.check_file_access(old_path, "w"):
                error_msg = SFTPStatusMessage(
                    message.request_id,
                    SSH_FX_PERMISSION_DENIED,
                    "Write access denied",
                )
                self._send_message(error_msg)
                return

            new_parent = os.path.dirname(new_path)
            if not self.check_directory_access(new_parent, "w"):
                error_msg = SFTPStatusMessage(
                    message.request_id,
                    SSH_FX_PERMISSION_DENIED,
                    "Destination directory write access denied",
                )
                self._send_message(error_msg)
                return

            # Rename file
            try:
                os.rename(old_path, new_path)
            except FileNotFoundError:
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_NO_SUCH_FILE, "Source file not found"
                )
                self._send_message(error_msg)
                return
            except OSError as e:
                error_msg = SFTPStatusMessage(
                    message.request_id, SSH_FX_FAILURE, f"Rename failed: {e}"
                )
                self._send_message(error_msg)
                return

            # Send success response
            status_msg = SFTPStatusMessage(message.request_id, SSH_FX_OK, "")
            self._send_message(status_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _handle_realpath(self, message: SFTPRealPathMessage) -> None:
        """Handle realpath request (resolve path)."""
        assert message.request_id is not None
        try:
            # Resolve and validate path
            resolved_path = self._resolve_path(message.path)

            # Convert back to relative path from root
            relative_path = os.path.relpath(resolved_path, self._root_path)
            if relative_path == ".":
                relative_path = "/"
            elif not relative_path.startswith("/"):
                relative_path = "/" + relative_path

            # Create attributes for the path (if it exists)
            try:
                attrs = self._path_to_attrs(resolved_path)
                longname = self._format_longname(os.path.basename(relative_path), attrs)
            except SFTPError:
                # Path doesn't exist, create minimal attributes
                attrs = SFTPAttributes()
                longname = os.path.basename(relative_path)

            # Send name response with single entry
            names = [(relative_path, longname, attrs)]
            name_msg = SFTPNameMessage(int(message.request_id), names)
            self._send_message(name_msg)

        except SFTPError as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(
                message.request_id, e.status_code or SSH_FX_FAILURE, str(e)
            )
            self._send_message(error_msg)
        except Exception as e:
            assert message.request_id is not None
            error_msg = SFTPStatusMessage(message.request_id, SSH_FX_FAILURE, str(e))
            self._send_message(error_msg)

    def _format_longname(self, filename: str, attrs: SFTPAttributes) -> str:
        """
        Format long name for directory listings (ls -l style).

        Args:
            filename: File name
            attrs: File attributes

        Returns:
            Formatted long name string
        """
        # File type and permissions
        if attrs.permissions is not None:
            mode = attrs.permissions
            if stat.S_ISDIR(mode):
                type_char = "d"
            elif stat.S_ISLNK(mode):
                type_char = "l"
            elif stat.S_ISREG(mode):
                type_char = "-"
            else:
                type_char = "?"

            # Permission bits
            perms = (
                ("r" if mode & stat.S_IRUSR else "-")
                + ("w" if mode & stat.S_IWUSR else "-")
                + ("x" if mode & stat.S_IXUSR else "-")
                + ("r" if mode & stat.S_IRGRP else "-")
                + ("w" if mode & stat.S_IWGRP else "-")
                + ("x" if mode & stat.S_IXGRP else "-")
                + ("r" if mode & stat.S_IROTH else "-")
                + ("w" if mode & stat.S_IWOTH else "-")
                + ("x" if mode & stat.S_IXOTH else "-")
            )
            mode_str = type_char + perms
        else:
            mode_str = "----------"

        # Number of links (hardcoded to 1)
        nlink = 1

        # Owner and group (use numeric IDs)
        uid = attrs.uid if attrs.uid is not None else 0
        gid = attrs.gid if attrs.gid is not None else 0

        # File size
        size = attrs.size if attrs.size is not None else 0

        # Modification time (simplified format)
        if attrs.mtime is not None:
            import time

            mtime_str = time.strftime("%b %d %H:%M", time.localtime(attrs.mtime))
        else:
            mtime_str = "Jan  1 00:00"

        return (
            f"{mode_str} {nlink:3d} {uid:8d} {gid:8d} {size:8d} {mtime_str} {filename}"
        )

    # Authorization hooks - can be overridden by subclasses

    def check_file_access(self, path: str, mode: str) -> bool:
        """
        Check if file access is authorized.

        Override this method to implement custom file access authorization.

        Args:
            path: File path to check
            mode: Access mode ('r', 'w', 'x')

        Returns:
            True if access is authorized
        """
        # Default implementation allows all access
        return True

    def check_directory_access(self, path: str, mode: str) -> bool:
        """
        Check if directory access is authorized.

        Override this method to implement custom directory access authorization.

        Args:
            path: Directory path to check
            mode: Access mode ('r', 'w', 'x')

        Returns:
            True if access is authorized
        """
        # Default implementation allows all access
        return True

    def get_file_permissions(self, path: str) -> int:
        """
        Get file permissions for new files.

        Override this method to customize file permissions.

        Args:
            path: File path

        Returns:
            File permissions (octal mode)
        """
        # Default permissions: 644 (rw-r--r--)
        return 0o644

    def get_directory_permissions(self, path: str) -> int:
        """
        Get directory permissions for new directories.

        Override this method to customize directory permissions.

        Args:
            path: Directory path

        Returns:
            Directory permissions (octal mode)
        """
        # Default permissions: 755 (rwxr-xr-x)
        return 0o755

    def close(self) -> None:
        """Close SFTP server and cleanup resources."""
        # Close all open handles
        with self._handle_lock:
            for handle in self._handles.values():
                handle.close()
            self._handles.clear()

        # Close channel
        if self._channel:
            try:
                self._channel.close()
            except Exception:
                pass
