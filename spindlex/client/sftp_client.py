"""
SFTP Client Implementation

Provides SFTP (SSH File Transfer Protocol) client functionality for
secure file operations over SSH connections.
"""

import logging
import os
import threading
from typing import Any, BinaryIO, List, Optional, Union

from ..exceptions import ChannelException, SFTPError, SSHException
from ..protocol.sftp_constants import (
    SFTP_MAX_READ_SIZE,
    SFTP_SUBSYSTEM,
    SFTP_VERSION,
    SSH_FILEXFER_ATTR_PERMISSIONS,
    SSH_FILEXFER_ATTR_SIZE,
    SSH_FX_EOF,
    SSH_FX_OK,
    SSH_FXF_CREAT,
    SSH_FXF_READ,
    SSH_FXF_TRUNC,
    SSH_FXF_WRITE,
    SSH_FXP_INIT,
    SSH_FXP_RENAME,
    SSH_FXP_VERSION,
)
from ..protocol.sftp_messages import (
    SFTPAttributes,
    SFTPCloseMessage,
    SFTPDataMessage,
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
        self._server_version = None
        self._server_extensions = {}

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

            self._logger.debug(
                f"SFTP initialized, server version: {self._server_version}"
            )

        except Exception as e:
            if self._channel:
                self._channel.close()
                self._channel = None
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"SFTP initialization failed: {e}")

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
            self._channel.send(data)
        except Exception as e:
            raise SFTPError(f"Failed to send SFTP message: {e}")

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
            # Read message length first
            length_data = self._channel.recv(4)
            if len(length_data) != 4:
                raise SFTPError("Failed to read message length")

            # Read message content
            msg_length = int.from_bytes(length_data, "big")
            msg_data = length_data + self._channel.recv(msg_length)

            return SFTPMessage.unpack(msg_data)
        except Exception as e:
            raise SFTPError(f"Failed to receive SFTP message: {e}")

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
        response = self._receive_message()

        # Return response as-is - let caller handle status codes
        # This allows EOF and other status codes to be handled appropriately
        return response

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
                with open(localpath, "wb") as local_file:
                    offset = 0

                    while True:
                        # Read chunk from remote file
                        request_id = self._get_next_request_id()
                        read_msg = SFTPReadMessage(
                            request_id, handle, offset, SFTP_MAX_READ_SIZE
                        )

                        response = self._send_request_and_wait_response(read_msg)

                        if isinstance(response, SFTPStatusMessage):
                            if response.status_code == SSH_FX_EOF:
                                break  # End of file reached
                            else:
                                raise SFTPError.from_status(
                                    response.status_code, response.message
                                )
                        elif isinstance(response, SFTPDataMessage):
                            local_file.write(response.data)
                            offset += len(response.data)
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
            raise SFTPError(f"File download failed: {e}", filename=remotepath)

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
                # Open local file for reading and upload in chunks
                with open(localpath, "rb") as local_file:
                    offset = 0

                    while True:
                        # Read chunk from local file
                        chunk = local_file.read(SFTP_MAX_READ_SIZE)
                        if not chunk:
                            break  # End of file reached

                        # Write chunk to remote file
                        request_id = self._get_next_request_id()
                        write_msg = SFTPWriteMessage(request_id, handle, offset, chunk)

                        response = self._send_request_and_wait_response(write_msg)
                        if isinstance(response, SFTPStatusMessage):
                            if response.status_code != SSH_FX_OK:
                                raise SFTPError.from_status(
                                    response.status_code, response.message
                                )
                        else:
                            raise SFTPError("Unexpected response to write request")

                        offset += len(chunk)

            finally:
                # Close remote file
                request_id = self._get_next_request_id()
                close_msg = SFTPCloseMessage(request_id, handle)
                self._send_request_and_wait_response(close_msg)

        except Exception as e:
            if isinstance(e, SFTPError):
                raise
            raise SFTPError(f"File upload failed: {e}", filename=localpath)

    def listdir(self, path: str = ".") -> List[str]:
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
            attrs = SFTPAttributes()
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
                            for filename, longname, attrs in response.names:
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
            raise SFTPError(f"Rename operation failed: {e}")

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
            raise SFTPError(f"Get current directory failed: {e}")

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
            raise SFTPError(f"Path normalization failed: {e}", filename=path)

    def close(self) -> None:
        """Close SFTP session and cleanup resources."""
        if self._channel:
            try:
                self._channel.close()
            except Exception as e:
                self._logger.warning(f"Error closing SFTP channel: {e}")
            finally:
                self._channel = None
