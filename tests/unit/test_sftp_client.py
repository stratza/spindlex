"""
Tests for SFTP client functionality.
"""

import os
import stat
import tempfile
from unittest.mock import MagicMock, Mock, mock_open, patch

import pytest

from spindlex.client.sftp_client import SFTPClient
from spindlex.exceptions import ChannelException, SFTPError
from spindlex.protocol.sftp_constants import (
    SFTP_VERSION,
    SSH_FILEXFER_ATTR_PERMISSIONS,
    SSH_FILEXFER_ATTR_SIZE,
    SSH_FX_EOF,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
    SSH_FX_PERMISSION_DENIED,
    SSH_FXF_READ,
    SSH_FXF_WRITE,
)
from spindlex.protocol.sftp_messages import (
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
    SFTPRemoveMessage,
    SFTPRmdirMessage,
    SFTPSetStatMessage,
    SFTPStatMessage,
    SFTPStatusMessage,
    SFTPVersionMessage,
    SFTPWriteMessage,
)
from spindlex.transport.channel import Channel
from spindlex.transport.transport import Transport


class TestSFTPClient:
    """Test cases for SFTPClient class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_transport = Mock(spec=Transport)
        self.mock_channel = Mock(spec=Channel)

        # Mock transport.open_channel to return our mock channel
        self.mock_transport.open_channel.return_value = self.mock_channel

        # Mock successful SFTP initialization
        version_msg = SFTPVersionMessage(SFTP_VERSION)
        version_data = version_msg.pack()

        self.mock_channel.recv.side_effect = [
            version_data[:4],  # Length
            version_data[4:],  # Content
        ]

    def test_sftp_client_initialization(self):
        """Test SFTP client initialization."""
        client = SFTPClient(self.mock_transport)

        # Verify channel was opened and subsystem invoked
        self.mock_transport.open_channel.assert_called_once_with("session")
        self.mock_channel.invoke_subsystem.assert_called_once_with("sftp")

        # Verify init message was sent
        self.mock_channel.send.assert_called()

        assert client._server_version == SFTP_VERSION
        assert isinstance(client._server_extensions, dict)

    def test_sftp_client_initialization_failure(self):
        """Test SFTP client initialization failure."""
        self.mock_transport.open_channel.return_value = None

        with pytest.raises(SFTPError, match="Failed to open channel"):
            SFTPClient(self.mock_transport)

    def test_get_file_success(self):
        """Test successful file download."""
        client = SFTPClient(self.mock_transport)

        # Mock file handle response
        handle_msg = SFTPHandleMessage(1, b"test_handle")
        handle_data = handle_msg.pack()

        # Mock file data response
        file_content = b"test file content"
        data_msg = SFTPDataMessage(2, file_content)
        data_data = data_msg.pack()

        # Mock EOF response
        eof_msg = SFTPStatusMessage(3, SSH_FX_EOF)
        eof_data = eof_msg.pack()

        # Mock close response
        close_msg = SFTPStatusMessage(4, SSH_FX_OK)
        close_data = close_msg.pack()

        # Reset mock to clear initialization calls
        self.mock_channel.recv.reset_mock()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [
            # Open response
            handle_data[:4],
            handle_data[4:],
            # Read response
            data_data[:4],
            data_data[4:],
            # EOF response
            eof_data[:4],
            eof_data[4:],
            # Close response
            close_data[:4],
            close_data[4:],
        ]

        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_path = tmp_file.name

        try:
            client.get("/remote/file.txt", tmp_path)

            # Verify file was written correctly
            with open(tmp_path, "rb") as f:
                assert f.read() == file_content
        finally:
            os.unlink(tmp_path)

    def test_put_file_success(self):
        """Test successful file upload."""
        client = SFTPClient(self.mock_transport)

        # Create test file
        test_content = b"test file content for upload"
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(test_content)
            tmp_path = tmp_file.name

        try:
            # Mock file handle response
            handle_msg = SFTPHandleMessage(1, b"test_handle")
            handle_data = handle_msg.pack()

            # Mock write response
            write_msg = SFTPStatusMessage(2, SSH_FX_OK)
            write_data = write_msg.pack()

            # Mock close response
            close_msg = SFTPStatusMessage(3, SSH_FX_OK)
            close_data = close_msg.pack()

            # Reset mock to clear initialization calls
            self.mock_channel.recv.reset_mock()

            # Set up channel recv responses
            self.mock_channel.recv.side_effect = [
                # Open response
                handle_data[:4],
                handle_data[4:],
                # Write response
                write_data[:4],
                write_data[4:],
                # Close response
                close_data[:4],
                close_data[4:],
            ]

            client.put(tmp_path, "/remote/file.txt")

            # Verify send was called multiple times (open, write, close)
            assert self.mock_channel.send.call_count >= 3
        finally:
            os.unlink(tmp_path)

    def test_listdir_success(self):
        """Test successful directory listing."""
        client = SFTPClient(self.mock_transport)

        # Mock directory handle response
        handle_msg = SFTPHandleMessage(1, b"dir_handle")
        handle_data = handle_msg.pack()

        # Mock directory entries
        attrs1 = SFTPAttributes()
        attrs1.permissions = stat.S_IFREG | 0o644
        attrs2 = SFTPAttributes()
        attrs2.permissions = stat.S_IFDIR | 0o755

        names = [
            ("file1.txt", "-rw-r--r-- 1 user group 1024 Jan 1 12:00 file1.txt", attrs1),
            ("subdir", "drwxr-xr-x 1 user group 4096 Jan 1 12:00 subdir", attrs2),
        ]
        name_msg = SFTPNameMessage(2, names)
        name_data = name_msg.pack()

        # Mock EOF response
        eof_msg = SFTPStatusMessage(3, SSH_FX_EOF)
        eof_data = eof_msg.pack()

        # Mock close response
        close_msg = SFTPStatusMessage(4, SSH_FX_OK)
        close_data = close_msg.pack()

        # Reset mock to clear initialization calls
        self.mock_channel.recv.reset_mock()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [
            # Open response
            handle_data[:4],
            handle_data[4:],
            # Name response
            name_data[:4],
            name_data[4:],
            # EOF response
            eof_data[:4],
            eof_data[4:],
            # Close response
            close_data[:4],
            close_data[4:],
        ]

        result = client.listdir("/remote/dir")

        assert result == ["file1.txt", "subdir"]

    def test_stat_success(self):
        """Test successful stat operation."""
        client = SFTPClient(self.mock_transport)

        # Mock stat response
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS
        attrs.size = 1024
        attrs.permissions = stat.S_IFREG | 0o644

        attrs_msg = SFTPAttrsMessage(1, attrs)
        attrs_data = attrs_msg.pack()

        # Reset mock to clear initialization calls
        self.mock_channel.recv.reset_mock()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [attrs_data[:4], attrs_data[4:]]

        result = client.stat("/remote/file.txt")

        assert result.size == 1024
        assert result.permissions == (stat.S_IFREG | 0o644)
        assert result.is_file()
        assert not result.is_dir()

    def test_mkdir_success(self):
        """Test successful directory creation."""
        client = SFTPClient(self.mock_transport)

        # Mock mkdir response
        mkdir_msg = SFTPStatusMessage(1, SSH_FX_OK)
        mkdir_data = mkdir_msg.pack()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [mkdir_data[:4], mkdir_data[4:]]

        client.mkdir("/remote/newdir", 0o755)

        # Verify mkdir message was sent
        self.mock_channel.send.assert_called()

    def test_rmdir_success(self):
        """Test successful directory removal."""
        client = SFTPClient(self.mock_transport)

        # Mock rmdir response
        rmdir_msg = SFTPStatusMessage(1, SSH_FX_OK)
        rmdir_data = rmdir_msg.pack()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [rmdir_data[:4], rmdir_data[4:]]

        client.rmdir("/remote/olddir")

        # Verify rmdir message was sent
        self.mock_channel.send.assert_called()

    def test_remove_success(self):
        """Test successful file removal."""
        client = SFTPClient(self.mock_transport)

        # Mock remove response
        remove_msg = SFTPStatusMessage(1, SSH_FX_OK)
        remove_data = remove_msg.pack()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [remove_data[:4], remove_data[4:]]

        client.remove("/remote/file.txt")

        # Verify remove message was sent
        self.mock_channel.send.assert_called()

    def test_chmod_success(self):
        """Test successful chmod operation."""
        client = SFTPClient(self.mock_transport)

        # Mock chmod response
        chmod_msg = SFTPStatusMessage(1, SSH_FX_OK)
        chmod_data = chmod_msg.pack()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [chmod_data[:4], chmod_data[4:]]

        client.chmod("/remote/file.txt", 0o755)

        # Verify setstat message was sent
        self.mock_channel.send.assert_called()

    def test_error_handling_no_such_file(self):
        """Test error handling for non-existent file."""
        client = SFTPClient(self.mock_transport)

        # Mock error response
        error_msg = SFTPStatusMessage(1, SSH_FX_NO_SUCH_FILE, "No such file")
        error_data = error_msg.pack()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [error_data[:4], error_data[4:]]

        with pytest.raises(SFTPError, match="No such file"):
            client.stat("/nonexistent/file.txt")

    def test_error_handling_permission_denied(self):
        """Test error handling for permission denied."""
        client = SFTPClient(self.mock_transport)

        # Mock error response
        error_msg = SFTPStatusMessage(1, SSH_FX_PERMISSION_DENIED, "Permission denied")
        error_data = error_msg.pack()

        # Set up channel recv responses
        self.mock_channel.recv.side_effect = [error_data[:4], error_data[4:]]

        with pytest.raises(SFTPError, match="Permission denied"):
            client.mkdir("/restricted/dir")

    def test_close_cleanup(self):
        """Test proper cleanup on close."""
        client = SFTPClient(self.mock_transport)

        client.close()

        # Verify channel was closed
        self.mock_channel.close.assert_called_once()
        assert client._channel is None

    def test_close_with_error(self):
        """Test close with channel error."""
        client = SFTPClient(self.mock_transport)

        # Mock channel close to raise exception
        self.mock_channel.close.side_effect = Exception("Close error")

        # Should not raise exception, just log warning
        client.close()

        assert client._channel is None


class TestSFTPAttributes:
    """Test cases for SFTPAttributes class."""

    def test_attributes_creation(self):
        """Test SFTPAttributes creation and basic properties."""
        attrs = SFTPAttributes()

        assert attrs.flags == 0
        assert attrs.size is None
        assert attrs.permissions is None
        assert attrs.uid is None
        assert attrs.gid is None
        assert attrs.atime is None
        assert attrs.mtime is None
        assert attrs.extended == {}

    def test_attributes_file_type_detection(self):
        """Test file type detection methods."""
        # Regular file
        attrs = SFTPAttributes()
        attrs.permissions = stat.S_IFREG | 0o644
        assert attrs.is_file()
        assert not attrs.is_dir()
        assert not attrs.is_symlink()

        # Directory
        attrs.permissions = stat.S_IFDIR | 0o755
        assert not attrs.is_file()
        assert attrs.is_dir()
        assert not attrs.is_symlink()

        # Symbolic link
        attrs.permissions = stat.S_IFLNK | 0o777
        assert not attrs.is_file()
        assert not attrs.is_dir()
        assert attrs.is_symlink()

    def test_attributes_serialization(self):
        """Test SFTPAttributes serialization and deserialization."""
        # Create attributes with various fields
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_PERMISSIONS
        attrs.size = 1024
        attrs.permissions = stat.S_IFREG | 0o644

        # Serialize
        data = attrs.pack()

        # Deserialize
        attrs2, offset = SFTPAttributes.unpack(data, 0)

        assert attrs2.flags == attrs.flags
        assert attrs2.size == attrs.size
        assert attrs2.permissions == attrs.permissions
        assert offset == len(data)

    def test_attributes_with_extended(self):
        """Test SFTPAttributes with extended attributes."""
        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_SIZE
        attrs.size = 2048
        attrs.extended = {"custom": "value", "another": "data"}

        # Note: This test would need SSH_FILEXFER_ATTR_EXTENDED flag
        # but we're keeping it simple for core functionality
        data = attrs.pack()
        attrs2, offset = SFTPAttributes.unpack(data, 0)

        assert attrs2.size == 2048


class TestSFTPMessages:
    """Test cases for SFTP message classes."""

    def test_sftp_init_message(self):
        """Test SFTPInitMessage serialization."""
        msg = SFTPInitMessage(SFTP_VERSION)
        data = msg.pack()

        # Verify message can be unpacked
        unpacked = SFTPMessage.unpack(data)
        assert isinstance(unpacked, SFTPInitMessage)
        assert unpacked.version == SFTP_VERSION

    def test_sftp_status_message(self):
        """Test SFTPStatusMessage serialization."""
        msg = SFTPStatusMessage(1, SSH_FX_OK, "Success")
        data = msg.pack()

        # Verify message can be unpacked
        unpacked = SFTPMessage.unpack(data)
        assert isinstance(unpacked, SFTPStatusMessage)
        assert unpacked.request_id == 1
        assert unpacked.status_code == SSH_FX_OK
        assert unpacked.message == "Success"

    def test_sftp_handle_message(self):
        """Test SFTPHandleMessage serialization."""
        handle = b"test_handle_123"
        msg = SFTPHandleMessage(1, handle)
        data = msg.pack()

        # Verify message can be unpacked
        unpacked = SFTPMessage.unpack(data)
        assert isinstance(unpacked, SFTPHandleMessage)
        assert unpacked.request_id == 1
        assert unpacked.handle == handle

    def test_sftp_data_message(self):
        """Test SFTPDataMessage serialization."""
        file_data = b"file content data"
        msg = SFTPDataMessage(1, file_data)
        data = msg.pack()

        # Verify message can be unpacked
        unpacked = SFTPMessage.unpack(data)
        assert isinstance(unpacked, SFTPDataMessage)
        assert unpacked.request_id == 1
        assert unpacked.data == file_data


if __name__ == "__main__":
    pytest.main([__file__])
