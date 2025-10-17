"""
SFTP Server Tests

Tests for SFTP server functionality including file operations,
directory operations, and authorization hooks.
"""

import os
import shutil
import stat
import tempfile
import unittest
from unittest.mock import MagicMock, Mock, patch

from ssh_library.exceptions import SFTPError
from ssh_library.protocol.sftp_constants import (
    SFTP_VERSION,
    SSH_FILEXFER_ATTR_ACMODTIME,
    SSH_FILEXFER_ATTR_PERMISSIONS,
    SSH_FILEXFER_ATTR_SIZE,
    SSH_FILEXFER_ATTR_UIDGID,
    SSH_FX_EOF,
    SSH_FX_FAILURE,
    SSH_FX_NO_SUCH_FILE,
    SSH_FX_OK,
    SSH_FX_PERMISSION_DENIED,
    SSH_FXF_CREAT,
    SSH_FXF_READ,
    SSH_FXF_TRUNC,
    SSH_FXF_WRITE,
)
from ssh_library.protocol.sftp_messages import (
    SFTPAttributes,
    SFTPAttrsMessage,
    SFTPCloseMessage,
    SFTPDataMessage,
    SFTPFStatMessage,
    SFTPHandleMessage,
    SFTPInitMessage,
    SFTPLStatMessage,
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
from ssh_library.server.sftp_server import SFTPHandle, SFTPServer
from ssh_library.transport.channel import Channel


class TestSFTPHandle(unittest.TestCase):
    """Test SFTP handle functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("test content")

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    def test_file_handle_creation(self):
        """Test creating file handle."""
        with open(self.test_file, "rb") as f:
            handle = SFTPHandle(b"handle1", self.test_file, SSH_FXF_READ, f)

            self.assertEqual(handle.handle_id, b"handle1")
            self.assertEqual(handle.path, self.test_file)
            self.assertEqual(handle.flags, SSH_FXF_READ)
            self.assertFalse(handle.is_directory)
            self.assertEqual(handle.position, 0)

    def test_directory_handle_creation(self):
        """Test creating directory handle."""
        handle = SFTPHandle(b"handle2", self.temp_dir, 0)

        self.assertEqual(handle.handle_id, b"handle2")
        self.assertEqual(handle.path, self.temp_dir)
        self.assertTrue(handle.is_directory)
        self.assertIsNone(handle.file_obj)

    def test_file_read(self):
        """Test reading from file handle."""
        with open(self.test_file, "rb") as f:
            handle = SFTPHandle(b"handle1", self.test_file, SSH_FXF_READ, f)

            data = handle.read(4)
            self.assertEqual(data, b"test")

    def test_file_write(self):
        """Test writing to file handle."""
        with open(self.test_file, "r+b") as f:
            handle = SFTPHandle(b"handle1", self.test_file, SSH_FXF_WRITE, f)

            bytes_written = handle.write(b"new ")
            self.assertEqual(bytes_written, 4)

    def test_directory_read_error(self):
        """Test reading from directory handle raises error."""
        handle = SFTPHandle(b"handle2", self.temp_dir, 0)

        with self.assertRaises(SFTPError) as cm:
            handle.read(10)
        self.assertEqual(cm.exception.status_code, SSH_FX_FAILURE)

    def test_directory_write_error(self):
        """Test writing to directory handle raises error."""
        handle = SFTPHandle(b"handle2", self.temp_dir, 0)

        with self.assertRaises(SFTPError) as cm:
            handle.write(b"data")
        self.assertEqual(cm.exception.status_code, SSH_FX_FAILURE)


class TestSFTPServer(unittest.TestCase):
    """Test SFTP server functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.mock_channel = Mock(spec=Channel)

        # Mock the channel recv/send methods
        self.sent_messages = []
        self.received_messages = []

        def mock_send(data):
            self.sent_messages.append(data)

        def mock_recv(size):
            if self.received_messages:
                return self.received_messages.pop(0)
            return b""

        self.mock_channel.send = mock_send
        self.mock_channel.recv = mock_recv

        # Create test files
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        with open(self.test_file, "w") as f:
            f.write("test content")

        self.test_dir = os.path.join(self.temp_dir, "testdir")
        os.mkdir(self.test_dir)

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    def create_server(self):
        """Create SFTP server with mocked initialization."""
        with patch.object(SFTPServer, "_start_sftp_session"):
            server = SFTPServer(self.mock_channel, self.temp_dir)
            return server

    def test_server_initialization(self):
        """Test SFTP server initialization."""
        server = self.create_server()

        self.assertEqual(server._root_path, os.path.abspath(self.temp_dir))
        self.assertEqual(server._channel, self.mock_channel)
        self.assertEqual(len(server._handles), 0)

    def test_generate_handle(self):
        """Test handle generation."""
        server = self.create_server()

        handle1 = server._generate_handle()
        handle2 = server._generate_handle()

        self.assertNotEqual(handle1, handle2)
        self.assertTrue(handle1.startswith(b"handle_"))
        self.assertTrue(handle2.startswith(b"handle_"))

    def test_resolve_path(self):
        """Test path resolution."""
        server = self.create_server()

        # Test relative path
        resolved = server._resolve_path("test.txt")
        expected = os.path.join(self.temp_dir, "test.txt")
        self.assertEqual(os.path.normcase(resolved), os.path.normcase(expected))

        # Test absolute path
        resolved = server._resolve_path("/test.txt")
        self.assertEqual(os.path.normcase(resolved), os.path.normcase(expected))

    def test_resolve_path_outside_root(self):
        """Test path resolution rejects paths outside root."""
        server = self.create_server()

        with self.assertRaises(SFTPError) as cm:
            server._resolve_path("../outside.txt")
        self.assertEqual(cm.exception.status_code, SSH_FX_PERMISSION_DENIED)

    def test_path_to_attrs(self):
        """Test converting path to SFTP attributes."""
        server = self.create_server()

        attrs = server._path_to_attrs(self.test_file)

        self.assertIsNotNone(attrs.size)
        self.assertIsNotNone(attrs.permissions)
        self.assertIsNotNone(attrs.mtime)
        self.assertTrue(attrs.flags & SSH_FILEXFER_ATTR_SIZE)
        self.assertTrue(attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS)

    def test_path_to_attrs_nonexistent(self):
        """Test path to attrs for nonexistent file."""
        server = self.create_server()

        with self.assertRaises(SFTPError) as cm:
            server._path_to_attrs("/nonexistent.txt")
        self.assertEqual(cm.exception.status_code, SSH_FX_NO_SUCH_FILE)

    def test_handle_open_read(self):
        """Test handling file open for reading."""
        server = self.create_server()

        # Create open message
        attrs = SFTPAttributes()
        message = SFTPOpenMessage(1, "test.txt", SSH_FXF_READ, attrs)

        # Handle the message
        server._handle_open(message)

        # Check that a handle was created
        self.assertEqual(len(server._handles), 1)

        # Check that handle message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_open_nonexistent(self):
        """Test handling file open for nonexistent file."""
        server = self.create_server()

        attrs = SFTPAttributes()
        message = SFTPOpenMessage(1, "nonexistent.txt", SSH_FXF_READ, attrs)

        server._handle_open(message)

        # Check that no handle was created
        self.assertEqual(len(server._handles), 0)

        # Check that error message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_close(self):
        """Test handling file close."""
        server = self.create_server()

        # Create a handle first
        handle_id = server._generate_handle()
        with open(self.test_file, "rb") as f:
            handle = SFTPHandle(handle_id, self.test_file, SSH_FXF_READ, f)
            server._handles[handle_id] = handle

        # Create close message
        message = SFTPCloseMessage(1, handle_id)

        # Handle the message
        server._handle_close(message)

        # Check that handle was removed
        self.assertEqual(len(server._handles), 0)

        # Check that success message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_close_invalid_handle(self):
        """Test handling close with invalid handle."""
        server = self.create_server()

        message = SFTPCloseMessage(1, b"invalid_handle")

        server._handle_close(message)

        # Check that error message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_stat(self):
        """Test handling stat request."""
        server = self.create_server()

        message = SFTPStatMessage(1, "test.txt")

        server._handle_stat(message)

        # Check that attrs message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_stat_nonexistent(self):
        """Test handling stat for nonexistent file."""
        server = self.create_server()

        message = SFTPStatMessage(1, "nonexistent.txt")

        server._handle_stat(message)

        # Check that error message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_mkdir(self):
        """Test handling directory creation."""
        server = self.create_server()

        attrs = SFTPAttributes()
        attrs.flags = SSH_FILEXFER_ATTR_PERMISSIONS
        attrs.permissions = 0o755

        message = SFTPMkdirMessage(1, "newdir", attrs)

        server._handle_mkdir(message)

        # Check that directory was created
        new_dir = os.path.join(self.temp_dir, "newdir")
        self.assertTrue(os.path.isdir(new_dir))

        # Check that success message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_mkdir_existing(self):
        """Test handling mkdir for existing directory."""
        server = self.create_server()

        attrs = SFTPAttributes()
        message = SFTPMkdirMessage(1, "testdir", attrs)

        server._handle_mkdir(message)

        # Check that error message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_rmdir(self):
        """Test handling directory removal."""
        server = self.create_server()

        message = SFTPRmdirMessage(1, "testdir")

        server._handle_rmdir(message)

        # Check that directory was removed
        self.assertFalse(os.path.exists(self.test_dir))

        # Check that success message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_rmdir_nonexistent(self):
        """Test handling rmdir for nonexistent directory."""
        server = self.create_server()

        message = SFTPRmdirMessage(1, "nonexistent")

        server._handle_rmdir(message)

        # Check that error message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_remove(self):
        """Test handling file removal."""
        server = self.create_server()

        message = SFTPRemoveMessage(1, "test.txt")

        server._handle_remove(message)

        # Check that file was removed
        self.assertFalse(os.path.exists(self.test_file))

        # Check that success message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_remove_nonexistent(self):
        """Test handling remove for nonexistent file."""
        server = self.create_server()

        message = SFTPRemoveMessage(1, "nonexistent.txt")

        server._handle_remove(message)

        # Check that error message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_rename(self):
        """Test handling file rename."""
        server = self.create_server()

        message = SFTPRenameMessage(1, "test.txt", "renamed.txt")

        server._handle_rename(message)

        # Check that file was renamed
        old_path = os.path.join(self.temp_dir, "test.txt")
        new_path = os.path.join(self.temp_dir, "renamed.txt")
        self.assertFalse(os.path.exists(old_path))
        self.assertTrue(os.path.exists(new_path))

        # Check that success message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_handle_realpath(self):
        """Test handling realpath request."""
        server = self.create_server()

        message = SFTPRealPathMessage(1, ".")

        server._handle_realpath(message)

        # Check that name message was sent
        self.assertEqual(len(self.sent_messages), 1)

    def test_format_longname(self):
        """Test formatting long names for directory listings."""
        server = self.create_server()

        attrs = SFTPAttributes()
        attrs.flags = (
            SSH_FILEXFER_ATTR_SIZE
            | SSH_FILEXFER_ATTR_PERMISSIONS
            | SSH_FILEXFER_ATTR_ACMODTIME
            | SSH_FILEXFER_ATTR_UIDGID
        )
        attrs.size = 1024
        attrs.permissions = 0o100644  # Regular file with 644 permissions
        attrs.mtime = 1234567890
        attrs.uid = 1000
        attrs.gid = 1000

        longname = server._format_longname("test.txt", attrs)

        self.assertIn("test.txt", longname)
        self.assertIn("1024", longname)
        self.assertTrue(longname.startswith("-rw-r--r--"))

    def test_authorization_hooks(self):
        """Test authorization hook methods."""
        server = self.create_server()

        # Test default authorization (should allow all)
        self.assertTrue(server.check_file_access("/test.txt", "r"))
        self.assertTrue(server.check_file_access("/test.txt", "w"))
        self.assertTrue(server.check_directory_access("/", "r"))
        self.assertTrue(server.check_directory_access("/", "w"))

        # Test permission getters
        file_perms = server.get_file_permissions("/test.txt")
        self.assertEqual(file_perms, 0o644)

        dir_perms = server.get_directory_permissions("/testdir")
        self.assertEqual(dir_perms, 0o755)

    def test_server_close(self):
        """Test server cleanup."""
        server = self.create_server()

        # Add some handles
        handle_id = server._generate_handle()
        with open(self.test_file, "rb") as f:
            handle = SFTPHandle(handle_id, self.test_file, SSH_FXF_READ, f)
            server._handles[handle_id] = handle

        # Close server
        server.close()

        # Check that handles were cleaned up
        self.assertEqual(len(server._handles), 0)


class TestSFTPServerAuthorization(unittest.TestCase):
    """Test SFTP server authorization functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.temp_dir = tempfile.mkdtemp()
        self.mock_channel = Mock(spec=Channel)

        # Mock the channel methods
        self.sent_messages = []
        self.mock_channel.send = lambda data: self.sent_messages.append(data)
        self.mock_channel.recv = lambda size: b""

    def tearDown(self):
        """Clean up test fixtures."""
        shutil.rmtree(self.temp_dir)

    def test_custom_authorization(self):
        """Test custom authorization implementation."""

        class RestrictedSFTPServer(SFTPServer):
            def check_file_access(self, path, mode):
                # Only allow access to files starting with "allowed_"
                filename = os.path.basename(path)
                return filename.startswith("allowed_")

            def check_directory_access(self, path, mode):
                # Only allow read access to directories
                return mode == "r"

        with patch.object(SFTPServer, "_start_sftp_session"):
            server = RestrictedSFTPServer(self.mock_channel, self.temp_dir)

        # Test file access authorization
        self.assertTrue(server.check_file_access("/allowed_file.txt", "r"))
        self.assertFalse(server.check_file_access("/restricted_file.txt", "r"))

        # Test directory access authorization
        self.assertTrue(server.check_directory_access("/somedir", "r"))
        self.assertFalse(server.check_directory_access("/somedir", "w"))

    def test_permission_customization(self):
        """Test custom permission settings."""

        class CustomPermissionServer(SFTPServer):
            def get_file_permissions(self, path):
                return 0o600  # Owner read/write only

            def get_directory_permissions(self, path):
                return 0o700  # Owner full access only

        with patch.object(SFTPServer, "_start_sftp_session"):
            server = CustomPermissionServer(self.mock_channel, self.temp_dir)

        # Test custom permissions
        self.assertEqual(server.get_file_permissions("/test.txt"), 0o600)
        self.assertEqual(server.get_directory_permissions("/testdir"), 0o700)


if __name__ == "__main__":
    unittest.main()
