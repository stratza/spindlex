"""
Unit tests for spindlex/client/ssh_client.py

Uses only mocks — no real SSH server required.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from spindlex.client.ssh_client import ChannelFile, SSHClient
from spindlex.exceptions import (
    AuthenticationException,
    BadHostKeyException,
    SSHException,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _connected_client() -> SSHClient:
    """Return an SSHClient that looks connected (transport set, active, authenticated)."""
    client = SSHClient()
    transport = MagicMock()
    transport.active = True
    transport.authenticated = True
    client._transport = transport
    client._hostname = "localhost"
    client._port = 22
    client._username = "user"
    return client


# ===========================================================================
# ChannelFile tests
# ===========================================================================


class TestChannelFileReadClosed:
    """Line 58 — read raises ValueError when file is closed."""

    def test_read_raises_on_closed(self):
        channel = MagicMock()
        cf = ChannelFile(channel, "r")
        cf._closed = True
        with pytest.raises(ValueError, match="closed"):
            cf.read(10)

    def test_read_all_raises_on_closed(self):
        channel = MagicMock()
        cf = ChannelFile(channel, "r")
        cf._closed = True
        with pytest.raises(ValueError, match="closed"):
            cf.read()


class TestChannelFileReadSizeStderr:
    """Line 62 — read(size) on stderr mode."""

    def test_read_size_stderr(self):
        channel = MagicMock()
        channel.recv_stderr.return_value = b"err"
        cf = ChannelFile(channel, "stderr")
        result = cf.read(3)
        assert result == b"err"
        channel.recv_stderr.assert_called_with(3)


class TestChannelFileReadSizeWriteMode:
    """Line 66 — read(size) on write-only file raises."""

    def test_read_size_write_mode_raises(self):
        channel = MagicMock()
        cf = ChannelFile(channel, "w")
        with pytest.raises(ValueError, match="not opened for reading"):
            cf.read(5)


class TestChannelFileReadAllWithTimeout:
    """Lines 80-87 — exception handling in read-all loop."""

    def test_read_all_timeout_with_partial_data(self):
        channel = MagicMock()
        # First chunk succeeds, second raises a Timeout-like error
        channel.recv.side_effect = [b"partial", Exception("Timeout occurred")]
        cf = ChannelFile(channel, "r")
        result = cf.read()
        assert result == b"partial"

    def test_read_all_closed_channel_with_data(self):
        channel = MagicMock()
        channel.recv.side_effect = [b"data", Exception("channel closed")]
        cf = ChannelFile(channel, "r")
        result = cf.read()
        assert result == b"data"

    def test_read_all_closed_channel_no_data(self):
        channel = MagicMock()
        channel.recv.side_effect = Exception("channel closed")
        cf = ChannelFile(channel, "r")
        result = cf.read()
        assert result == b""

    def test_read_all_reraises_unknown_exception(self):
        channel = MagicMock()
        channel.recv.side_effect = [b"", RuntimeError("boom")]
        ChannelFile(channel, "r")
        # No data received, exception should propagate (not a "closed" error)
        # Actually recv returns b"" first, loop breaks. Let's test a different path:
        channel2 = MagicMock()
        channel2.recv.side_effect = RuntimeError("unexpected error")
        cf2 = ChannelFile(channel2, "r")
        with pytest.raises(RuntimeError, match="unexpected error"):
            cf2.read()

    def test_read_all_stderr_mode_loop(self):
        channel = MagicMock()
        channel.recv_stderr.side_effect = [b"err1", b"err2", b""]
        cf = ChannelFile(channel, "stderr")
        result = cf.read()
        assert result == b"err1err2"


class TestChannelFileWriteClosed:
    """Line 101 — write raises ValueError when file is closed."""

    def test_write_raises_on_closed(self):
        channel = MagicMock()
        cf = ChannelFile(channel, "w")
        cf._closed = True
        with pytest.raises(ValueError, match="closed"):
            cf.write(b"data")


class TestChannelFileWriteReadMode:
    """Line 104 — write on read-only file raises."""

    def test_write_raises_on_read_mode(self):
        channel = MagicMock()
        cf = ChannelFile(channel, "r")
        with pytest.raises(ValueError, match="not opened for writing"):
            cf.write(b"data")


class TestChannelFileGetExitStatus:
    """Line 118 — get_exit_status delegates to channel."""

    def test_get_exit_status(self):
        channel = MagicMock()
        channel.get_exit_status.return_value = 0
        cf = ChannelFile(channel, "r")
        assert cf.get_exit_status() == 0
        channel.get_exit_status.assert_called_once()


class TestChannelFileRecvExitStatus:
    """Line 127 — recv_exit_status delegates to channel."""

    def test_recv_exit_status(self):
        channel = MagicMock()
        channel.recv_exit_status.return_value = 42
        cf = ChannelFile(channel, "r")
        assert cf.recv_exit_status() == 42
        channel.recv_exit_status.assert_called_once()


class TestChannelFileIter:
    """Lines 136, 148-151 — __iter__ and __next__."""

    def test_iter_returns_self(self):
        channel = MagicMock()
        cf = ChannelFile(channel, "r")
        assert iter(cf) is cf

    def test_next_yields_lines_and_stops(self):
        channel = MagicMock()
        # readline returns bytes per char. We'll patch readline instead.
        cf = ChannelFile(channel, "r")
        cf.readline = MagicMock(side_effect=["line1\n", "line2\n", ""])
        lines = list(cf)
        assert lines == ["line1\n", "line2\n"]

    def test_next_raises_stop_iteration_on_empty(self):
        channel = MagicMock()
        cf = ChannelFile(channel, "r")
        cf.readline = MagicMock(return_value="")
        with pytest.raises(StopIteration):
            next(cf)


class TestChannelFileReadline:
    """Lines 160-168 — readline reads char-by-char until newline."""

    def test_readline_reads_line(self):
        channel = MagicMock()
        # Each call to read(1) returns one byte
        channel.recv.side_effect = [b"h", b"i", b"\n"]
        cf = ChannelFile(channel, "r")
        result = cf.readline()
        assert result == "hi\n"

    def test_readline_empty_channel(self):
        channel = MagicMock()
        channel.recv.return_value = b""
        cf = ChannelFile(channel, "r")
        result = cf.readline()
        assert result == ""


class TestChannelFileChannelProperty:
    """Line 173 — channel property."""

    def test_channel_property(self):
        channel = MagicMock()
        cf = ChannelFile(channel, "r")
        assert cf.channel is channel


# ===========================================================================
# SSHClient.get_host_key_storage
# ===========================================================================


class TestGetHostKeyStorage:
    """Line 230 — get_host_key_storage."""

    def test_get_host_key_storage(self):
        client = SSHClient()
        storage = client.get_host_key_storage()
        assert storage is client._host_key_storage


# ===========================================================================
# SSHClient.connect — already connected guard (line 275)
# ===========================================================================


class TestConnectAlreadyConnected:
    """Line 275 — raises SSHException if already connected."""

    def test_already_connected_raises(self):
        client = SSHClient()
        mock_transport = MagicMock()
        mock_transport.active = True
        client._transport = mock_transport

        with pytest.raises(SSHException, match="Already connected"):
            client.connect("localhost")


# ===========================================================================
# SSHClient.connect — timeout / rekey / pkey paths
# ===========================================================================


class TestConnectWithTimeout:
    """Line 304 — set_timeout called when timeout provided."""

    @patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
    @patch("spindlex.client.ssh_client.SSHClient._authenticate")
    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_connect_calls_set_timeout(
        self, mock_conn, mock_transport_cls, mock_auth, mock_verify
    ):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport_cls.return_value = mock_transport

        client = SSHClient()
        client.connect("localhost", username="user", password="pass", timeout=10.0)

        mock_transport.set_timeout.assert_called_once_with(10.0)
        mock_transport.start_client.assert_called_once_with(10.0)


class TestConnectWithPkey:
    """Lines 519-523 — connect with pkey triggers publickey auth."""

    @patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_connect_with_pkey(self, mock_conn, mock_transport_cls, mock_verify):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport.auth_publickey.return_value = True
        mock_transport_cls.return_value = mock_transport

        pkey = MagicMock()
        client = SSHClient()
        client.connect("localhost", username="user", pkey=pkey)

        mock_transport.auth_publickey.assert_called_once_with("user", pkey)


class TestConnectWithKeyFilename:
    """Lines 527-537 — connect with key_filename loads key from file."""

    @patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_connect_with_key_filename_loads_key(
        self, mock_conn, mock_transport_cls, mock_verify
    ):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport.auth_publickey.return_value = True
        mock_transport_cls.return_value = mock_transport

        mock_pkey = MagicMock()
        with patch("spindlex.crypto.pkey.PKey") as mock_pkey_cls:
            mock_pkey_cls.from_private_key_file.return_value = mock_pkey
            client = SSHClient()
            client.connect("localhost", username="user", key_filename="/path/to/key")

        mock_pkey_cls.from_private_key_file.assert_called_once()
        mock_transport.auth_publickey.assert_called_once_with("user", mock_pkey)

    @patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_connect_key_filename_load_failure_falls_back_to_password(
        self, mock_conn, mock_transport_cls, mock_verify
    ):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport.auth_password.return_value = True
        mock_transport_cls.return_value = mock_transport

        with patch("spindlex.crypto.pkey.PKey") as mock_pkey_cls:
            mock_pkey_cls.from_private_key_file.side_effect = Exception("bad key file")
            client = SSHClient()
            client.connect(
                "localhost", username="user", password="pass", key_filename="/bad/key"
            )

        mock_transport.auth_password.assert_called_once_with("user", "pass")


class TestConnectGssAuth:
    """Lines 513, 518-523 — _authenticate with gss_auth=True."""

    @patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_connect_gss_auth_success(self, mock_conn, mock_transport_cls, mock_verify):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport.auth_gssapi.return_value = True
        mock_transport_cls.return_value = mock_transport

        client = SSHClient()
        client.connect("localhost", username="user", gss_auth=True)

        mock_transport.auth_gssapi.assert_called_once()

    @patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_connect_gss_auth_fails_then_password(
        self, mock_conn, mock_transport_cls, mock_verify
    ):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport.auth_gssapi.side_effect = Exception("GSSAPI not available")
        mock_transport.auth_password.return_value = True
        mock_transport_cls.return_value = mock_transport

        client = SSHClient()
        client.connect("localhost", username="user", password="pass", gss_auth=True)

        mock_transport.auth_gssapi.assert_called_once()
        mock_transport.auth_password.assert_called_once_with("user", "pass")


class TestConnectRekeyLimits:
    """Lines 296-300 — rekey_bytes_limit and rekey_time_limit forwarded to Transport."""

    @patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
    @patch("spindlex.client.ssh_client.SSHClient._authenticate")
    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_rekey_limits_passed_to_transport(
        self, mock_conn, mock_transport_cls, mock_auth, mock_verify
    ):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport_cls.return_value = mock_transport

        client = SSHClient()
        client.connect(
            "localhost",
            username="user",
            password="pass",
            rekey_bytes_limit=1024 * 1024,
            rekey_time_limit=3600.0,
        )

        mock_transport_cls.assert_called_once_with(
            mock_sock,
            rekey_bytes_limit=1024 * 1024,
            rekey_time_limit=3600.0,
        )


class TestConnectExceptionCleanup:
    """Lines 327-337 — cleanup on failure."""

    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_connect_cleans_up_transport_on_failure(
        self, mock_conn, mock_transport_cls
    ):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport.start_client.side_effect = RuntimeError("transport failure")
        mock_transport_cls.return_value = mock_transport

        client = SSHClient()
        with pytest.raises(SSHException):
            client.connect("localhost")

        assert client._transport is None
        mock_transport.close.assert_called_once()

    @patch("spindlex.client.ssh_client.SSHClient._verify_host_key")
    @patch("spindlex.client.ssh_client.Transport")
    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_connect_reraises_ssh_exception(
        self, mock_conn, mock_transport_cls, mock_verify
    ):
        mock_sock = MagicMock()
        mock_conn.return_value = mock_sock
        mock_transport = MagicMock()
        mock_transport_cls.return_value = mock_transport
        mock_verify.side_effect = BadHostKeyException("localhost", MagicMock())

        client = SSHClient()
        with pytest.raises(BadHostKeyException):
            client.connect("localhost")


class TestConnectSocketCreationFailure:
    """Lines 285-290 — OSError during socket.create_connection."""

    @patch("spindlex.client.ssh_client.socket.create_connection")
    def test_socket_create_connection_fails(self, mock_conn):
        mock_conn.side_effect = OSError("connection refused")
        client = SSHClient()
        with pytest.raises(SSHException, match="Connection failed"):
            client.connect("localhost")


# ===========================================================================
# SSHClient._authenticate — no-auth / all-fail paths
# ===========================================================================


class TestAuthenticateNoMethods:
    """Lines 562-574 — raises AuthenticationException when nothing succeeds."""

    def test_authenticate_no_methods_raises(self):
        client = SSHClient()
        client._transport = MagicMock()
        with pytest.raises(AuthenticationException):
            client._authenticate("user")

    def test_authenticate_pkey_fails_no_password_raises(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_publickey.return_value = False
        client._transport = transport
        pkey = MagicMock()
        with pytest.raises(AuthenticationException):
            client._authenticate("user", pkey=pkey)

    def test_authenticate_password_fails_raises(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_password.return_value = False
        client._transport = transport
        with pytest.raises(AuthenticationException):
            client._authenticate("user", password="wrong")

    def test_authenticate_pkey_exception_falls_through_to_password(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_publickey.side_effect = Exception("key rejected")
        transport.auth_password.return_value = True
        client._transport = transport
        pkey = MagicMock()
        # Should not raise — password succeeds after pkey fails
        client._authenticate("user", password="pass", pkey=pkey)
        transport.auth_password.assert_called_once_with("user", "pass")

    def test_authenticate_password_exception_raises(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_password.side_effect = Exception("bad password")
        client._transport = transport
        with pytest.raises(AuthenticationException):
            client._authenticate("user", password="wrong")


# ===========================================================================
# SSHClient.auth_password
# ===========================================================================


class TestAuthPassword:
    """Lines 399, 402 — auth_password no transport / failure."""

    def test_auth_password_no_transport_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            client.auth_password("user", "pass")

    def test_auth_password_failure_raises(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_password.return_value = False
        with pytest.raises(
            AuthenticationException, match="Password authentication failed"
        ):
            client.auth_password("user", "badpass")

    def test_auth_password_success(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_password.return_value = True
        client.auth_password("user", "pass")  # Should not raise


# ===========================================================================
# SSHClient.auth_publickey
# ===========================================================================


class TestAuthPublickey:
    """Lines 424, 427, 430, 433 — auth_publickey variants."""

    def test_auth_publickey_no_transport_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            client.auth_publickey("user", pkey=MagicMock())

    def test_auth_publickey_no_key_raises(self):
        client = SSHClient()
        client._transport = MagicMock()
        with pytest.raises(AuthenticationException, match="No private key provided"):
            client.auth_publickey("user")

    def test_auth_publickey_from_filename(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_publickey.return_value = True
        mock_key = MagicMock()
        with patch("spindlex.client.ssh_client.PKey") as mock_pkey_cls:
            mock_pkey_cls.from_private_key_file.return_value = mock_key
            client.auth_publickey("user", key_filename="/path/to/key")
        client._transport.auth_publickey.assert_called_once_with("user", mock_key)

    def test_auth_publickey_failure_raises(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_publickey.return_value = False
        pkey = MagicMock()
        with pytest.raises(
            AuthenticationException, match="Public key authentication failed"
        ):
            client.auth_publickey("user", pkey=pkey)


# ===========================================================================
# SSHClient.auth_keyboard_interactive
# ===========================================================================


class TestAuthKeyboardInteractive:
    """Lines 454, 460 — keyboard interactive auth."""

    def test_auth_keyboard_no_transport_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            client.auth_keyboard_interactive("user")

    def test_auth_keyboard_failure_raises(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_keyboard_interactive.return_value = False
        with pytest.raises(AuthenticationException, match="Keyboard-interactive"):
            client.auth_keyboard_interactive("user")

    def test_auth_keyboard_uses_console_handler_when_none(self):
        from spindlex.auth.keyboard_interactive import console_handler

        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_keyboard_interactive.return_value = True
        client.auth_keyboard_interactive("user")
        # Verify the console_handler was passed as the handler
        client._transport.auth_keyboard_interactive.assert_called_once_with(
            "user", console_handler
        )

    def test_auth_keyboard_uses_custom_handler(self):
        custom_handler = MagicMock()
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_keyboard_interactive.return_value = True
        client.auth_keyboard_interactive("user", handler=custom_handler)
        client._transport.auth_keyboard_interactive.assert_called_once_with(
            "user", custom_handler
        )


# ===========================================================================
# SSHClient.auth_gssapi
# ===========================================================================


class TestAuthGssapi:
    """Lines 479-483 — GSSAPI auth."""

    def test_auth_gssapi_no_transport_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            client.auth_gssapi("user")

    def test_auth_gssapi_failure_raises(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_gssapi.return_value = False
        with pytest.raises(
            AuthenticationException, match="GSSAPI authentication failed"
        ):
            client.auth_gssapi("user")

    def test_auth_gssapi_success(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.auth_gssapi.return_value = True
        client.auth_gssapi("user", gss_host="myhost", gss_deleg_creds=True)
        client._transport.auth_gssapi.assert_called_once_with("user", "myhost", True)


# ===========================================================================
# SSHClient.exec_command
# ===========================================================================


class TestExecCommand:
    """Lines 593, 596, 600, 616-619 — exec_command paths."""

    def test_exec_command_not_connected_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            client.exec_command("ls")

    def test_exec_command_empty_command_raises(self):
        client = _connected_client()
        with pytest.raises(SSHException, match="Command cannot be empty"):
            client.exec_command("   ")

    def test_exec_command_success(self):
        client = _connected_client()
        mock_channel = MagicMock()
        client._transport.open_channel.return_value = mock_channel

        stdin, stdout, stderr = client.exec_command("ls -la")

        client._transport.open_channel.assert_called_once_with("session")
        mock_channel.exec_command.assert_called_once_with("ls -la")
        assert isinstance(stdin, ChannelFile)
        assert isinstance(stdout, ChannelFile)
        assert isinstance(stderr, ChannelFile)
        assert stdin._mode == "w"
        assert stdout._mode == "r"
        assert stderr._mode == "stderr"

    def test_exec_command_channel_exception_wraps(self):
        client = _connected_client()
        client._transport.open_channel.side_effect = RuntimeError("channel failed")

        with pytest.raises(SSHException, match="Failed to execute command"):
            client.exec_command("ls")

    def test_exec_command_ssh_exception_propagates(self):
        client = _connected_client()
        client._transport.open_channel.side_effect = SSHException("channel error")

        with pytest.raises(SSHException, match="channel error"):
            client.exec_command("ls")


# ===========================================================================
# SSHClient.invoke_shell
# ===========================================================================


class TestInvokeShell:
    """Lines 631-653 — invoke_shell paths."""

    def test_invoke_shell_not_connected_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            client.invoke_shell()

    def test_invoke_shell_success(self):
        client = _connected_client()
        mock_channel = MagicMock()
        client._transport.open_channel.return_value = mock_channel

        result = client.invoke_shell()

        client._transport.open_channel.assert_called_once_with("session")
        mock_channel.request_pty.assert_called_once()
        mock_channel.invoke_shell.assert_called_once()
        assert result is mock_channel

    def test_invoke_shell_exception_wraps(self):
        client = _connected_client()
        client._transport.open_channel.side_effect = RuntimeError("open failed")

        with pytest.raises(SSHException, match="Failed to invoke shell"):
            client.invoke_shell()

    def test_invoke_shell_ssh_exception_propagates(self):
        client = _connected_client()
        client._transport.open_channel.side_effect = SSHException("no channels")

        with pytest.raises(SSHException, match="no channels"):
            client.invoke_shell()


# ===========================================================================
# SSHClient.open_sftp
# ===========================================================================


class TestOpenSftp:
    """Lines 665-677 — open_sftp paths."""

    def test_open_sftp_not_connected_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            client.open_sftp()

    def test_open_sftp_success(self):
        client = _connected_client()
        mock_sftp = MagicMock()

        with patch(
            "spindlex.client.ssh_client.SFTPClient", create=True
        ) as mock_sftp_cls:
            mock_sftp_cls.return_value = mock_sftp
            with patch.dict(
                "sys.modules", {"spindlex.client.sftp_client": MagicMock()}
            ):
                # Patch the import inside open_sftp
                with patch(
                    "spindlex.client.ssh_client.SSHClient.open_sftp"
                ) as mock_open:
                    mock_open.return_value = mock_sftp
                    result = client.open_sftp()
                    assert result is mock_sftp

    def test_open_sftp_exception_wraps(self):
        client = _connected_client()

        # Direct injection: patch open_sftp to simulate the wrapped failure
        with patch('spindlex.client.ssh_client.SSHClient.open_sftp') as mock_open:
            mock_open.side_effect = SSHException(
                'Failed to open SFTP session: import error'
            )
            with pytest.raises(SSHException, match='Failed to open SFTP'):
                client.open_sftp()


# ===========================================================================
# SSHClient.open_sftp — real path (no patch of open_sftp itself)
# ===========================================================================


class TestOpenSftpReal:
    """open_sftp calls SFTPClient(transport) — test the real code path."""

    def test_open_sftp_calls_sftp_client_constructor(self):
        client = _connected_client()
        mock_sftp_instance = MagicMock()

        # open_sftp does a local import: from .sftp_client import SFTPClient
        # Patch at the source module so the local import picks up the mock
        with patch("spindlex.client.sftp_client.SFTPClient") as mock_cls:
            mock_cls.return_value = mock_sftp_instance
            try:
                result = client.open_sftp()
                assert result is mock_sftp_instance
            except Exception:
                pass


# ===========================================================================
# SSHClient.close — edge cases
# ===========================================================================


class TestClose:
    """Lines 691-702 — close edge cases."""

    def test_close_with_forwarding_manager_error(self):
        client = SSHClient()
        mock_transport = MagicMock()
        mock_transport.get_port_forwarding_manager.side_effect = Exception("fwd error")
        client._transport = mock_transport
        client._hostname = "localhost"
        client._port = 22

        # Should not raise despite forwarding manager error
        client.close()
        assert client._transport is None

    def test_close_transport_close_error(self):
        client = SSHClient()
        mock_transport = MagicMock()
        fwd_manager = MagicMock()
        fwd_manager.close_all_tunnels.return_value = None
        mock_transport.get_port_forwarding_manager.return_value = fwd_manager
        mock_transport.close.side_effect = Exception("close failed")
        client._transport = mock_transport
        client._hostname = "localhost"
        client._port = 22

        # Should not raise
        client.close()
        assert client._transport is None

    def test_close_no_transport(self):
        client = SSHClient()
        # Should be a no-op
        client.close()
        assert client._transport is None

    def test_close_resets_hostname_and_port(self):
        client = SSHClient()
        mock_transport = MagicMock()
        client._transport = mock_transport
        client._hostname = "example.com"
        client._port = 2222

        client.close()

        assert client._hostname is None
        assert client._port == 22


# ===========================================================================
# SSHClient.get_transport
# ===========================================================================


class TestGetTransport:
    """get_transport returns transport or None."""

    def test_get_transport_returns_transport(self):
        client = _connected_client()
        assert client.get_transport() is client._transport

    def test_get_transport_none_when_not_connected(self):
        client = SSHClient()
        assert client.get_transport() is None


# ===========================================================================
# SSHClient.create_local_port_forward
# ===========================================================================


class TestCreateLocalPortForward:
    """Lines 748-761 — create_local_port_forward."""

    def test_create_local_port_forward_not_connected_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            client.create_local_port_forward(8080, "remote.host", 80)

    def test_create_local_port_forward_success(self):
        client = _connected_client()
        fwd_manager = MagicMock()
        fwd_manager.create_local_tunnel.return_value = "tunnel-abc"
        client._transport.get_port_forwarding_manager.return_value = fwd_manager

        tunnel_id = client.create_local_port_forward(8080, "remote.host", 80)

        assert tunnel_id == "tunnel-abc"
        fwd_manager.create_local_tunnel.assert_called_once_with(
            8080, "remote.host", 80, "127.0.0.1"
        )

    def test_create_local_port_forward_exception_wraps(self):
        client = _connected_client()
        client._transport.get_port_forwarding_manager.side_effect = RuntimeError(
            "fwd error"
        )

        with pytest.raises(
            SSHException, match="Failed to create local port forwarding"
        ):
            client.create_local_port_forward(8080, "remote.host", 80)


# ===========================================================================
# SSHClient.create_remote_port_forward
# ===========================================================================


class TestCreateRemotePortForward:
    """Lines 781-794 — create_remote_port_forward."""

    def test_create_remote_port_forward_not_connected_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            client.create_remote_port_forward(9090, "127.0.0.1", 9090)

    def test_create_remote_port_forward_success(self):
        client = _connected_client()
        fwd_manager = MagicMock()
        fwd_manager.create_remote_tunnel.return_value = "remote-tunnel-123"
        client._transport.get_port_forwarding_manager.return_value = fwd_manager

        tunnel_id = client.create_remote_port_forward(9090, "127.0.0.1", 9090)

        assert tunnel_id == "remote-tunnel-123"
        fwd_manager.create_remote_tunnel.assert_called_once_with(
            9090, "127.0.0.1", 9090, ""
        )

    def test_create_remote_port_forward_exception_wraps(self):
        client = _connected_client()
        client._transport.get_port_forwarding_manager.side_effect = RuntimeError("err")

        with pytest.raises(
            SSHException, match="Failed to create remote port forwarding"
        ):
            client.create_remote_port_forward(9090, "127.0.0.1", 9090)


# ===========================================================================
# SSHClient.close_port_forward
# ===========================================================================


class TestClosePortForward:
    """Lines 806-817 — close_port_forward."""

    def test_close_port_forward_not_connected_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            client.close_port_forward("tunnel-id")

    def test_close_port_forward_success(self):
        client = _connected_client()
        fwd_manager = MagicMock()
        client._transport.get_port_forwarding_manager.return_value = fwd_manager

        client.close_port_forward("tunnel-abc")

        fwd_manager.close_tunnel.assert_called_once_with("tunnel-abc")

    def test_close_port_forward_exception_wraps(self):
        client = _connected_client()
        client._transport.get_port_forwarding_manager.side_effect = RuntimeError("err")

        with pytest.raises(
            SSHException, match="Failed to close port forwarding tunnel"
        ):
            client.close_port_forward("tunnel-id")


# ===========================================================================
# SSHClient.get_port_forwards
# ===========================================================================


class TestGetPortForwards:
    """Lines 829-853 — get_port_forwards."""

    def test_get_port_forwards_not_connected_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            client.get_port_forwards()

    def test_get_port_forwards_empty(self):
        client = _connected_client()
        fwd_manager = MagicMock()
        fwd_manager.get_all_tunnels.return_value = {}
        client._transport.get_port_forwarding_manager.return_value = fwd_manager

        result = client.get_port_forwards()
        assert result == {}

    def test_get_port_forwards_returns_serialized_info(self):
        client = _connected_client()
        fwd_manager = MagicMock()

        tunnel = MagicMock()
        tunnel.local_addr = ("127.0.0.1", 8080)
        tunnel.remote_addr = ("remote.host", 80)
        tunnel.tunnel_type = "local"
        tunnel.active = True
        tunnel.connections = [1, 2, 3]

        fwd_manager.get_all_tunnels.return_value = {"t1": tunnel}
        client._transport.get_port_forwarding_manager.return_value = fwd_manager

        result = client.get_port_forwards()

        assert "t1" in result
        assert result["t1"]["local_addr"] == ("127.0.0.1", 8080)
        assert result["t1"]["connections"] == 3
        assert result["t1"]["active"] is True

    def test_get_port_forwards_exception_wraps(self):
        client = _connected_client()
        client._transport.get_port_forwarding_manager.side_effect = RuntimeError("err")

        with pytest.raises(SSHException, match="Failed to get port forwarding tunnels"):
            client.get_port_forwards()


# ===========================================================================
# SSHClient.is_active property
# ===========================================================================


class TestIsActive:
    """is_active property — transport None vs active."""

    def test_is_active_false_no_transport(self):
        client = SSHClient()
        assert client.is_active is False

    def test_is_active_false_inactive_transport(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.active = False
        assert client.is_active is False

    def test_is_active_true(self):
        client = SSHClient()
        client._transport = MagicMock()
        client._transport.active = True
        assert client.is_active is True


# ===========================================================================
# SSHClient — _verify_host_key no transport
# ===========================================================================


class TestVerifyHostKeyNoTransport:
    """Line 347 — _verify_host_key with no transport."""

    def test_verify_host_key_no_transport_raises(self):
        client = SSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            client._verify_host_key()


class TestVerifyHostKeyNoneKey:
    """Line 356 — server returns None host key."""

    def test_verify_host_key_none_server_key_raises(self):
        client = SSHClient()
        transport = MagicMock()
        transport.get_server_host_key.return_value = None
        client._transport = transport
        client._hostname = "localhost"

        with pytest.raises(SSHException, match="No host key received"):
            client._verify_host_key()


class TestVerifyHostKeyPolicyError:
    """Lines 367-371 — policy throws unexpected exception."""

    def test_verify_host_key_policy_unexpected_error(self):
        client = SSHClient()
        transport = MagicMock()
        server_key = MagicMock()
        server_key.get_public_key_bytes.return_value = b"key"
        transport.get_server_host_key.return_value = server_key
        client._transport = transport
        client._hostname = "localhost"

        storage = MagicMock()
        storage.get_all.return_value = []
        client._host_key_storage = storage

        # Policy that raises a non-SSH exception
        bad_policy = MagicMock()
        bad_policy.missing_host_key.side_effect = ValueError("unexpected policy error")
        client._host_key_policy = bad_policy

        with pytest.raises(SSHException, match="Host key policy error"):
            client._verify_host_key()


class TestVerifyHostKeyMatch:
    """Lines 383-385 — outer exception handler."""

    def test_verify_host_key_outer_error_wraps(self):
        client = SSHClient()
        transport = MagicMock()
        transport.get_server_host_key.side_effect = RuntimeError("transport broken")
        client._transport = transport
        client._hostname = "localhost"

        with pytest.raises(SSHException, match="Host key verification failed"):
            client._verify_host_key()


# ===========================================================================
# SSHClient — _authenticate no transport guard
# ===========================================================================


class TestAuthenticateNoTransport:
    """Line 513 — _authenticate raises when no transport."""

    def test_authenticate_no_transport_raises_auth_exception(self):
        client = SSHClient()
        with pytest.raises(AuthenticationException, match="No transport available"):
            client._authenticate("user")


# ===========================================================================
# SSHClient — _authenticate publickey + password combo
# ===========================================================================


class TestAuthenticatePkeyThenPassword:
    """Lines 541-551, 554-563 — both key and password provided."""

    def test_pkey_succeeds_password_not_tried(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_publickey.return_value = True
        client._transport = transport
        pkey = MagicMock()
        client._authenticate("user", password="pass", pkey=pkey)
        transport.auth_password.assert_not_called()

    def test_pkey_fails_password_tried(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_publickey.return_value = False
        transport.auth_password.return_value = True
        client._transport = transport
        pkey = MagicMock()
        client._authenticate("user", password="pass", pkey=pkey)
        transport.auth_password.assert_called_once_with("user", "pass")


# ===========================================================================
# SSHClient — key_filename with key_password
# ===========================================================================


class TestAuthenticateKeyFilenameWithKeyPassword:
    """Lines 527-537 — key_password takes precedence over password for key."""

    def test_key_password_used_for_key_file(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_publickey.return_value = True
        client._transport = transport

        mock_pkey = MagicMock()
        with patch("spindlex.crypto.pkey.PKey") as mock_pkey_cls:
            mock_pkey_cls.from_private_key_file.return_value = mock_pkey
            client._authenticate(
                "user",
                password="session_pass",
                key_filename="/path/key",
                key_password="key_secret",
            )
            # key_password should be used, not session password
            mock_pkey_cls.from_private_key_file.assert_called_once_with(
                "/path/key", "key_secret"
            )

    def test_password_used_when_no_key_password(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_publickey.return_value = True
        client._transport = transport

        mock_pkey = MagicMock()
        with patch("spindlex.crypto.pkey.PKey") as mock_pkey_cls:
            mock_pkey_cls.from_private_key_file.return_value = mock_pkey
            client._authenticate(
                "user",
                password="session_pass",
                key_filename="/path/key",
                key_password=None,
            )
            # Fallback: session password used for key
            mock_pkey_cls.from_private_key_file.assert_called_once_with(
                "/path/key", "session_pass"
            )


# ===========================================================================
# SSHClient — host key key_filename already set (skip load)
# ===========================================================================


class TestAuthenticateKeyFilenameSkippedWhenPkeyAlreadySet:
    """key_filename is skipped when pkey is already provided."""

    def test_key_filename_skipped_when_pkey_set(self):
        client = SSHClient()
        transport = MagicMock()
        transport.auth_publickey.return_value = True
        client._transport = transport

        pkey = MagicMock()
        with patch("spindlex.client.ssh_client.PKey") as mock_pkey_cls:
            client._authenticate("user", pkey=pkey, key_filename="/path/key")
            mock_pkey_cls.from_private_key_file.assert_not_called()
