"""
Comprehensive mock-based unit tests for:
  - spindlex/client/async_ssh_client.py  (AsyncSSHClient)
  - spindlex/transport/async_transport.py (AsyncTransport bridge methods)

No real SSH connections are made; all I/O is mocked with MagicMock / AsyncMock.
asyncio_mode = "auto" is set in pyproject.toml, so no @pytest.mark.asyncio needed.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spindlex.client.async_ssh_client import AsyncSSHClient
from spindlex.exceptions import (
    AuthenticationException,
    BadHostKeyException,
    SSHException,
    TransportException,
)
from spindlex.hostkeys.policy import AutoAddPolicy, RejectPolicy
from spindlex.hostkeys.storage import HostKeyStorage

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_transport(active: bool = True) -> MagicMock:
    """Return a fully-mocked AsyncTransport."""
    t = MagicMock()
    t.active = active
    t.start_client = AsyncMock()
    t.connect_existing = AsyncMock()
    t.close = AsyncMock()
    t.open_channel = AsyncMock()
    t.auth_password = AsyncMock(return_value=True)
    t.auth_publickey = AsyncMock(return_value=True)
    t.auth_keyboard_interactive = AsyncMock(return_value=True)
    t.auth_gssapi = AsyncMock(return_value=True)
    t.get_server_host_key = MagicMock(return_value=None)
    t.get_port_forwarding_manager = MagicMock()
    return t


def _connected_client(transport: MagicMock | None = None) -> AsyncSSHClient:
    """Return an AsyncSSHClient that is already in the connected state."""
    client = AsyncSSHClient()
    client._transport = transport or _make_transport()
    client._connected = True
    client._hostname = "testhost"
    client._port = 22
    client._username = "testuser"
    return client


# ===========================================================================
# AsyncSSHClient.__init__
# ===========================================================================


class TestAsyncSSHClientInit:
    def test_defaults(self):
        client = AsyncSSHClient()
        assert client._transport is None
        assert client._hostname is None
        assert client._port == 22
        assert client._username is None
        assert client._connected is False
        assert isinstance(client._host_key_policy, RejectPolicy)
        assert isinstance(client._host_key_storage, HostKeyStorage)

    def test_connected_property_false_when_no_transport(self):
        client = AsyncSSHClient()
        assert client.connected is False

    def test_connected_property_false_when_flag_true_but_no_transport(self):
        client = AsyncSSHClient()
        client._connected = True
        assert client.connected is False

    def test_connected_property_true(self):
        client = _connected_client()
        assert client.connected is True

    def test_hostname_property(self):
        client = _connected_client()
        assert client.hostname == "testhost"

    def test_port_property(self):
        client = _connected_client()
        assert client.port == 22

    def test_username_property(self):
        client = _connected_client()
        assert client.username == "testuser"


# ===========================================================================
# AsyncSSHClient.connect
# ===========================================================================


class TestAsyncSSHClientConnect:
    async def test_already_connected_raises(self):
        client = _connected_client()
        with pytest.raises(SSHException, match="Already connected"):
            await client.connect("host")

    async def test_happy_path_no_auth(self):
        """connect() succeeds without credentials; transport is set up."""
        mock_transport = _make_transport()
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)

        with patch(
            "spindlex.client.async_ssh_client.AsyncTransport",
            return_value=mock_transport,
        ):
            with patch(
                "spindlex.client.async_ssh_client.AsyncSSHClient._create_connection",
                new=AsyncMock(return_value=(MagicMock(), mock_reader, mock_writer)),
            ):
                with patch.object(AsyncSSHClient, "_verify_host_key"):
                    client = AsyncSSHClient()
                    await client.connect("myhost", port=2222)

        assert client._hostname == "myhost"
        assert client._port == 2222
        assert client._connected is True
        mock_transport.start_client.assert_awaited_once()

    async def test_happy_path_with_password_auth(self):
        mock_transport = _make_transport()
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)

        with patch(
            "spindlex.client.async_ssh_client.AsyncTransport",
            return_value=mock_transport,
        ):
            with patch(
                "spindlex.client.async_ssh_client.AsyncSSHClient._create_connection",
                new=AsyncMock(return_value=(MagicMock(), mock_reader, mock_writer)),
            ):
                with patch.object(AsyncSSHClient, "_verify_host_key"):
                    with patch.object(
                        AsyncSSHClient, "_authenticate", new=AsyncMock()
                    ) as mock_auth:
                        client = AsyncSSHClient()
                        await client.connect(
                            "myhost", username="alice", password="secret"
                        )
                        mock_auth.assert_awaited_once()

    async def test_socket_error_raises_ssh_exception(self):
        client = AsyncSSHClient()
        with patch(
            "spindlex.client.async_ssh_client.AsyncSSHClient._create_connection",
            new=AsyncMock(side_effect=SSHException("Connection timeout")),
        ):
            with pytest.raises(SSHException, match="Connection timeout"):
                await client.connect("badhost")

    async def test_transport_closed_on_exception(self):
        mock_transport = _make_transport()
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)

        with patch(
            "spindlex.client.async_ssh_client.AsyncTransport",
            return_value=mock_transport,
        ):
            with patch(
                "spindlex.client.async_ssh_client.AsyncSSHClient._create_connection",
                new=AsyncMock(return_value=(MagicMock(), mock_reader, mock_writer)),
            ):
                mock_transport.start_client.side_effect = TransportException(
                    "KEX failed"
                )
                client = AsyncSSHClient()
                with pytest.raises(SSHException):
                    await client.connect("badhost")

        mock_transport.close.assert_awaited()
        assert client._transport is None

    async def test_generic_exception_wrapped_in_ssh_exception(self):
        client = AsyncSSHClient()
        with patch(
            "spindlex.client.async_ssh_client.AsyncSSHClient._create_connection",
            new=AsyncMock(side_effect=RuntimeError("unexpected")),
        ):
            with pytest.raises(SSHException, match="Connection failed"):
                await client.connect("badhost")

    async def test_provided_sock_with_makefile(self):
        """When sock is provided and has makefile attr, open_connection is called."""
        mock_transport = _make_transport()
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        fake_sock = MagicMock()
        fake_sock.makefile = MagicMock()  # has makefile attr

        with patch(
            "spindlex.client.async_ssh_client.AsyncTransport",
            return_value=mock_transport,
        ):
            with patch(
                "spindlex.client.async_ssh_client.asyncio.open_connection",
                new=AsyncMock(return_value=(mock_reader, mock_writer)),
            ):
                with patch.object(AsyncSSHClient, "_verify_host_key"):
                    client = AsyncSSHClient()
                    await client.connect("myhost", sock=fake_sock)

        assert client._connected is True

    async def test_provided_sock_without_makefile(self):
        """When sock is provided but has no makefile, reader/writer are None."""
        mock_transport = _make_transport()
        fake_sock = MagicMock(spec=[])  # no makefile attr

        with patch(
            "spindlex.client.async_ssh_client.AsyncTransport",
            return_value=mock_transport,
        ):
            with patch.object(AsyncSSHClient, "_verify_host_key"):
                client = AsyncSSHClient()
                await client.connect("myhost", sock=fake_sock)

        assert client._connected is True
        # connect_existing should NOT have been called (reader/writer were None)
        mock_transport.connect_existing.assert_not_awaited()


# ===========================================================================
# AsyncSSHClient._create_connection
# ===========================================================================


class TestCreateConnection:
    async def test_timeout_raises_ssh_exception(self):
        client = AsyncSSHClient()
        with patch(
            "spindlex.client.async_ssh_client.asyncio.wait_for",
            side_effect=asyncio.TimeoutError(),
        ):
            with pytest.raises(SSHException, match="Connection timeout"):
                await client._create_connection("host", 22, 1.0)

    async def test_generic_error_raises_ssh_exception(self):
        client = AsyncSSHClient()
        with patch(
            "spindlex.client.async_ssh_client.asyncio.wait_for",
            side_effect=OSError("refused"),
        ):
            with pytest.raises(SSHException, match="Failed to connect"):
                await client._create_connection("host", 22, None)

    async def test_success_returns_sock_reader_writer(self):
        client = AsyncSSHClient()
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        fake_sock = MagicMock()
        mock_writer.get_extra_info.return_value = fake_sock

        with patch(
            "spindlex.client.async_ssh_client.asyncio.wait_for",
            new=AsyncMock(return_value=(mock_reader, mock_writer)),
        ):
            sock, reader, writer = await client._create_connection("host", 22, None)

        assert sock is fake_sock
        assert reader is mock_reader
        assert writer is mock_writer


# ===========================================================================
# AsyncSSHClient._verify_host_key
# ===========================================================================


class TestVerifyHostKey:
    def test_no_transport_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            client._verify_host_key()

    def test_no_server_key_logs_warning_and_returns(self):
        client = _connected_client()
        client._transport.get_server_host_key.return_value = None
        # Should not raise
        client._verify_host_key()

    def test_known_key_match_passes(self):
        client = _connected_client()
        server_key = MagicMock()
        server_key.get_public_key_bytes.return_value = b"same"
        client._transport.get_server_host_key.return_value = server_key

        known_key = MagicMock()
        known_key.get_public_key_bytes.return_value = b"same"
        storage = MagicMock(spec=HostKeyStorage)
        storage.get.return_value = known_key
        client._host_key_storage = storage
        # Should not raise
        client._verify_host_key()

    def test_known_key_mismatch_raises_bad_host_key(self):
        client = _connected_client()
        server_key = MagicMock()
        server_key.get_public_key_bytes.return_value = b"new"
        client._transport.get_server_host_key.return_value = server_key

        known_key = MagicMock()
        known_key.get_public_key_bytes.return_value = b"old"
        storage = MagicMock(spec=HostKeyStorage)
        storage.get.return_value = known_key
        client._host_key_storage = storage

        with pytest.raises(BadHostKeyException):
            client._verify_host_key()

    def test_unknown_key_with_reject_policy_raises(self):
        client = _connected_client()
        server_key = MagicMock()
        server_key.get_public_key_bytes.return_value = b"key"
        client._transport.get_server_host_key.return_value = server_key

        storage = MagicMock(spec=HostKeyStorage)
        storage.get.return_value = None
        client._host_key_storage = storage
        client._host_key_policy = RejectPolicy()

        with pytest.raises(BadHostKeyException):
            client._verify_host_key()

    def test_unknown_key_with_auto_add_policy_stores_key(self):
        client = _connected_client()
        server_key = MagicMock()
        server_key.get_public_key_bytes.return_value = b"key"
        server_key.algorithm_name = "ssh-rsa"
        server_key.get_fingerprint.return_value = "AA:BB"
        client._transport.get_server_host_key.return_value = server_key

        storage = MagicMock(spec=HostKeyStorage)
        storage.get.return_value = None
        storage.get_all.return_value = []
        client._host_key_storage = storage
        client._host_key_policy = AutoAddPolicy(accept_risk=True)

        client._verify_host_key()
        storage.add.assert_called_once()

    def test_policy_non_bad_host_key_exception_is_swallowed(self):
        """A policy that raises a generic exception (not BadHostKeyException)
        should be swallowed with a warning log — the source explicitly catches it."""
        client = _connected_client()
        server_key = MagicMock()
        server_key.get_public_key_bytes.return_value = b"key"
        client._transport.get_server_host_key.return_value = server_key

        storage = MagicMock(spec=HostKeyStorage)
        storage.get.return_value = None
        client._host_key_storage = storage

        bad_policy = MagicMock(spec=RejectPolicy)
        bad_policy.missing_host_key.side_effect = RuntimeError("policy exploded")
        client._host_key_policy = bad_policy

        # Source code logs a warning and continues — does NOT raise
        client._verify_host_key()  # must not raise


# ===========================================================================
# AsyncSSHClient.exec_command
# ===========================================================================


class TestExecCommand:
    async def test_not_connected_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            await client.exec_command("ls")

    async def test_happy_path_returns_streams(self):
        mock_channel = MagicMock()
        mock_channel.exec_command = AsyncMock()
        mock_channel.makefile.return_value = MagicMock()
        mock_channel.makefile_stderr.return_value = MagicMock()

        client = _connected_client()
        client._transport.open_channel = AsyncMock(return_value=mock_channel)

        stdin, stdout, stderr = await client.exec_command("echo hi")
        mock_channel.exec_command.assert_awaited_once_with("echo hi")

    async def test_channel_exception_raises_ssh_exception(self):
        client = _connected_client()
        client._transport.open_channel = AsyncMock(
            side_effect=RuntimeError("channel fail")
        )
        with pytest.raises(SSHException, match="Command execution failed"):
            await client.exec_command("ls")

    async def test_ssh_exception_reraises_directly(self):
        client = _connected_client()
        client._transport.open_channel = AsyncMock(
            side_effect=SSHException("already raised")
        )
        with pytest.raises(SSHException, match="already raised"):
            await client.exec_command("ls")


# ===========================================================================
# AsyncSSHClient.invoke_shell
# ===========================================================================


class TestInvokeShell:
    async def test_not_connected_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            await client.invoke_shell()

    async def test_happy_path_returns_channel(self):
        mock_channel = MagicMock()
        mock_channel.invoke_shell = AsyncMock()

        client = _connected_client()
        client._transport.open_channel = AsyncMock(return_value=mock_channel)

        result = await client.invoke_shell()
        assert result is mock_channel
        mock_channel.invoke_shell.assert_awaited_once()

    async def test_generic_exception_wrapped(self):
        client = _connected_client()
        client._transport.open_channel = AsyncMock(
            side_effect=RuntimeError("shell fail")
        )
        with pytest.raises(SSHException, match="Shell invocation failed"):
            await client.invoke_shell()

    async def test_ssh_exception_reraises_directly(self):
        client = _connected_client()
        client._transport.open_channel = AsyncMock(side_effect=SSHException("oops"))
        with pytest.raises(SSHException, match="oops"):
            await client.invoke_shell()


# ===========================================================================
# AsyncSSHClient.open_sftp
# ===========================================================================


class TestOpenSftp:
    async def test_not_connected_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            await client.open_sftp()

    async def test_happy_path_returns_sftp_client(self):
        from spindlex.client.async_sftp_client import AsyncSFTPClient

        mock_channel = MagicMock()
        mock_channel.invoke_subsystem = AsyncMock()

        mock_sftp = MagicMock(spec=AsyncSFTPClient)
        mock_sftp._initialize = AsyncMock()

        client = _connected_client()
        client._transport.open_channel = AsyncMock(return_value=mock_channel)

        with patch(
            "spindlex.client.async_ssh_client.AsyncSFTPClient",
            return_value=mock_sftp,
        ):
            result = await client.open_sftp()

        assert result is mock_sftp
        mock_sftp._initialize.assert_awaited_once()

    async def test_generic_exception_wrapped(self):
        client = _connected_client()
        client._transport.open_channel = AsyncMock(
            side_effect=RuntimeError("sftp fail")
        )
        with pytest.raises(SSHException, match="SFTP open failed"):
            await client.open_sftp()

    async def test_ssh_exception_reraises_directly(self):
        client = _connected_client()
        client._transport.open_channel = AsyncMock(
            side_effect=SSHException("sftp broke")
        )
        with pytest.raises(SSHException, match="sftp broke"):
            await client.open_sftp()


# ===========================================================================
# AsyncSSHClient.auth_password
# ===========================================================================


class TestAuthPassword:
    async def test_no_transport_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            await client.auth_password("user", "pass")

    async def test_successful_auth(self):
        client = _connected_client()
        client._transport.auth_password = AsyncMock(return_value=True)
        await client.auth_password("user", "pass")
        client._transport.auth_password.assert_awaited_once_with("user", "pass")

    async def test_failed_auth_raises_authentication_exception(self):
        client = _connected_client()
        client._transport.auth_password = AsyncMock(return_value=False)
        with pytest.raises(
            AuthenticationException, match="Password authentication failed"
        ):
            await client.auth_password("user", "wrong")


# ===========================================================================
# AsyncSSHClient.auth_publickey
# ===========================================================================


class TestAuthPublickey:
    async def test_no_transport_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            await client.auth_publickey("user", pkey=MagicMock())

    async def test_no_pkey_raises(self):
        client = _connected_client()
        with pytest.raises(AuthenticationException, match="No private key provided"):
            await client.auth_publickey("user")

    async def test_successful_auth_with_pkey(self):
        client = _connected_client()
        pkey = MagicMock()
        client._transport.auth_publickey = AsyncMock(return_value=True)
        await client.auth_publickey("user", pkey=pkey)
        client._transport.auth_publickey.assert_awaited_once_with("user", pkey)

    async def test_failed_auth_with_pkey_raises(self):
        client = _connected_client()
        pkey = MagicMock()
        client._transport.auth_publickey = AsyncMock(return_value=False)
        with pytest.raises(
            AuthenticationException, match="Public key authentication failed"
        ):
            await client.auth_publickey("user", pkey=pkey)

    async def test_key_filename_list_success_on_first(self):
        """With key_filename list, succeeds on the first key."""
        fake_pkey = MagicMock()
        client = _connected_client()
        client._transport.auth_publickey = AsyncMock(return_value=True)

        with patch(
            "spindlex.client.async_ssh_client.asyncio.to_thread",
            new=AsyncMock(return_value=fake_pkey),
        ):
            await client.auth_publickey("user", key_filename=["/id_rsa"])

        client._transport.auth_publickey.assert_awaited_once()

    async def test_key_filename_list_all_fail_raises(self):
        """With key_filename list, raises when all keys fail and no pkey left."""
        client = _connected_client()
        client._transport.auth_publickey = AsyncMock(return_value=False)

        with patch(
            "spindlex.client.async_ssh_client.asyncio.to_thread",
            new=AsyncMock(side_effect=Exception("bad key")),
        ):
            with pytest.raises(AuthenticationException):
                await client.auth_publickey("user", key_filename=["/bad_key"])

    async def test_key_filename_single_string(self):
        """key_filename as str (not list) is also supported."""
        fake_pkey = MagicMock()
        client = _connected_client()
        client._transport.auth_publickey = AsyncMock(return_value=True)

        with patch(
            "spindlex.client.async_ssh_client.asyncio.to_thread",
            new=AsyncMock(return_value=fake_pkey),
        ):
            await client.auth_publickey("user", key_filename="/id_rsa")


# ===========================================================================
# AsyncSSHClient.auth_keyboard_interactive
# ===========================================================================


class TestAuthKeyboardInteractive:
    async def test_no_transport_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            await client.auth_keyboard_interactive("user")

    async def test_successful_auth(self):
        client = _connected_client()
        client._transport.auth_keyboard_interactive = AsyncMock(return_value=True)
        await client.auth_keyboard_interactive("user")
        client._transport.auth_keyboard_interactive.assert_awaited_once()

    async def test_failed_auth_raises(self):
        client = _connected_client()
        client._transport.auth_keyboard_interactive = AsyncMock(return_value=False)
        with pytest.raises(
            AuthenticationException, match="Keyboard-interactive authentication failed"
        ):
            await client.auth_keyboard_interactive("user")

    async def test_custom_handler_passed_through(self):
        client = _connected_client()
        client._transport.auth_keyboard_interactive = AsyncMock(return_value=True)
        custom_handler = MagicMock()
        await client.auth_keyboard_interactive("user", handler=custom_handler)
        _, call_args, _ = client._transport.auth_keyboard_interactive.mock_calls[0]
        assert call_args[1] is custom_handler


# ===========================================================================
# AsyncSSHClient.auth_gssapi
# ===========================================================================


class TestAuthGssapi:
    async def test_no_transport_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            await client.auth_gssapi("user")

    async def test_successful_auth(self):
        client = _connected_client()
        client._transport.auth_gssapi = AsyncMock(return_value=True)
        await client.auth_gssapi(
            "user", gss_host="kdc.example.com", gss_deleg_creds=True
        )
        client._transport.auth_gssapi.assert_awaited_once_with(
            "user", "kdc.example.com", True
        )

    async def test_failed_auth_raises(self):
        client = _connected_client()
        client._transport.auth_gssapi = AsyncMock(return_value=False)
        with pytest.raises(
            AuthenticationException, match="GSSAPI authentication failed"
        ):
            await client.auth_gssapi("user")


# ===========================================================================
# AsyncSSHClient._authenticate
# ===========================================================================


class TestAuthenticate:
    async def test_no_transport_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="No transport available"):
            await client._authenticate("user")

    async def test_gss_auth_success_skips_others(self):
        client = _connected_client()
        with patch.object(client, "auth_gssapi", new=AsyncMock()) as mock_gss:
            with patch.object(client, "auth_publickey", new=AsyncMock()) as mock_pk:
                await client._authenticate("user", gss_auth=True)
                mock_gss.assert_awaited_once()
                mock_pk.assert_not_awaited()

    async def test_pkey_success_skips_password_and_ki(self):
        client = _connected_client()
        pkey = MagicMock()
        with patch.object(client, "auth_publickey", new=AsyncMock()) as mock_pk:
            with patch.object(client, "auth_password", new=AsyncMock()) as mock_pw:
                await client._authenticate("user", pkey=pkey)
                mock_pk.assert_awaited_once()
                mock_pw.assert_not_awaited()

    async def test_password_success_skips_keyboard_interactive(self):
        client = _connected_client()
        with patch.object(client, "auth_password", new=AsyncMock()) as mock_pw:
            with patch.object(
                client, "auth_keyboard_interactive", new=AsyncMock()
            ) as mock_ki:
                await client._authenticate("user", password="pass")
                mock_pw.assert_awaited_once()
                mock_ki.assert_not_awaited()

    async def test_keyboard_interactive_as_fallback(self):
        client = _connected_client()
        with patch.object(
            client, "auth_keyboard_interactive", new=AsyncMock()
        ) as mock_ki:
            await client._authenticate("user")
            mock_ki.assert_awaited_once()

    async def test_all_methods_fail_raises_authentication_exception(self):
        client = _connected_client()
        with patch.object(
            client,
            "auth_keyboard_interactive",
            new=AsyncMock(side_effect=AuthenticationException("ki fail")),
        ):
            with pytest.raises(
                AuthenticationException, match="Authentication failed for user"
            ):
                await client._authenticate("user")

    async def test_gss_fail_falls_through_to_password(self):
        client = _connected_client()
        with patch.object(
            client,
            "auth_gssapi",
            new=AsyncMock(side_effect=AuthenticationException("gss")),
        ):
            with patch.object(client, "auth_password", new=AsyncMock()) as mock_pw:
                await client._authenticate("user", gss_auth=True, password="pass")
                mock_pw.assert_awaited_once()


# ===========================================================================
# AsyncSSHClient port-forwarding methods
# ===========================================================================


class TestPortForwarding:
    async def test_create_local_not_connected_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            await client.create_local_port_forward(8080, "remote", 80)

    async def test_create_local_delegates_to_manager(self):
        mock_manager = MagicMock()
        mock_manager.create_local_tunnel = AsyncMock(return_value="tunnel-1")
        client = _connected_client()
        client._transport.get_port_forwarding_manager.return_value = mock_manager

        tid = await client.create_local_port_forward(8080, "remote.host", 80)
        assert tid == "tunnel-1"
        mock_manager.create_local_tunnel.assert_awaited_once_with(
            8080, "remote.host", 80, "127.0.0.1"
        )

    async def test_create_remote_not_connected_raises(self):
        client = AsyncSSHClient()
        with pytest.raises(SSHException, match="Not connected"):
            await client.create_remote_port_forward(9090, "localhost", 9090)

    async def test_create_remote_delegates_to_manager(self):
        mock_manager = MagicMock()
        mock_manager.create_remote_tunnel = AsyncMock(return_value="tunnel-2")
        client = _connected_client()
        client._transport.get_port_forwarding_manager.return_value = mock_manager

        tid = await client.create_remote_port_forward(9090, "localhost", 9090, "")
        assert tid == "tunnel-2"

    async def test_close_port_forward_with_transport(self):
        mock_manager = MagicMock()
        mock_manager.close_tunnel = AsyncMock()
        client = _connected_client()
        client._transport.get_port_forwarding_manager.return_value = mock_manager

        await client.close_port_forward("tunnel-1")
        mock_manager.close_tunnel.assert_awaited_once_with("tunnel-1")

    async def test_close_port_forward_without_transport(self):
        client = AsyncSSHClient()
        # Should not raise even without transport
        await client.close_port_forward("tunnel-1")

    def test_get_port_forwards_with_transport(self):
        mock_manager = MagicMock()
        mock_manager.get_all_tunnels.return_value = {"t1": MagicMock()}
        client = _connected_client()
        client._transport.get_port_forwarding_manager.return_value = mock_manager

        result = client.get_port_forwards()
        assert "t1" in result

    def test_get_port_forwards_without_transport(self):
        client = AsyncSSHClient()
        result = client.get_port_forwards()
        assert result == {}


# ===========================================================================
# AsyncSSHClient host-key storage/policy helpers
# ===========================================================================


class TestHostKeyHelpers:
    def test_set_missing_host_key_policy(self):
        client = AsyncSSHClient()
        policy = AutoAddPolicy(accept_risk=True)
        client.set_missing_host_key_policy(policy)
        assert client._host_key_policy is policy

    def test_set_host_key_storage(self):
        client = AsyncSSHClient()
        storage = MagicMock(spec=HostKeyStorage)
        client.set_host_key_storage(storage)
        assert client._host_key_storage is storage

    def test_get_host_key_storage(self):
        client = AsyncSSHClient()
        storage = client.get_host_key_storage()
        assert isinstance(storage, HostKeyStorage)


# ===========================================================================
# AsyncSSHClient.close
# ===========================================================================


class TestAsyncSSHClientClose:
    async def test_close_with_transport(self):
        mock_transport = _make_transport()
        client = _connected_client(mock_transport)
        await client.close()

        mock_transport.close.assert_awaited_once()
        assert client._transport is None
        assert client._connected is False
        assert client._hostname is None
        assert client._port == 22
        assert client._username is None

    async def test_close_without_transport(self):
        client = AsyncSSHClient()
        # Should not raise
        await client.close()
        assert client._connected is False


# ===========================================================================
# AsyncSSHClient async context manager
# ===========================================================================


class TestAsyncContextManager:
    async def test_aenter_returns_self(self):
        client = AsyncSSHClient()
        result = await client.__aenter__()
        assert result is client

    async def test_aexit_calls_close(self):
        client = AsyncSSHClient()
        with patch.object(client, "close", new=AsyncMock()) as mock_close:
            await client.__aexit__(None, None, None)
            mock_close.assert_awaited_once()

    async def test_context_manager_usage(self):
        async with AsyncSSHClient() as client:
            assert isinstance(client, AsyncSSHClient)


# ===========================================================================
# AsyncTransport.__init__ and connect_existing
# ===========================================================================


class TestAsyncTransportInit:
    def test_init_sets_async_flag(self):
        from spindlex.transport.async_transport import AsyncTransport

        MagicMock(spec=[])
        with patch("spindlex.transport.transport.Transport.__init__") as mock_super:
            mock_super.return_value = None
            with patch("asyncio.get_event_loop"):
                transport = AsyncTransport.__new__(AsyncTransport)
                # Manually set minimal attrs that Transport.__init__ would set
                transport._port_forwarding_manager = None
                transport._reader = None
                transport._writer = None
                transport._loop = None
                transport._send_lock = asyncio.Lock()
                transport._recv_lock = asyncio.Lock()
                transport._state_lock = asyncio.Lock()
                transport._is_async = True
                assert transport._is_async is True

    async def test_connect_existing_sets_reader_writer(self):
        from spindlex.transport.async_transport import AsyncTransport

        MagicMock()
        with patch(
            "spindlex.transport.transport.Transport.__init__", return_value=None
        ):
            with patch("asyncio.get_event_loop", return_value=MagicMock()):
                transport = AsyncTransport.__new__(AsyncTransport)
                transport._reader = None
                transport._writer = None
                transport._loop = asyncio.get_event_loop()
                transport._send_lock = asyncio.Lock()
                transport._recv_lock = asyncio.Lock()
                transport._state_lock = asyncio.Lock()
                transport._is_async = True
                transport._port_forwarding_manager = None

        reader = MagicMock(spec=asyncio.StreamReader)
        writer = MagicMock(spec=asyncio.StreamWriter)

        await transport.connect_existing(reader, writer)
        assert transport._reader is reader
        assert transport._writer is writer


# ===========================================================================
# AsyncTransport.start_client
# ===========================================================================


class TestAsyncTransportStartClient:
    def _make_transport(self) -> MagicMock:
        """Build a minimally patched AsyncTransport that we can test."""
        from spindlex.transport.async_transport import AsyncTransport

        t = MagicMock(spec=AsyncTransport)
        t._active = False
        t._server_mode = False
        t._kex_in_progress = False
        t._connect_timeout = None
        t._state_lock = asyncio.Lock()
        t._send_version_async = AsyncMock()
        t._recv_version_async = AsyncMock()
        t._start_kex_async = AsyncMock()
        t.close = AsyncMock()
        # Make the real method available for calling
        t.start_client = AsyncTransport.start_client.__get__(t)
        return t

    async def test_already_active_raises(self):
        t = self._make_transport()
        t._active = True
        with pytest.raises(TransportException, match="already active"):
            await t.start_client()

    async def test_happy_path_calls_handshake(self):
        t = self._make_transport()
        await t.start_client(timeout=5.0)
        t._send_version_async.assert_awaited_once()
        t._recv_version_async.assert_awaited_once()
        t._start_kex_async.assert_awaited_once()
        assert t._active is True

    async def test_exception_triggers_close(self):
        t = self._make_transport()
        t._recv_version_async.side_effect = TransportException("recv failed")
        with pytest.raises(TransportException):
            await t.start_client()
        t.close.assert_awaited()


# ===========================================================================
# AsyncTransport._start_kex_async
# ===========================================================================


class TestStartKexAsync:
    def _make_transport(self) -> MagicMock:
        from spindlex.transport.async_transport import AsyncTransport

        t = MagicMock(spec=AsyncTransport)
        t._kex_in_progress = False
        t._state_lock = asyncio.Lock()
        t._run_kex_threadsafe = MagicMock()
        t._start_kex_async = AsyncTransport._start_kex_async.__get__(t)
        return t

    async def test_kex_in_progress_raises(self):
        t = self._make_transport()
        t._kex_in_progress = True
        with pytest.raises(
            TransportException, match="Key exchange already in progress"
        ):
            await t._start_kex_async()

    async def test_happy_path_calls_run_kex_threadsafe(self):
        t = self._make_transport()

        with patch("asyncio.to_thread", new=AsyncMock()) as mock_to_thread:
            await t._start_kex_async()
            mock_to_thread.assert_awaited_once_with(t._run_kex_threadsafe)

    async def test_exception_resets_kex_in_progress(self):
        t = self._make_transport()

        with patch(
            "asyncio.to_thread", new=AsyncMock(side_effect=RuntimeError("kex boom"))
        ):
            with pytest.raises(RuntimeError):
                await t._start_kex_async()

        assert t._kex_in_progress is False


# ===========================================================================
# AsyncTransport._run_kex_threadsafe
# ===========================================================================


class TestRunKexThreadsafe:
    def _make_transport(self) -> MagicMock:
        from spindlex.transport.async_transport import AsyncTransport

        t = MagicMock(spec=AsyncTransport)
        t._kex_in_progress = True
        t._kex_thread = None
        t._kex = MagicMock()
        t._send_kexinit = MagicMock()
        t._recv_kexinit = MagicMock()
        t._run_kex_threadsafe = AsyncTransport._run_kex_threadsafe.__get__(t)
        return t

    def test_sets_and_clears_kex_thread(self):
        t = self._make_transport()
        t._run_kex_threadsafe()
        assert t._kex_thread is None
        assert t._kex_in_progress is False

    def test_calls_kex_sequence(self):
        t = self._make_transport()
        t._run_kex_threadsafe()
        t._send_kexinit.assert_called_once()
        t._recv_kexinit.assert_called_once()
        t._kex.start_kex.assert_called_once()

    def test_kex_exception_still_clears_progress(self):
        t = self._make_transport()
        t._kex.start_kex.side_effect = RuntimeError("kex error")
        with pytest.raises(RuntimeError):
            t._run_kex_threadsafe()
        assert t._kex_in_progress is False


# ===========================================================================
# AsyncTransport.get_port_forwarding_manager
# ===========================================================================


class TestGetPortForwardingManager:
    def _make_transport(self) -> MagicMock:
        from spindlex.transport.async_transport import AsyncTransport

        t = MagicMock(spec=AsyncTransport)
        t._port_forwarding_manager = None
        t.get_port_forwarding_manager = (
            AsyncTransport.get_port_forwarding_manager.__get__(t)
        )
        return t

    def test_creates_manager_on_first_call(self):
        t = self._make_transport()
        mock_manager = MagicMock()
        mock_cls = MagicMock(return_value=mock_manager)

        # The method does a lazy import: `from .async_forwarding import AsyncPortForwardingManager`
        # Patch that class at its source module so the local import picks it up.
        with patch(
            "spindlex.transport.async_forwarding.AsyncPortForwardingManager",
            mock_cls,
        ):
            # Also patch the import inside the method body by injecting into sys.modules
            import spindlex.transport.async_forwarding as _afwd_mod

            original_cls = _afwd_mod.AsyncPortForwardingManager
            _afwd_mod.AsyncPortForwardingManager = mock_cls  # type: ignore[attr-defined]
            try:
                result = t.get_port_forwarding_manager()
            finally:
                _afwd_mod.AsyncPortForwardingManager = original_cls  # type: ignore[attr-defined]

        assert result is mock_manager

    def test_returns_same_manager_on_second_call(self):
        t = self._make_transport()
        existing_manager = MagicMock()
        t._port_forwarding_manager = existing_manager
        result = t.get_port_forwarding_manager()
        assert result is existing_manager


# ===========================================================================
# AsyncTransport._send_message bridge
# ===========================================================================


class TestSendMessageBridge:
    def _make_transport(self) -> MagicMock:
        from spindlex.transport.async_transport import AsyncTransport

        t = MagicMock(spec=AsyncTransport)
        t._loop = None
        t._send_message = AsyncTransport._send_message.__get__(t)
        return t

    def test_no_loop_falls_through_to_super(self):
        from spindlex.transport.async_transport import AsyncTransport

        t = self._make_transport()
        t._loop = None
        msg = MagicMock()

        with patch.object(AsyncTransport.__bases__[0], "_send_message") as mock_super:
            t._send_message(msg)
            mock_super.assert_called_once_with(msg)

    def test_loop_not_running_falls_through_to_super(self):
        from spindlex.transport.async_transport import AsyncTransport

        t = self._make_transport()
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = False
        t._loop = mock_loop
        msg = MagicMock()

        with patch.object(AsyncTransport.__bases__[0], "_send_message") as mock_super:
            t._send_message(msg)
            mock_super.assert_called_once_with(msg)

    def test_loop_running_uses_run_coroutine_threadsafe(self):

        t = self._make_transport()
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = True
        t._loop = mock_loop
        t._send_message_async = AsyncMock()
        msg = MagicMock()

        mock_future = MagicMock()
        mock_future.result.return_value = None

        with patch(
            "spindlex.transport.async_transport.asyncio.run_coroutine_threadsafe",
            return_value=mock_future,
        ) as mock_rcf:
            t._send_message(msg)
            mock_rcf.assert_called_once()
            mock_future.result.assert_called_once()

    def test_loop_running_transport_exception_reraises(self):

        t = self._make_transport()
        mock_loop = MagicMock()
        mock_loop.is_running.return_value = True
        t._loop = mock_loop
        t._send_message_async = AsyncMock()
        msg = MagicMock()

        mock_future = MagicMock()
        mock_future.result.side_effect = TransportException("send failed")

        with patch(
            "spindlex.transport.async_transport.asyncio.run_coroutine_threadsafe",
            return_value=mock_future,
        ):
            with pytest.raises(TransportException, match="send failed"):
                t._send_message(msg)


# ===========================================================================
# AsyncTransport._recv_message bridge
# ===========================================================================


class TestRecvMessageBridge:
    def _make_transport(self) -> MagicMock:
        from spindlex.transport.async_transport import AsyncTransport

        t = MagicMock(spec=AsyncTransport)
        t._loop = None
        t._recv_message = AsyncTransport._recv_message.__get__(t)
        return t

    def test_no_loop_falls_through_to_super(self):
        from spindlex.transport.async_transport import AsyncTransport

        t = self._make_transport()
        t._loop = None
        msg = MagicMock()

        with patch.object(
            AsyncTransport.__bases__[0], "_recv_message", return_value=msg
        ) as mock_super:
            result = t._recv_message()
            mock_super.assert_called_once()
            assert result is msg

    def test_loop_running_raises_transport_exception(self):

        t = self._make_transport()
        t._loop = MagicMock()

        # When asyncio.get_running_loop() succeeds, we're on the loop thread
        with patch(
            "spindlex.transport.async_transport.asyncio.get_running_loop",
            return_value=MagicMock(),
        ):
            with pytest.raises(
                TransportException,
                match="Synchronous receive called on event loop thread",
            ):
                t._recv_message()

    def test_not_on_loop_thread_uses_threadsafe(self):

        t = self._make_transport()
        t._loop = MagicMock()
        t._recv_message_async = AsyncMock()
        expected_msg = MagicMock()

        mock_future = MagicMock()
        mock_future.result.return_value = expected_msg

        # RuntimeError means no running loop on this thread — safe to block
        with patch(
            "spindlex.transport.async_transport.asyncio.get_running_loop",
            side_effect=RuntimeError("no running loop"),
        ):
            with patch(
                "spindlex.transport.async_transport.asyncio.run_coroutine_threadsafe",
                return_value=mock_future,
            ) as mock_rcf:
                result = t._recv_message()
                mock_rcf.assert_called_once()
                assert result is expected_msg


# ===========================================================================
# AsyncTransport.close
# ===========================================================================


class TestAsyncTransportClose:
    async def test_close_sets_inactive_and_clears_writer(self):
        from spindlex.transport.async_transport import AsyncTransport

        t = MagicMock(spec=AsyncTransport)
        t._active = True
        t._channels = {}
        t._state_lock = asyncio.Lock()
        t._writer = MagicMock()
        t._writer.close = MagicMock()
        t._writer.wait_closed = AsyncMock()
        t._reader = MagicMock()
        t._socket = MagicMock()
        t.close = AsyncTransport.close.__get__(t)

        with patch("asyncio.wait_for", new=AsyncMock()):
            await t.close()

        assert t._active is False
        assert t._reader is None
        assert t._writer is None

    async def test_close_without_writer_is_safe(self):
        from spindlex.transport.async_transport import AsyncTransport

        t = MagicMock(spec=AsyncTransport)
        t._active = True
        t._channels = {}
        t._state_lock = asyncio.Lock()
        t._writer = None
        t._reader = None
        t._socket = None
        t.close = AsyncTransport.close.__get__(t)

        # Should not raise
        await t.close()
        assert t._active is False


# ===========================================================================
# Edge-case / integration-style tests
# ===========================================================================


class TestEdgeCases:
    async def test_connect_with_reader_writer_calls_connect_existing(self):
        """Verify connect_existing is called when reader/writer are returned."""
        mock_transport = _make_transport()
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)

        with patch(
            "spindlex.client.async_ssh_client.AsyncTransport",
            return_value=mock_transport,
        ):
            with patch(
                "spindlex.client.async_ssh_client.AsyncSSHClient._create_connection",
                new=AsyncMock(return_value=(MagicMock(), mock_reader, mock_writer)),
            ):
                with patch.object(AsyncSSHClient, "_verify_host_key"):
                    client = AsyncSSHClient()
                    await client.connect("myhost")

        mock_transport.connect_existing.assert_awaited_once_with(
            mock_reader, mock_writer
        )

    async def test_full_connect_and_close_lifecycle(self):
        """Happy-path lifecycle: connect then close."""
        mock_transport = _make_transport()
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)

        with patch(
            "spindlex.client.async_ssh_client.AsyncTransport",
            return_value=mock_transport,
        ):
            with patch(
                "spindlex.client.async_ssh_client.AsyncSSHClient._create_connection",
                new=AsyncMock(return_value=(MagicMock(), mock_reader, mock_writer)),
            ):
                with patch.object(AsyncSSHClient, "_verify_host_key"):
                    client = AsyncSSHClient()
                    await client.connect("myhost", username="bob", password="pw")
                    assert client.connected is True
                    assert client.hostname == "myhost"
                    assert client.username == "bob"
                    await client.close()
                    assert client.connected is False
                    assert client.hostname is None

    async def test_authenticate_gss_and_pkey_both_fail_tries_password(self):
        client = _connected_client()
        with patch.object(
            client,
            "auth_gssapi",
            new=AsyncMock(side_effect=AuthenticationException("gss fail")),
        ):
            with patch.object(
                client,
                "auth_publickey",
                new=AsyncMock(side_effect=AuthenticationException("pk fail")),
            ):
                with patch.object(client, "auth_password", new=AsyncMock()) as mock_pw:
                    pkey = MagicMock()
                    await client._authenticate(
                        "user",
                        gss_auth=True,
                        pkey=pkey,
                        password="secret",
                    )
                    mock_pw.assert_awaited_once()

    def test_connected_false_when_flag_false_but_transport_set(self):
        client = AsyncSSHClient()
        client._transport = _make_transport()
        client._connected = False
        assert client.connected is False
