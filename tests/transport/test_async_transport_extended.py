"""Extended unit tests for AsyncTransport - covering version exchange, channel ops, auth service, close."""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spindlex.exceptions import ProtocolException, TransportException
from spindlex.protocol.constants import (
    MSG_NEWKEYS,
    MSG_REQUEST_SUCCESS,
)
from spindlex.protocol.messages import (
    ChannelOpenFailureMessage,
    KexInitMessage,
    Message,
)
from spindlex.transport.async_transport import AsyncTransport


@pytest.fixture
def mock_socket():
    sock = MagicMock(spec=socket.socket)
    sock.fileno.return_value = 1
    return sock


@pytest.fixture
def transport(mock_socket):
    return AsyncTransport(mock_socket)


@pytest.fixture
async def connected_transport(transport):
    reader = MagicMock(spec=asyncio.StreamReader)
    writer = MagicMock(spec=asyncio.StreamWriter)
    await transport.connect_existing(reader, writer)
    return transport


# ---- Version Exchange ----


class TestVersionExchange:
    @pytest.mark.asyncio
    async def test_send_version_client_mode(self, connected_transport):
        t = connected_transport
        t._server_mode = False
        await t._send_version_async()
        t._writer.write.assert_called_once()
        assert t._client_version is not None

    @pytest.mark.asyncio
    async def test_send_version_server_mode(self, connected_transport):
        t = connected_transport
        t._server_mode = True
        await t._send_version_async()
        assert t._server_version is not None

    @pytest.mark.asyncio
    async def test_recv_version_client_mode(self, connected_transport):
        t = connected_transport
        t._server_mode = False
        t._reader.readline = AsyncMock(return_value=b"SSH-2.0-TestServer\r\n")
        await t._recv_version_async()
        assert t._server_version == "SSH-2.0-TestServer"

    @pytest.mark.asyncio
    async def test_recv_version_server_mode(self, connected_transport):
        t = connected_transport
        t._server_mode = True
        t._reader.readline = AsyncMock(return_value=b"SSH-2.0-TestClient\r\n")
        await t._recv_version_async()
        assert t._client_version == "SSH-2.0-TestClient"

    @pytest.mark.asyncio
    async def test_recv_version_skips_non_ssh_lines(self, connected_transport):
        t = connected_transport
        t._server_mode = False
        t._reader.readline = AsyncMock(
            side_effect=[
                b"some banner\r\n",
                b"another line\r\n",
                b"SSH-2.0-RealServer\r\n",
            ]
        )
        await t._recv_version_async()
        assert t._server_version == "SSH-2.0-RealServer"

    @pytest.mark.asyncio
    async def test_recv_version_connection_closed(self, connected_transport):
        t = connected_transport
        t._reader.readline = AsyncMock(return_value=b"")
        with pytest.raises(TransportException, match="Connection closed"):
            await t._recv_version_async()


# ---- KEX ----


class TestKexAsync:
    @pytest.mark.asyncio
    async def test_start_kex_already_in_progress(self, connected_transport):
        t = connected_transport
        t._kex_in_progress = True
        with pytest.raises(TransportException, match="already in progress"):
            await t._start_kex_async()

    @pytest.mark.asyncio
    async def test_start_kex_async_calls_thread(self, connected_transport):
        t = connected_transport
        with patch.object(t, "_run_kex_threadsafe"):
            await t._start_kex_async()

    @pytest.mark.asyncio
    async def test_start_kex_error_resets_flag(self, connected_transport):
        t = connected_transport
        with patch.object(
            t, "_run_kex_threadsafe", side_effect=RuntimeError("kex fail")
        ):
            with pytest.raises(RuntimeError):
                await t._start_kex_async()
        assert t._kex_in_progress is False

    @pytest.mark.asyncio
    async def test_recv_kexinit_async(self, connected_transport):
        t = connected_transport
        kexinit = MagicMock(spec=KexInitMessage)
        kexinit.__class__ = KexInitMessage
        with patch.object(
            t, "_wait_for_message_async", new=AsyncMock(return_value=kexinit)
        ):
            await t._recv_kexinit_async()
        assert t._peer_kexinit is kexinit

    @pytest.mark.asyncio
    async def test_recv_kexinit_wrong_type_raises(self, connected_transport):
        t = connected_transport
        msg = MagicMock(spec=Message)
        with patch.object(
            t, "_wait_for_message_async", new=AsyncMock(return_value=msg)
        ):
            with pytest.raises(ProtocolException, match="Expected KEXINIT"):
                await t._recv_kexinit_async()

    @pytest.mark.asyncio
    async def test_send_kexinit_async(self, connected_transport):
        t = connected_transport
        with patch.object(t, "_send_kexinit") as mock:
            await t._send_kexinit_async()
            mock.assert_called_once()


# ---- Auth Service ----


class TestAuthAsync:
    @pytest.mark.asyncio
    async def test_auth_password_requests_service(self, connected_transport):
        t = connected_transport
        t._userauth_service_requested = False
        with patch.object(t, "_send_message_async", new=AsyncMock()):
            with patch.object(t, "_expect_message_async", new=AsyncMock()):
                with patch("spindlex.auth.password.PasswordAuth") as mock_cls:
                    mock_auth = mock_cls.return_value
                    mock_auth.authenticate_async = AsyncMock(
                        return_value=MagicMock(msg_type=52)
                    )
                    with patch.object(
                        t, "_handle_auth_response_message", return_value=True
                    ):
                        await t.auth_password("u", "p")
        assert t._userauth_service_requested is True

    @pytest.mark.asyncio
    async def test_auth_publickey_requests_service(self, connected_transport):
        t = connected_transport
        t._userauth_service_requested = False
        with patch.object(t, "_send_message_async", new=AsyncMock()):
            with patch.object(t, "_expect_message_async", new=AsyncMock()):
                with patch("spindlex.auth.publickey.PublicKeyAuth") as mock_cls:
                    mock_auth = mock_cls.return_value
                    mock_auth.authenticate_async = AsyncMock(
                        return_value=MagicMock(msg_type=52)
                    )
                    with patch.object(
                        t, "_handle_auth_response_message", return_value=True
                    ):
                        await t.auth_publickey("u", MagicMock())
        assert t._userauth_service_requested is True

    @pytest.mark.asyncio
    async def test_auth_keyboard_interactive(self, connected_transport):
        t = connected_transport
        t._userauth_service_requested = True
        with patch.object(t, "_send_message_async", new=AsyncMock()):
            with patch(
                "spindlex.auth.keyboard_interactive.AsyncKeyboardInteractiveAuth"
            ) as mock_cls:
                mock_auth = mock_cls.return_value
                mock_auth.authenticate_async = AsyncMock(return_value=True)
                result = await t.auth_keyboard_interactive("u", MagicMock())
        assert result is True
        assert t._authenticated is True

    @pytest.mark.asyncio
    async def test_auth_gssapi(self, connected_transport):
        t = connected_transport
        t._userauth_service_requested = True
        with patch.object(t, "_send_message_async", new=AsyncMock()):
            with patch.object(t, "_expect_message_async", new=AsyncMock()):
                with patch("spindlex.auth.gssapi.GSSAPIAuth") as mock_cls:
                    mock_auth = mock_cls.return_value
                    mock_auth.authenticate.return_value = True
                    mock_auth.cleanup = MagicMock()
                    result = await t.auth_gssapi("u")
        assert result is True
        assert t._authenticated is True


# ---- Channel Ops ----


class TestChannelOpsAsync:
    @pytest.mark.asyncio
    async def test_send_channel_request_async(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = 5
        t._channels[0] = chan
        with patch.object(t, "_send_message_async", new=AsyncMock()) as m:
            await t._send_channel_request_async(0, "exec", True, b"ls")
            m.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_channel_request_no_remote_id(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = None
        t._channels[0] = chan
        with pytest.raises(TransportException, match="remote ID not set"):
            await t._send_channel_request_async(0, "exec", True, b"ls")

    @pytest.mark.asyncio
    async def test_send_channel_data_async(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = 5
        t._channels[0] = chan
        with patch.object(t, "_send_message_async", new=AsyncMock()) as m:
            await t._send_channel_data_async(0, b"data")
            m.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_channel_data_no_remote_id(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = None
        t._channels[0] = chan
        with pytest.raises(TransportException, match="remote ID not set"):
            await t._send_channel_data_async(0, b"data")

    @pytest.mark.asyncio
    async def test_send_channel_eof_async(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = 5
        t._channels[0] = chan
        with patch.object(t, "_send_message_async", new=AsyncMock()) as m:
            await t._send_channel_eof_async(0)
            m.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_channel_eof_no_remote_id(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = None
        t._channels[0] = chan
        await t._send_channel_eof_async(0)  # should just return

    @pytest.mark.asyncio
    async def test_send_channel_close_async(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = 5
        t._channels[0] = chan
        with patch.object(t, "_send_message_async", new=AsyncMock()) as m:
            await t._send_channel_close_async(0)
            m.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_channel_close_no_remote_id(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = None
        t._channels[0] = chan
        await t._send_channel_close_async(0)  # should just return

    @pytest.mark.asyncio
    async def test_send_channel_window_adjust_async(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = 5
        t._channels[0] = chan
        with patch.object(t, "_send_message_async", new=AsyncMock()) as m:
            await t._send_channel_window_adjust_async(0, 1024)
            m.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_channel_window_adjust_no_channel(self, connected_transport):
        t = connected_transport
        await t._send_channel_window_adjust_async(99, 1024)  # should just return

    @pytest.mark.asyncio
    async def test_send_channel_window_adjust_no_remote_id(self, connected_transport):
        t = connected_transport
        chan = MagicMock()
        chan._remote_channel_id = None
        t._channels[0] = chan
        await t._send_channel_window_adjust_async(0, 1024)  # should just return


# ---- Global Request ----


class TestGlobalRequestAsync:
    @pytest.mark.asyncio
    async def test_send_global_request_with_reply(self, connected_transport):
        t = connected_transport
        msg = MagicMock(spec=Message)
        msg.msg_type = MSG_REQUEST_SUCCESS
        with patch.object(t, "_send_message_async", new=AsyncMock()):
            with patch.object(
                t, "_expect_message_async", new=AsyncMock(return_value=msg)
            ):
                result = await t._send_global_request_async("test", True)
        assert result is msg

    @pytest.mark.asyncio
    async def test_send_global_request_no_reply(self, connected_transport):
        t = connected_transport
        with patch.object(t, "_send_message_async", new=AsyncMock()):
            result = await t._send_global_request_async("test", False)
        assert result is None


# ---- Forwarding Bridge ----


class TestForwardingBridge:
    def test_handle_forwarded_tcpip_with_manager(self, transport):
        transport._loop = MagicMock()
        mgr = MagicMock()
        mgr.handle_forwarded_connection_async = AsyncMock()
        transport._port_forwarding_manager = mgr
        with patch("asyncio.run_coroutine_threadsafe") as mock_rcs:
            transport._handle_forwarded_tcpip_open(0, 1024, 512, b"data")
            mock_rcs.assert_called_once()

    def test_handle_forwarded_tcpip_no_manager(self, transport):
        transport._port_forwarding_manager = None
        with patch.object(transport, "_send_message") as m:
            transport._handle_forwarded_tcpip_open(0, 1024, 512, b"data")
            sent = m.call_args[0][0]
            assert isinstance(sent, ChannelOpenFailureMessage)


# ---- _build_keyboard_interactive_data ----


class TestBuildKeyboardInteractiveData:
    def test_returns_bytes(self, transport):
        data = transport._build_keyboard_interactive_data()
        assert isinstance(data, bytes)
        assert len(data) > 0


# ---- recv_message_async ----


class TestRecvMessageAsync:
    @pytest.mark.asyncio
    async def test_recv_from_queue(self, connected_transport):
        t = connected_transport
        msg = MagicMock(spec=Message)
        msg.msg_type = 1
        t._message_queue.append(msg)
        result = await t._recv_message_async(check_queue=True)
        assert result is msg
        assert len(t._message_queue) == 0

    @pytest.mark.asyncio
    async def test_recv_from_transport(self, connected_transport):
        t = connected_transport
        msg = MagicMock(spec=Message)
        msg.msg_type = 1
        # New native-async path: mock _recv_packet_async + _dispatch_packet
        with patch.object(
            t, "_recv_packet_async", new=AsyncMock(return_value=b"\x00" * 8)
        ):
            with patch.object(t, "_dispatch_packet", return_value=msg):
                result = await t._recv_message_async(check_queue=False)
        assert result is msg


# ---- pump_async ----


class TestPumpAsync:
    @pytest.mark.asyncio
    async def test_pump_queues_non_channel_message(self, connected_transport):
        t = connected_transport
        msg = MagicMock(spec=Message)
        msg.msg_type = 91  # CHANNEL_OPEN_CONFIRMATION: someone may be waiting
        with patch.object(
            t, "_recv_packet_async", new=AsyncMock(return_value=b"\x00" * 8)
        ):
            with patch.object(t, "_dispatch_packet", return_value=msg):
                await t._pump_async()
        assert msg in t._message_queue

    @pytest.mark.asyncio
    async def test_pump_drops_unawaitable_message(self, connected_transport):
        t = connected_transport
        msg = MagicMock(spec=Message)
        msg.msg_type = 3  # UNIMPLEMENTED: nothing ever waits for it
        with patch.object(
            t, "_recv_packet_async", new=AsyncMock(return_value=b"\x00" * 8)
        ):
            with patch.object(t, "_dispatch_packet", return_value=msg):
                await t._pump_async()
        assert msg not in t._message_queue

    @pytest.mark.asyncio
    async def test_pump_handled_sentinel_does_not_queue(self, connected_transport):
        t = connected_transport
        from spindlex.transport.transport import HandledMessage

        sentinel = HandledMessage()
        with patch.object(
            t, "_recv_packet_async", new=AsyncMock(return_value=b"\x00" * 8)
        ):
            with patch.object(t, "_dispatch_packet", return_value=sentinel):
                await t._pump_async()
        assert len(t._message_queue) == 0


# ---- open_channel error ----


class TestOpenChannelAsync:
    @pytest.mark.asyncio
    async def test_open_channel_exception_on_expect_cleans_up(
        self, connected_transport
    ):
        t = connected_transport
        with patch.object(t, "_send_message_async", new=AsyncMock()):
            with patch.object(
                t,
                "_expect_message_async",
                new=AsyncMock(side_effect=RuntimeError("fail")),
            ):
                with pytest.raises(RuntimeError):
                    await t.open_channel("session")
        assert len(t._channels) == 0


# ---- close edge cases ----


class TestCloseEdgeCases:
    @pytest.mark.asyncio
    async def test_close_with_sync_channel(self, connected_transport):
        t = connected_transport
        from spindlex.transport.channel import Channel

        ch = MagicMock(spec=Channel)
        t._channels[0] = ch
        await t.close()
        ch.close.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_writer_error(self, connected_transport):
        t = connected_transport
        t._writer.close.side_effect = OSError("fail")
        await t.close()  # should not raise
        assert t._active is False

    @pytest.mark.asyncio
    async def test_close_socket_error(self, connected_transport):
        t = connected_transport
        t._socket.close.side_effect = OSError("fail")
        await t.close()  # should not raise

    @pytest.mark.asyncio
    async def test_close_channel_error_ignored(self, connected_transport):
        t = connected_transport
        from spindlex.transport.async_channel import AsyncChannel

        ch = AsyncChannel(t, 0)
        ch.close = AsyncMock(side_effect=Exception("fail"))
        t._channels[0] = ch
        await t.close()  # should not raise


# ---- send_message_async NEWKEYS activates encryption ----


class TestSendMessageNewkeys:
    @pytest.mark.asyncio
    async def test_newkeys_activates_encryption(self, connected_transport):
        t = connected_transport
        msg = MagicMock(spec=Message)
        msg.msg_type = MSG_NEWKEYS
        msg.pack.return_value = b"\x15"
        with patch.object(t, "_build_packet", return_value=b"pkt"):
            with patch.object(t, "_encrypt_packet", return_value=b"enc"):
                with patch.object(t, "_activate_outbound_encryption") as m:
                    await t._send_message_async(msg)
                    m.assert_called_once()

    @pytest.mark.asyncio
    async def test_non_kex_msg_tracks_bytes(self, connected_transport):
        t = connected_transport
        t._bytes_since_rekey = 0
        msg = MagicMock(spec=Message)
        msg.msg_type = 90  # some channel message
        msg.pack.return_value = b"\x5a"
        with patch.object(t, "_build_packet", return_value=b"pkt12345"):
            with patch.object(t, "_encrypt_packet", return_value=b"enc12345"):
                with patch.object(t, "_check_rekey"):
                    await t._send_message_async(msg)
        assert t._bytes_since_rekey > 0


# ---- expect_message_async reads from transport when not in queue ----


class TestExpectMessageFromTransport:
    @pytest.mark.asyncio
    async def test_reads_and_queues_non_matching(self, connected_transport):
        t = connected_transport
        msg1 = MagicMock(spec=Message)
        msg1.msg_type = 91
        msg1.recipient_channel = None
        msg1._data = b""
        msg2 = MagicMock(spec=Message)
        msg2.msg_type = 81
        msg2.recipient_channel = None
        msg2._data = b""

        with patch.object(
            t, "_recv_packet_async", new=AsyncMock(return_value=b"\x00" * 8)
        ):
            with patch.object(t, "_dispatch_packet", side_effect=[msg1, msg2]):
                result = await t._expect_message_async(81)
        assert result is msg2
        assert msg1 in t._message_queue

    @pytest.mark.asyncio
    async def test_finds_message_queued_by_concurrent_reader(self, connected_transport):
        # A task waiting for a reply must not block on the socket behind a
        # task that is already reading; it must pick the reply up from the
        # queue once that reader has dispatched it.
        t = connected_transport
        reply = MagicMock(spec=Message)
        reply.msg_type = 91
        reply.recipient_channel = 4
        reply._data = b""

        await t._recv_lock.acquire()  # another task is reading

        async def other_reader_delivers():
            await asyncio.sleep(0.05)
            t._enqueue_message(reply)
            t._notify_packet_dispatched()

        deliver = asyncio.create_task(other_reader_delivers())
        try:
            result = await asyncio.wait_for(
                t._expect_message_async(91, channel_id=4), timeout=2
            )
        finally:
            t._recv_lock.release()
            await deliver
        assert result is reply
