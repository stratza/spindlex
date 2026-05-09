"""
Unit tests for spindlex/transport/async_transport.py
"""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from spindlex.exceptions import TransportException
from spindlex.protocol.messages import Message
from spindlex.transport.async_transport import AsyncTransport


class TestAsyncTransportUnit:
    @pytest.fixture
    def mock_socket(self):
        sock = MagicMock(spec=socket.socket)
        sock.fileno.return_value = 1
        return sock

    @pytest.fixture
    def transport(self, mock_socket):
        return AsyncTransport(mock_socket)

    def test_init(self, transport, mock_socket):
        assert transport._socket is mock_socket
        assert transport._is_async is True
        assert transport._reader is None
        assert transport._writer is None
        assert transport._loop is None

    @pytest.mark.asyncio
    async def test_connect_existing(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)

        await transport.connect_existing(mock_reader, mock_writer)

        assert transport._reader is mock_reader
        assert transport._writer is mock_writer
        assert transport._loop is not None

    @pytest.mark.asyncio
    async def test_start_client_already_active_raises(self, transport):
        transport._active = True
        with pytest.raises(TransportException, match="Transport already active"):
            await transport.start_client()

    @pytest.mark.asyncio
    async def test_start_client_failure_closes_transport(self, transport):
        with patch.object(
            transport, "_send_version_async", side_effect=RuntimeError("fail")
        ):
            with patch.object(transport, "close", new=AsyncMock()) as mock_close:
                with pytest.raises(TransportException, match="Client start failed"):
                    await transport.start_client()
                mock_close.assert_awaited_once()

    def test_get_port_forwarding_manager(self, transport):
        with patch(
            "spindlex.transport.async_forwarding.AsyncPortForwardingManager"
        ) as mock_manager_cls:
            manager = transport.get_port_forwarding_manager()
            assert manager == mock_manager_cls.return_value
            # Second call should return the same instance
            assert transport.get_port_forwarding_manager() == manager

    @pytest.mark.asyncio
    async def test_send_message_async_no_writer_raises(self, transport):
        msg = MagicMock(spec=Message)
        with pytest.raises(TransportException, match="Transport not initialized"):
            await transport._send_message_async(msg)

    @pytest.mark.asyncio
    async def test_recv_bytes_no_reader_raises(self, transport):
        with pytest.raises(TransportException, match="Transport not initialized"):
            transport._recv_bytes(10)

    @pytest.mark.asyncio
    async def test_send_version_async_no_writer_raises(self, transport):
        with pytest.raises(TransportException, match="Transport not initialized"):
            await transport._send_version_async()

    @pytest.mark.asyncio
    async def test_recv_version_async_no_reader_raises(self, transport):
        with pytest.raises(TransportException, match="Transport not initialized"):
            await transport.recv_version_async() if hasattr(
                transport, "recv_version_async"
            ) else await transport._recv_version_async()

    @pytest.mark.asyncio
    async def test_send_message_bridge_from_other_thread(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)

        msg = MagicMock(spec=Message)
        msg.pack.return_value = b"payload"

        with patch.object(
            transport, "_send_message_async", new=AsyncMock()
        ) as mock_send:
            # Simulate calling from a thread
            def run_in_thread():
                transport._send_message(msg)

            await asyncio.to_thread(run_in_thread)
            mock_send.assert_awaited_once_with(msg)

    @pytest.mark.asyncio
    async def test_recv_message_bridge_from_other_thread(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)

        msg = MagicMock(spec=Message)

        with patch.object(
            transport, "_recv_message_async", new=AsyncMock(return_value=msg)
        ):

            def run_in_thread():
                return transport._recv_message()

            result = await asyncio.to_thread(run_in_thread)
            assert result is msg

    @pytest.mark.asyncio
    async def test_expect_message_bridge_from_other_thread(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)

        msg = MagicMock(spec=Message)

        with patch.object(
            transport, "_expect_message_async", new=AsyncMock(return_value=msg)
        ):

            def run_in_thread():
                return transport._expect_message(1, 2, channel_id=5)

            result = await asyncio.to_thread(run_in_thread)
            assert result is msg

    @pytest.mark.asyncio
    async def test_send_message_async_success(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)

        msg = MagicMock(spec=Message)
        msg.msg_type = 20  # MSG_KEXINIT
        msg.pack.return_value = b"payload"

        with patch.object(transport, "_build_packet", return_value=b"packet"):
            with patch.object(transport, "_encrypt_packet", return_value=b"encrypted"):
                await transport._send_message_async(msg)
                mock_writer.write.assert_called_with(b"encrypted")
                mock_writer.drain.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_expect_message_async_queue_logic(self, transport):
        msg1 = MagicMock(spec=Message)
        msg1.msg_type = 1
        msg2 = MagicMock(spec=Message)
        msg2.msg_type = 2

        transport._message_queue.append(msg1)
        transport._message_queue.append(msg2)

        # Should pick from queue
        result = await transport._expect_message_async(2)
        assert result is msg2
        assert len(transport._message_queue) == 1
        assert transport._message_queue[0] is msg1

    @pytest.mark.asyncio
    async def test_expect_message_async_channel_id_filtering(self, transport):
        import struct

        msg1 = MagicMock(spec=Message)
        msg1.msg_type = 91  # MSG_CHANNEL_OPEN_CONFIRMATION
        msg1._data = struct.pack(">I", 10)  # remote channel id
        msg1.recipient_channel = 10

        msg2 = MagicMock(spec=Message)
        msg2.msg_type = 91
        msg2._data = struct.pack(">I", 20)
        msg2.recipient_channel = 20

        transport._message_queue.append(msg1)
        transport._message_queue.append(msg2)

        result = await transport._expect_message_async(91, channel_id=20)
        assert result is msg2
        assert len(transport._message_queue) == 1
        assert transport._message_queue[0] is msg1

    @pytest.mark.asyncio
    async def test_auth_password_success(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)
        transport._userauth_service_requested = True

        with patch("spindlex.auth.password.PasswordAuth") as mock_auth_cls:
            mock_auth = mock_auth_cls.return_value
            mock_auth.authenticate_async = AsyncMock(
                return_value=MagicMock(msg_type=52)
            )  # MSG_USERAUTH_SUCCESS

            with patch.object(
                transport, "_handle_auth_response_message", return_value=True
            ):
                result = await transport.auth_password("user", "pass")
                assert result is True
                mock_auth.authenticate_async.assert_awaited_once_with("user", "pass")

    @pytest.mark.asyncio
    async def test_auth_publickey_success(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)
        transport._userauth_service_requested = True

        pkey = MagicMock()
        with patch("spindlex.auth.publickey.PublicKeyAuth") as mock_auth_cls:
            mock_auth = mock_auth_cls.return_value
            mock_auth.authenticate_async = AsyncMock(
                return_value=MagicMock(msg_type=52)
            )

            with patch.object(
                transport, "_handle_auth_response_message", return_value=True
            ):
                result = await transport.auth_publickey("user", pkey)
                assert result is True
                mock_auth.authenticate_async.assert_awaited_once_with("user", pkey)

    @pytest.mark.asyncio
    async def test_open_channel_success(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)

        from spindlex.protocol.messages import ChannelOpenConfirmationMessage

        conf = MagicMock(spec=ChannelOpenConfirmationMessage)
        conf.msg_type = 91
        conf.sender_channel = 100
        conf.initial_window_size = 1024
        conf.maximum_packet_size = 512

        with patch.object(transport, "_send_message_async", new=AsyncMock()):
            with patch.object(
                transport, "_expect_message_async", new=AsyncMock(return_value=conf)
            ):
                channel = await transport.open_channel("session")
                assert channel is not None
                assert channel._remote_channel_id == 100
                assert transport._channels[channel._channel_id] is channel

    @pytest.mark.asyncio
    async def test_open_channel_failure(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)

        from spindlex.protocol.messages import ChannelOpenFailureMessage

        fail = MagicMock(spec=ChannelOpenFailureMessage)
        fail.msg_type = 92

        with patch.object(transport, "_send_message_async", new=AsyncMock()):
            with patch.object(
                transport, "_expect_message_async", new=AsyncMock(return_value=fail)
            ):
                with pytest.raises(TransportException, match="Failed to open channel"):
                    await transport.open_channel("session")

    @pytest.mark.asyncio
    async def test_close_success(self, transport):
        mock_reader = MagicMock(spec=asyncio.StreamReader)
        mock_writer = MagicMock(spec=asyncio.StreamWriter)
        await transport.connect_existing(mock_reader, mock_writer)

        from spindlex.transport.async_channel import AsyncChannel

        # Use a real AsyncChannel but with mocked transport methods
        chan = AsyncChannel(transport, 1)
        chan.close = AsyncMock()
        transport._channels[1] = chan

        await transport.close()

        assert transport._active is False
        assert len(transport._channels) == 0
        chan.close.assert_awaited_once()
        mock_writer.close.assert_called_once()
        mock_writer.wait_closed.assert_awaited_once()
