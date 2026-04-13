"""
Async SSH Transport Layer Implementation

Provides asynchronous SSH transport functionality for high-concurrency applications.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .async_forwarding import AsyncPortForwardingManager

from ..exceptions import ProtocolException, TransportException
from ..protocol.constants import *
from ..protocol.messages import *
from ..protocol.utils import *
from .transport import Transport


class AsyncTransport(Transport):
    """
    Async SSH transport layer implementation.

    This implementation bridges the synchronous Transport logic with
    asyncio by overriding the low-level I/O methods.
    """

    def __init__(
        self,
        sock: socket.socket,
        rekey_bytes_limit: int | None = None,
        rekey_time_limit: int | None = None,
    ) -> None:
        super().__init__(
            sock,
            rekey_bytes_limit=rekey_bytes_limit,
            rekey_time_limit=rekey_time_limit,
        )
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._port_forwarding_manager: AsyncPortForwardingManager | None = None  # type: ignore[assignment]
        try:
            self._loop = asyncio.get_event_loop()
        except RuntimeError:
            self._loop = None

        # Locks for async safety
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()

    async def connect_existing(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Initialize with existing asyncio streams."""
        async with self._state_lock:
            self._reader = reader
            self._writer = writer

    async def start_client(self, timeout: float | None = None) -> None:  # type: ignore[override]
        if timeout is not None:
            self._connect_timeout = timeout

        async with self._state_lock:
            if self._active:
                raise TransportException("Transport already active")
            self._server_mode = False

        try:
            # Handshake
            if self._server_mode:
                await self._send_version_async()
                await self._recv_version_async()
            else:
                await self._recv_version_async()
                await self._send_version_async()

            # Key Exchange
            await self._start_kex_async()

            async with self._state_lock:
                self._active = True

        except Exception as e:
            await self.close()
            if isinstance(e, (TransportException, ProtocolException)):
                raise
            raise TransportException(f"Client start failed: {e}") from e

    async def _start_kex_async(self) -> None:
        """Performs KEX by bridging sync KEX logic into a thread."""
        async with self._state_lock:
            if self._kex_in_progress:
                raise TransportException("Key exchange already in progress")
            self._kex_in_progress = True

        try:
            # We run the entire KEX initiation in a thread to avoid deadlocking the loop
            # with sync-to-async bridge calls (.result() calls).
            await asyncio.to_thread(self._run_kex_threadsafe)
        except Exception:
            async with self._state_lock:
                self._kex_in_progress = False
            raise

    def _run_kex_threadsafe(self) -> None:
        """Thread-safe KEX execution bridging."""
        # This runs in a separate thread, safe to block on .result()
        self._send_kexinit()
        self._recv_kexinit()
        self._kex.start_kex()

        # Reset progress flag
        self._kex_in_progress = False

    def get_port_forwarding_manager(self) -> AsyncPortForwardingManager:  # type: ignore[override]
        """Get port forwarding manager."""
        if self._port_forwarding_manager is None:
            from .async_forwarding import AsyncPortForwardingManager

            self._port_forwarding_manager = AsyncPortForwardingManager(self)

        return self._port_forwarding_manager

    # --- Bridge Methods for Sync Logic ---

    def _send_message(self, message: Message) -> None:
        """Bridge sync calls to async send."""
        if not self._loop or not self._loop.is_running():
            return super()._send_message(message)

        # Use run_coroutine_threadsafe to schedule and wait for the result
        # This ensures we have backpressure and catch exceptions.
        # This must be called from a thread OTHER than the event loop thread.
        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._send_message_async(message), self._loop
            )
            fut.result()
        except Exception as e:
            if isinstance(e, TransportException):
                raise
            raise TransportException(
                f"Failed to send message via async bridge: {e}"
            ) from e

    def _recv_message(self, allowed_types: list[int] | None = None) -> Message:
        """Bridge sync calls to async recv."""
        if not self._loop:
            return super()._recv_message()

        try:
            asyncio.get_running_loop()
            raise TransportException("Synchronous receive called on event loop thread")
        except RuntimeError:
            # For debugging the 'bytes' error
            # print(f"DEBUG: _recv_message from thread. Queue type: {type(self._message_queue)}")
            if not self._loop:
                raise TransportException("Event loop not available")
            fut = asyncio.run_coroutine_threadsafe(
                self._recv_message_async(), self._loop
            )
            return fut.result()

    def _expect_message(self, *allowed_types: int) -> Message:
        """Bridge sync expect_message."""
        if not self._loop:
            return super()._expect_message(*allowed_types)

        try:
            asyncio.get_running_loop()
            raise TransportException(
                "Synchronous expect_message called on event loop thread"
            )
        except RuntimeError:
            if not self._loop:
                raise TransportException("Event loop not available")
            fut = asyncio.run_coroutine_threadsafe(
                self._expect_message_async(*allowed_types), self._loop
            )
            return fut.result()

    # --- Async Implementation of Packet I/O ---

    def _recv_bytes(self, length: int) -> bytes:
        """Bridge sync recv_bytes to async reader."""
        if not self._reader or not self._loop:
            raise TransportException("Transport not initialized with async streams")

        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._reader.readexactly(length), self._loop
            )
            return fut.result()
        except Exception as e:
            print(
                f"DEBUG: AsyncTransport._recv_bytes({length}) failed: {e} ({type(e)})"
            )
            raise

    async def _send_message_async(self, message: Message) -> None:
        """Async version of _send_message."""
        async with self._send_lock:
            payload = message.pack()
            packet = self._build_packet(payload)
            packet = self._encrypt_packet(packet)

            if not self._writer:
                raise TransportException("Transport not initialized with async streams")

            self._writer.write(packet)
            await self._writer.drain()

            # Track bytes sent for rekeying
            if message.msg_type not in [
                MSG_KEXINIT,
                MSG_NEWKEYS,
            ] and not (MSG_KEXDH_INIT <= message.msg_type <= MSG_KEXDH_REPLY):
                self._bytes_since_rekey += len(packet)
                self._check_rekey()

            # If this was a NEWKEYS message, activate encryption AFTER sending it
            if message.msg_type == MSG_NEWKEYS:
                self._activate_outbound_encryption()

            self._sequence_number_out = (self._sequence_number_out + 1) & 0xFFFFFFFF

    async def _recv_message_async(self, check_queue: bool = True) -> Message:
        """Async version of _recv_message."""
        if check_queue:
            async with self._state_lock:
                if self._message_queue:
                    return self._message_queue.pop(0)

        async with self._recv_lock:
            # We call the base _read_message which calls our overridden _recv_bytes
            # to handle the actual reading from the asyncio reader.
            # Base _read_message also handles dispatching to channels.
            msg = await asyncio.to_thread(super()._read_message)
            return msg

    async def _pump_async(self) -> None:
        """
        Pump the transport once to read and dispatch a message.
        Used by channels to wait for data/window adjustments.
        """
        # We call with check_queue=False because we want to actually read from
        # the socket to trigger dispatcher logic for data packets.
        msg = await self._recv_message_async(check_queue=False)

        # Always queue the message so it can be picked up by _expect_message_async
        # even if it was already dispatched by _read_message.
        async with self._state_lock:
            self._message_queue.append(msg)

    async def _expect_message_async(
        self, *allowed_types: int, channel_id: int | None = None
    ) -> Message:
        """Async version of expect_message."""
        while True:
            # 1. Check queue
            async with self._state_lock:
                for i, msg in enumerate(self._message_queue):
                    if msg.msg_type in allowed_types:
                        # If channel_id is specified, check if it matches
                        if channel_id is not None:
                            msg_channel_id = getattr(msg, "recipient_channel", None)
                            if msg_channel_id is None and len(msg._data) >= 4:
                                msg_channel_id = struct.unpack(">I", msg._data[:4])[0]

                            if msg_channel_id != channel_id:
                                continue

                        return self._message_queue.pop(i)

            # 2. Read next
            msg = await self._recv_message_async(check_queue=False)
            if msg.msg_type in allowed_types:
                # If channel_id is specified, check if it matches
                if channel_id is not None:
                    msg_channel_id = getattr(msg, "recipient_channel", None)
                    if msg_channel_id is None and len(msg._data) >= 4:
                        msg_channel_id = struct.unpack(">I", msg._data[:4])[0]

                    if msg_channel_id == channel_id:
                        return msg
                else:
                    return msg

            # 3. Queue it
            async with self._state_lock:
                self._message_queue.append(msg)

    # --- Handshake Helpers ---

    async def _send_version_async(self) -> None:
        version_string = create_version_string()
        self._client_version = version_string
        if not self._writer:
            raise TransportException("Transport not initialized with async streams")
        self._writer.write((version_string + "\r\n").encode(SSH_STRING_ENCODING))
        await self._writer.drain()

    async def _recv_version_async(self) -> None:
        if not self._reader:
            raise TransportException("Transport not initialized with async streams")
        while True:
            line = await self._reader.readline()
            if not line:
                raise TransportException("Connection closed")
            line = line.strip()
            if line.startswith(b"SSH-"):
                self._server_version = line.decode(SSH_STRING_ENCODING)
                break

    async def _send_kexinit_async(self) -> None:
        self._send_kexinit()

    async def _recv_kexinit_async(self) -> None:
        msg = await self._recv_message_async()
        if not isinstance(msg, KexInitMessage):
            raise ProtocolException("Expected KEXINIT")
        self._peer_kexinit = msg

    # --- Common Async Methods ---

    async def auth_password(self, username: str, password: str) -> bool:  # type: ignore[override]
        if not self._userauth_service_requested:
            await self._send_message_async(ServiceRequestMessage(SERVICE_USERAUTH))
            await self._expect_message_async(MSG_SERVICE_ACCEPT)
            self._userauth_service_requested = True

        auth_msg = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PASSWORD,
            method_data=self._build_password_auth_data(password),
        )
        await self._send_message_async(auth_msg)
        res = await self._expect_message_async(
            MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE
        )
        if isinstance(res, UserAuthSuccessMessage):
            self._authenticated = True
            return True
        return False

    async def auth_publickey(self, username: str, key: Any) -> bool:  # type: ignore[override]
        """Authenticate using public key method asynchronously."""
        if not self._userauth_service_requested:
            await self._send_message_async(ServiceRequestMessage(SERVICE_USERAUTH))
            await self._expect_message_async(MSG_SERVICE_ACCEPT)
            self._userauth_service_requested = True

        # 1. Query if key is acceptable
        query_msg = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PUBLICKEY,
            method_data=self._build_publickey_query_data(key),
        )
        await self._send_message_async(query_msg)
        res = await self._expect_message_async(MSG_USERAUTH_FAILURE, MSG_USERAUTH_PK_OK)

        if isinstance(res, UserAuthFailureMessage):
            return False

        # 2. Key accepted, send signature
        auth_msg = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_PUBLICKEY,
            method_data=self._build_publickey_auth_data(username, key),
        )
        await self._send_message_async(auth_msg)
        res = await self._expect_message_async(
            MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE
        )

        if isinstance(res, UserAuthSuccessMessage):
            self._authenticated = True
            return True
        return False

    async def auth_gssapi(  # type: ignore[override]
        self,
        username: str,
        gss_host: str | None = None,
        gss_deleg_creds: bool = False,
    ) -> bool:
        """Authenticate using GSSAPI method asynchronously."""
        if not self._userauth_service_requested:
            await self._send_message_async(ServiceRequestMessage(SERVICE_USERAUTH))
            await self._expect_message_async(MSG_SERVICE_ACCEPT)
            self._userauth_service_requested = True

        from ..auth.gssapi import GSSAPIAuth

        gssapi_auth = GSSAPIAuth(self)

        try:
            # Note: The GSSAPI exchange uses internal bridge calls (_send_message, _recv_message)
            # which we've already bridged to async. However, for a fully async experience
            # we should really have an AsyncGSSAPIAuth. For now, since it runs in it's own
            # logic flow, we use to_thread to keep the loop free.
            result = await asyncio.to_thread(
                gssapi_auth.authenticate, username, gss_host, gss_deleg_creds
            )
            if result:
                self._authenticated = True
            return result
        finally:
            gssapi_auth.cleanup()

    async def auth_keyboard_interactive(  # type: ignore[override]
        self, username: str, handler: Any
    ) -> bool:
        """Authenticate using keyboard-interactive method asynchronously."""
        if not self._userauth_service_requested:
            await self._send_message_async(ServiceRequestMessage(SERVICE_USERAUTH))
            await self._expect_message_async(MSG_SERVICE_ACCEPT)
            self._userauth_service_requested = True

        from ..auth.keyboard_interactive import AsyncKeyboardInteractiveAuth

        # Send initial keyboard-interactive request
        auth_request = UserAuthRequestMessage(
            username=username,
            service=SERVICE_CONNECTION,
            method=AUTH_KEYBOARD_INTERACTIVE,
            method_data=self._build_keyboard_interactive_data(),
        )
        await self._send_message_async(auth_request)

        # Perform interactive authentication
        ki_auth = AsyncKeyboardInteractiveAuth(self)
        result = await ki_auth.authenticate_async(username, handler)

        if result:
            self._authenticated = True
        return result

    async def _send_global_request_async(
        self, request_name: str, want_reply: bool, request_data: bytes = b""
    ) -> Message | None:
        """Send global request asynchronously."""
        msg = GlobalRequestMessage(request_name, want_reply, request_data)
        await self._send_message_async(msg)

        if want_reply:
            return await self._expect_message_async(
                MSG_REQUEST_SUCCESS, MSG_REQUEST_FAILURE
            )
        return None

    def _handle_forwarded_tcpip_open(
        self,
        sender_channel: int,
        initial_window_size: int,
        maximum_packet_size: int,
        type_specific_data: bytes,
    ) -> None:
        """Bridge sync forwarded-tcpip open to async manager."""
        if self._port_forwarding_manager:
            # We must schedule this in the event loop as it involves async operations
            asyncio.run_coroutine_threadsafe(
                self._port_forwarding_manager.handle_forwarded_connection_async(
                    sender_channel,
                    initial_window_size,
                    maximum_packet_size,
                    type_specific_data,
                ),
                self._loop,  # type: ignore
            )
        else:
            # No manager, reject the channel
            failure_msg = ChannelOpenFailureMessage(
                recipient_channel=sender_channel,
                reason_code=SSH_OPEN_CONNECT_FAILED,
                description="Port forwarding not enabled",
                language="",
            )
            self._send_message(failure_msg)

    def _build_keyboard_interactive_data(self) -> bytes:
        """Build keyboard-interactive authentication method data."""
        data = bytearray()
        data.extend(write_string(""))  # language tag
        data.extend(write_string(""))  # submethods
        return bytes(data)

    async def open_channel(self, kind: str, dest_addr: tuple | None = None) -> Any:  # type: ignore[override]
        async with self._state_lock:
            cid = self._next_channel_id
            self._next_channel_id += 1

        from .async_channel import AsyncChannel

        chan = AsyncChannel(self, cid)

        async with self._state_lock:
            self._channels[cid] = chan

        # Build open message
        msg = ChannelOpenMessage(
            channel_type=kind,
            sender_channel=cid,
            initial_window_size=DEFAULT_WINDOW_SIZE,
            maximum_packet_size=DEFAULT_MAX_PACKET_SIZE,
        )
        await self._send_message_async(msg)

        # Wait for confirmation
        try:
            res = await self._expect_message_async(
                MSG_CHANNEL_OPEN_CONFIRMATION, MSG_CHANNEL_OPEN_FAILURE, channel_id=cid
            )
        except Exception:
            async with self._state_lock:
                if cid in self._channels:
                    del self._channels[cid]
            raise

        if isinstance(res, ChannelOpenConfirmationMessage):
            chan._remote_channel_id = res.sender_channel
            chan._remote_window_size = res.initial_window_size
            chan._remote_max_packet_size = res.maximum_packet_size
            return chan

        async with self._state_lock:
            if cid in self._channels:
                del self._channels[cid]
        raise TransportException("Failed to open channel")

    async def _send_channel_request_async(
        self, channel_id: int, request_type: str, want_reply: bool, data: bytes
    ) -> None:
        """Send channel request message asynchronously."""
        remote_id = self._channels[channel_id]._remote_channel_id
        if remote_id is None:
            raise TransportException(f"Channel {channel_id} remote ID not set")

        msg = ChannelRequestMessage(
            recipient_channel=remote_id,
            request_type=request_type,
            want_reply=want_reply,
            request_data=data,
        )
        await self._send_message_async(msg)

    async def _send_channel_data_async(self, channel_id: int, data: bytes) -> None:
        """Send channel data message asynchronously."""
        remote_id = self._channels[channel_id]._remote_channel_id
        if remote_id is None:
            raise TransportException(f"Channel {channel_id} remote ID not set")

        msg = ChannelDataMessage(recipient_channel=remote_id, data=data)
        await self._send_message_async(msg)

    async def _send_channel_eof_async(self, channel_id: int) -> None:
        """Send channel EOF message asynchronously."""
        remote_id = self._channels[channel_id]._remote_channel_id
        if remote_id is None:
            return

        msg = ChannelEOFMessage(recipient_channel=remote_id)
        await self._send_message_async(msg)

    async def _send_channel_close_async(self, channel_id: int) -> None:
        """Send channel close message asynchronously."""
        remote_id = self._channels[channel_id]._remote_channel_id
        if remote_id is None:
            return

        msg = ChannelCloseMessage(recipient_channel=remote_id)
        await self._send_message_async(msg)

    async def _send_channel_window_adjust_async(
        self, channel_id: int, bytes_to_add: int
    ) -> None:
        """Send channel window adjust message asynchronously."""
        remote_id = self._channels[channel_id]._remote_channel_id
        if remote_id is None:
            return

        msg = ChannelWindowAdjustMessage(
            recipient_channel=remote_id,
            bytes_to_add=bytes_to_add,
        )
        await self._send_message_async(msg)

    async def close(self) -> None:  # type: ignore[override]
        async with self._state_lock:
            self._active = False
            if self._writer:
                try:
                    self._writer.close()
                    await self._writer.wait_closed()
                except Exception:
                    pass
                self._writer = None
            self._reader = None
            if self._socket:
                try:
                    self._socket.close()
                except Exception:
                    pass
            for c in list(self._channels.values()):
                try:
                    from .async_channel import AsyncChannel

                    if isinstance(c, AsyncChannel):
                        await c.close()
                    else:
                        c.close()
                except Exception:
                    pass
            self._channels.clear()
