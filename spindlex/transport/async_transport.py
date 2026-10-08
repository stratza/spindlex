"""
Async SSH Transport Layer Implementation

Provides asynchronous SSH transport functionality for high-concurrency applications.
"""

from __future__ import annotations

import asyncio
import hmac
import socket
import struct
import threading
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from .async_forwarding import AsyncPortForwardingManager

from ..exceptions import ProtocolException, SSHException, TransportException
from ..protocol.constants import (
    AUTH_KEYBOARD_INTERACTIVE,
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_WINDOW_SIZE,
    MAX_CHANNELS,
    MAX_PACKET_SIZE,
    MIN_PACKET_SIZE,
    MSG_CHANNEL_OPEN_CONFIRMATION,
    MSG_CHANNEL_OPEN_FAILURE,
    MSG_KEXDH_INIT,
    MSG_KEXDH_REPLY,
    MSG_KEXINIT,
    MSG_NEWKEYS,
    MSG_REQUEST_FAILURE,
    MSG_REQUEST_SUCCESS,
    MSG_SERVICE_ACCEPT,
    PACKET_LENGTH_SIZE,
    SERVICE_CONNECTION,
    SERVICE_USERAUTH,
    SSH_OPEN_CONNECT_FAILED,
    SSH_STRING_ENCODING,
    create_version_string,
)
from ..protocol.messages import (
    ChannelCloseMessage,
    ChannelDataMessage,
    ChannelEOFMessage,
    ChannelOpenConfirmationMessage,
    ChannelOpenFailureMessage,
    ChannelOpenMessage,
    ChannelRequestMessage,
    ChannelWindowAdjustMessage,
    GlobalRequestMessage,
    KexInitMessage,
    Message,
    ServiceRequestMessage,
    UserAuthRequestMessage,
)
from ..protocol.utils import write_string
from .transport import Transport

# Only drain the asyncio write buffer when it exceeds this threshold.
# This avoids a per-packet event-loop yield while still providing backpressure.
_DRAIN_THRESHOLD = 65536  # 64 KB


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

        # Locks for async safety
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()
        self._is_async = True
        # Set (and replaced) each time a packet has been dispatched, so tasks
        # that find another task reading the socket can wait for it to deliver
        # instead of queueing behind it. Created lazily on the event loop.
        self._packet_event: asyncio.Event | None = None

    async def connect_existing(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Initialize with existing asyncio streams."""
        self._loop = asyncio.get_running_loop()
        async with self._state_lock:
            self._reader = reader
            self._writer = writer

    async def start_client(self, timeout: float | None = None) -> None:  # type: ignore[override]
        self._loop = asyncio.get_running_loop()
        if timeout is not None:
            self._connect_timeout = timeout

        async with self._state_lock:
            if self._active:
                raise TransportException("Transport already active")
            self._server_mode = False

        try:
            # Handshake: send our version first, then receive peer's (RFC 4253 §4.2)
            await self._send_version_async()
            await self._recv_version_async()

            # Key Exchange
            await self._start_kex_async()

            async with self._state_lock:
                self._active = True

        except Exception as e:
            await self.close()
            if isinstance(e, SSHException):
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
        # Record thread so _read_message receives packets
        self._kex_thread = threading.current_thread()
        try:
            # This runs in a separate thread, safe to block on .result()
            self._send_kexinit()
            self._recv_kexinit()
            self._kex.start_kex()
        finally:
            self._kex_thread = None
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

        try:
            running_loop: asyncio.AbstractEventLoop | None = asyncio.get_running_loop()
        except RuntimeError:
            running_loop = None
        if running_loop is self._loop:
            # Called synchronously on the event loop thread - typically a
            # handler inside _dispatch_packet replying to the peer (keepalive
            # global requests, channel requests, channel close). Waiting for
            # the result here would block the loop that has to run the send,
            # so schedule it instead; _send_lock keeps sends in order.
            task = self._loop.create_task(self._send_message_async(message))
            task.add_done_callback(self._log_scheduled_send_failure)
            return

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

    def _log_scheduled_send_failure(self, task: asyncio.Task) -> None:
        if task.cancelled():
            return
        exc = task.exception()
        if exc is not None:
            self._logger.debug(f"Scheduled send failed: {exc}")

    def _recv_message(self, allowed_types: list[int] | None = None) -> Message:
        """Bridge sync calls to async recv."""
        if not self._loop:
            return super()._recv_message()

        try:
            asyncio.get_running_loop()
            raise TransportException("Synchronous receive called on event loop thread")
        except RuntimeError:
            # For debugging the 'bytes' error
            fut = asyncio.run_coroutine_threadsafe(
                self._wait_for_message_async(None, None, self._is_kex_caller()),
                self._loop,
            )
            return fut.result()

    def _expect_message(
        self, *allowed_types: int, channel_id: Optional[int] = None
    ) -> Message:
        """Bridge sync expect_message."""
        if not self._loop:
            return super()._expect_message(*allowed_types, channel_id=channel_id)

        try:
            asyncio.get_running_loop()
            raise TransportException(
                "Synchronous expect_message called on event loop thread"
            )
        except RuntimeError:
            if not self._loop:
                raise TransportException("Event loop not available")
            fut = asyncio.run_coroutine_threadsafe(
                self._wait_for_message_async(
                    tuple(allowed_types), channel_id, self._is_kex_caller()
                ),
                self._loop,
            )
            return fut.result()

    # --- Async Implementation of Packet I/O ---

    def _recv_bytes(self, length: int, mid_packet: bool = False) -> bytes:
        """Bridge sync recv_bytes to async reader."""
        if not self._reader or not self._loop:
            raise TransportException("Transport not initialized with async streams")

        try:
            fut = asyncio.run_coroutine_threadsafe(
                self._reader.readexactly(length), self._loop
            )
            return fut.result()
        except Exception:
            raise

    async def _send_message_async(self, message: Message) -> None:
        """Async version of _send_message."""
        async with self._send_lock:
            if not self._writer:
                raise TransportException("Transport not initialized with async streams")

            payload = message.pack()
            packet = self._build_packet(payload)
            packet = self._encrypt_packet(packet)

            self._writer.write(packet)
            # Only drain when the write buffer is large; avoids a per-packet
            # event-loop yield that kills throughput on pipelined SFTP transfers.
            try:
                if self._writer.transport.get_write_buffer_size() > _DRAIN_THRESHOLD:
                    await self._writer.drain()
            except (AttributeError, TypeError):
                pass  # Buffer size unavailable; no drain needed (e.g. test mocks).

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

            # Strict-KEX (Terrapin defense, RFC): after sending NEWKEYS,
            # reset outbound sequence to 0 so the next packet uses nonce 0.
            if message.msg_type == MSG_NEWKEYS and self._strict_kex:
                self._sequence_number_out = 0
                self._logger.debug("Sequence number (out) reset for strict KEX")

    async def _recv_packet_async(self) -> bytes:
        """
        Read one complete SSH packet directly from the asyncio StreamReader.

        This is the hot-path replacement for the thread-bridge that previously
        called asyncio.to_thread(super()._read_message), eliminating two context
        switches (event-loop → thread → event-loop) per received packet.
        """
        if not self._reader:
            raise TransportException("Transport not initialised with async streams")

        try:
            if (
                getattr(self, "_cipher_in_active", None)
                == "chacha20-poly1305@openssh.com"
            ):
                enc_length = await self._reader.readexactly(PACKET_LENGTH_SIZE)
                assert self._chacha20_key_in is not None
                plain_length = self._crypto_backend.chacha20_poly1305_decrypt_length(
                    self._chacha20_key_in, self._sequence_number_in, enc_length
                )
                packet_length = struct.unpack(">I", plain_length)[0]
                if packet_length < 8 or packet_length > MAX_PACKET_SIZE:
                    raise ProtocolException(f"Invalid packet length: {packet_length}")
                enc_body = await self._reader.readexactly(packet_length)
                tag = await self._reader.readexactly(16)
                plain_body = self._crypto_backend.chacha20_poly1305_decrypt_body(
                    self._chacha20_key_in,
                    self._sequence_number_in,
                    enc_length,
                    enc_body,
                    tag,
                )
                return bytes(plain_length + plain_body)

            if self._decryptor_instance:
                # Read the encrypted packet-length field
                enc_len = await self._reader.readexactly(PACKET_LENGTH_SIZE)
                length_data = self._decryptor_instance.update(enc_len)
                packet_length = struct.unpack(">I", length_data)[0]

                if (
                    packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE
                    or packet_length > MAX_PACKET_SIZE
                ):
                    raise ProtocolException(f"Invalid packet length: {packet_length}")

                enc_payload = await self._reader.readexactly(packet_length)
                packet_payload = self._decryptor_instance.update(enc_payload)

                if self._mac_in_active and self._mac_key_in_active:
                    mac_info = self._kex._cipher_suite.get_mac_info(self._mac_in_active)
                    mac_len = mac_info["digest_len"]
                    received_mac = await self._reader.readexactly(mac_len)
                    mac_data = (
                        struct.pack(">I", self._sequence_number_in & 0xFFFFFFFF)
                        + length_data
                        + packet_payload
                    )
                    expected_mac = self._crypto_backend.compute_mac(
                        self._mac_in_active, self._mac_key_in_active, mac_data
                    )
                    if not hmac.compare_digest(received_mac, expected_mac):
                        raise TransportException("MAC verification failed")

                return bytes(length_data + packet_payload)

            # Unencrypted path
            length_data = await self._reader.readexactly(PACKET_LENGTH_SIZE)
            packet_length = struct.unpack(">I", length_data)[0]

            if packet_length < MIN_PACKET_SIZE - PACKET_LENGTH_SIZE:
                raise ProtocolException(f"Invalid packet length: {packet_length}")
            if packet_length > MAX_PACKET_SIZE - PACKET_LENGTH_SIZE:
                raise ProtocolException(f"Packet too large: {packet_length}")

            packet_data = await self._reader.readexactly(packet_length)

            if self._mac_in_active and self._mac_key_in_active:
                mac_info = self._kex._cipher_suite.get_mac_info(self._mac_in_active)
                mac_len = mac_info["digest_len"]
                received_mac = await self._reader.readexactly(mac_len)
                mac_data = (
                    struct.pack(">I", self._sequence_number_in & 0xFFFFFFFF)
                    + length_data
                    + packet_data
                )
                expected_mac = self._crypto_backend.compute_mac(
                    self._mac_in_active, self._mac_key_in_active, mac_data
                )
                if not hmac.compare_digest(received_mac, expected_mac):
                    raise TransportException("MAC verification failed")

            return bytes(length_data + packet_data)

        except asyncio.IncompleteReadError as e:
            if not self._active:
                raise TransportException("Transport closed")
            raise TransportException(
                f"Connection closed while reading packet: {e}"
            ) from e

    def _is_kex_caller(self) -> bool:
        """Whether the calling thread is the one driving a key exchange."""
        return self._kex_thread is not None and (
            threading.current_thread() is self._kex_thread
        )

    def _notify_packet_dispatched(self) -> None:
        event = self._packet_event
        self._packet_event = None
        if event is not None:
            event.set()

    async def _wait_for_other_reader(self) -> None:
        """Wait (briefly) for the task currently reading to dispatch a packet."""
        if self._packet_event is None:
            self._packet_event = asyncio.Event()
        try:
            await asyncio.wait_for(self._packet_event.wait(), timeout=0.1)
        except asyncio.TimeoutError:
            pass

    async def _recv_message_async(self, check_queue: bool = True) -> Message:
        """Async version of _recv_message - reads natively from StreamReader."""
        if not check_queue:
            # Legacy entry point: read straight from the socket.
            async with self._recv_lock:
                while True:
                    packet = await self._recv_packet_async()
                    if not packet:
                        if not self._active:
                            raise TransportException("Transport closed")
                        raise TransportException("Empty packet received")
                    msg = self._dispatch_packet(packet, single_pump=False)
                    if msg is not None and msg.msg_type != 0:
                        self._notify_packet_dispatched()
                        return msg
        return await self._wait_for_message_async(None, None, False)

    async def _pump_async(self) -> None:
        """
        Read and dispatch one SSH packet, or - if another task is already
        reading - wait for it to dispatch one. Used by channels waiting for
        data or window adjustments. Messages that are not handled internally
        are queued for _expect_message_async.
        """
        if self._kex_in_progress:
            # The kex thread drives the socket until NEWKEYS; reading here
            # could consume (and wrongly activate keys for) its packets.
            await asyncio.sleep(0.01)
            return
        if self._recv_lock.locked():
            await self._wait_for_other_reader()
            return

        async with self._recv_lock:
            packet = await self._recv_packet_async()
            msg = self._dispatch_packet(packet, single_pump=True)
            # Queue while still holding the read lock, so the next reader sees
            # it before reading further.
            if msg is not None and msg.msg_type != 0:
                self._enqueue_message(msg)
        self._notify_packet_dispatched()

    async def _expect_message_async(
        self, *allowed_types: int, channel_id: int | None = None
    ) -> Message:
        """Async version of expect_message."""
        return await self._wait_for_message_async(
            tuple(allowed_types), channel_id, False
        )

    async def _wait_for_message_async(
        self,
        allowed_types: tuple[int, ...] | None,
        channel_id: int | None,
        kex_reader: bool,
    ) -> Message:
        """Return the next matching message, reading the socket if no other
        task is.

        ``kex_reader`` marks the key-exchange thread's own requests: while a
        key exchange is in progress only those may read the socket.
        """
        while True:
            with self._lock:
                queued = self._take_queued_message(allowed_types, channel_id)
            if queued is not None:
                return queued

            if self._kex_in_progress and not kex_reader:
                await asyncio.sleep(0.01)
                continue
            if self._recv_lock.locked():
                # Another task is reading; it queues what it does not consume.
                await self._wait_for_other_reader()
                continue

            async with self._recv_lock:
                with self._lock:
                    queued = self._take_queued_message(allowed_types, channel_id)
                if queued is not None:
                    return queued
                packet = await self._recv_packet_async()
                if not packet:
                    if not self._active:
                        raise TransportException("Transport closed")
                    raise TransportException("Empty packet received")
                msg = self._dispatch_packet(packet, single_pump=False)
                matched = (
                    msg is not None
                    and msg.msg_type != 0
                    and self._message_matches(msg, allowed_types, channel_id)
                )
                if msg is not None and msg.msg_type != 0 and not matched:
                    self._enqueue_message(msg)
            self._notify_packet_dispatched()
            if matched:
                assert msg is not None
                return msg

    # --- Handshake Helpers ---

    async def _send_version_async(self) -> None:
        version_string = create_version_string()
        if self._server_mode:
            self._server_version = version_string
        else:
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
                version_string = line.decode(SSH_STRING_ENCODING)
                if self._server_mode:
                    self._client_version = version_string
                else:
                    self._server_version = version_string
                break

    async def _send_kexinit_async(self) -> None:
        self._send_kexinit()

    async def _recv_kexinit_async(self) -> None:
        msg = await self._wait_for_message_async((MSG_KEXINIT,), None, True)
        if not isinstance(msg, KexInitMessage):
            raise ProtocolException("Expected KEXINIT")
        self._peer_kexinit = msg

    # --- Common Async Methods ---

    async def auth_password(self, username: str, password: str) -> bool:  # type: ignore[override]
        if not self._userauth_service_requested:
            await self._send_message_async(ServiceRequestMessage(SERVICE_USERAUTH))
            await self._expect_message_async(MSG_SERVICE_ACCEPT)
            self._userauth_service_requested = True

        from ..auth.password import PasswordAuth

        auth = PasswordAuth(self)
        msg = await auth.authenticate_async(username, password)
        return self._handle_auth_response_message(msg)

    async def auth_publickey(self, username: str, key: Any) -> bool:  # type: ignore[override]
        """Authenticate using public key method asynchronously."""
        if not self._userauth_service_requested:
            await self._send_message_async(ServiceRequestMessage(SERVICE_USERAUTH))
            await self._expect_message_async(MSG_SERVICE_ACCEPT)
            self._userauth_service_requested = True

        from ..auth.publickey import PublicKeyAuth

        auth = PublicKeyAuth(self)
        msg = await auth.authenticate_async(username, key)
        return self._handle_auth_response_message(msg)

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
            if len(self._channels) >= MAX_CHANNELS:
                raise TransportException("Maximum number of channels reached")
            cid = self._allocate_channel_id()

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
            # What we advertised in CHANNEL_OPEN; the inbound window is
            # enforced against it.
            chan._local_window_size = DEFAULT_WINDOW_SIZE
            chan._local_max_packet_size = DEFAULT_MAX_PACKET_SIZE
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
        chan = self._channels.get(channel_id)
        if chan is None:
            return
        remote_id = chan._remote_channel_id
        if remote_id is None:
            return

        msg = ChannelWindowAdjustMessage(
            recipient_channel=remote_id,
            bytes_to_add=bytes_to_add,
        )
        await self._send_message_async(msg)

    async def close(self) -> None:  # type: ignore[override]
        # Snapshot channels and mark inactive before releasing lock
        async with self._state_lock:
            self._active = False
            channels_to_close = list(self._channels.values())
            self._channels.clear()

        # Close channels outside the state lock to avoid deadlock
        # (AsyncChannel.close() also acquires _state_lock)
        from .async_channel import AsyncChannel

        for c in channels_to_close:
            try:
                if isinstance(c, AsyncChannel):
                    await c.close()
                else:
                    c.close()
            except Exception as e:
                self._logger.debug(f"Channel close error in transport: {e}")
        async with self._state_lock:
            # When asyncio streams own the socket, closing the writer closes
            # it; asyncio's socket wrapper must not be closed directly.
            owned_by_streams = self._writer is not None
            if self._writer:
                try:
                    self._writer.close()
                    await asyncio.wait_for(self._writer.wait_closed(), timeout=2.0)
                except Exception as e:
                    self._logger.debug(f"Error closing channel in transport: {e}")
                self._writer = None
            self._reader = None
            if self._socket and not owned_by_streams:
                try:
                    self._socket.close()
                except Exception as e:
                    self._logger.debug(f"Error closing channel in transport: {e}")
