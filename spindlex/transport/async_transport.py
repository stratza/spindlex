"""
Async SSH Transport Layer Implementation

Provides asynchronous SSH transport functionality for high-concurrency applications.
"""

import asyncio
import socket
import struct
import os
from typing import Any, Dict, Optional, List

from ..exceptions import AuthenticationException, ProtocolException, TransportException
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

    def __init__(self, sock: socket.socket) -> None:
        super().__init__(sock)
        try:
            self._loop = asyncio.get_event_loop()
        except RuntimeError:
            self._loop = None
            
        self._reader: Optional[asyncio.StreamReader] = None
        self._writer: Optional[asyncio.StreamWriter] = None
        
        # Locks for async safety
        self._send_lock = asyncio.Lock()
        self._recv_lock = asyncio.Lock()
        self._state_lock = asyncio.Lock()

    async def connect_existing(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Initialize with existing asyncio streams."""
        async with self._state_lock:
            self._reader = reader
            self._writer = writer

    async def start_client(self, timeout: Optional[float] = None) -> None:
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
            raise TransportException(f"Client start failed: {e}")

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
        except Exception as e:
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

    # --- Bridge Methods for Sync Logic ---

    def _send_message(self, message: Message) -> None:
        """Bridge sync calls to async send."""
        if not self._loop:
            return super()._send_message(message)
            
        try:
            # If we're already on the loop thread, we can't block with .result()
            # but we also shouldn't be here if we want synchronous behavior.
            # However, for KEX and other sync-bridged parts, it's called from threads.
            asyncio.get_running_loop()
            
            # On the loop: schedule it.
            self._loop.call_soon_threadsafe(lambda: asyncio.create_task(self._send_message_async(message)))
        except RuntimeError:
            # Safe to block from other threads
            fut = asyncio.run_coroutine_threadsafe(self._send_message_async(message), self._loop)
            fut.result()

    def _recv_message(self, allowed_types: Optional[List[int]] = None) -> Message:
        """Bridge sync calls to async recv."""
        if not self._loop:
            return super()._recv_message()

        try:
            asyncio.get_running_loop()
            raise TransportException("Synchronous receive called on event loop thread")
        except RuntimeError:
            # For debugging the 'bytes' error
            # print(f"DEBUG: _recv_message from thread. Queue type: {type(self._message_queue)}")
            fut = asyncio.run_coroutine_threadsafe(self._recv_message_async(), self._loop)
            return fut.result()

    def _expect_message(self, *allowed_types: int) -> Message:
        """Bridge sync expect_message."""
        if not self._loop:
            return super()._expect_message(*allowed_types)

        try:
            asyncio.get_running_loop()
            raise TransportException("Synchronous expect_message called on event loop thread")
        except RuntimeError:
            fut = asyncio.run_coroutine_threadsafe(self._expect_message_async(*allowed_types), self._loop)
            return fut.result()

    # --- Async Implementation of Packet I/O ---

    def _recv_bytes(self, length: int) -> bytes:
        """Bridge sync recv_bytes to async reader."""
        # This is called via asyncio.to_thread in _recv_message_async
        # so we must use run_coroutine_threadsafe.
        fut = asyncio.run_coroutine_threadsafe(self._reader.readexactly(length), self._loop)
        return fut.result()

    async def _send_message_async(self, message: Message) -> None:
        """Async version of _send_message."""
        async with self._send_lock:
            payload = message.pack()
            packet = self._build_packet(payload)
            packet = self._encrypt_packet(packet)
            
            self._writer.write(packet)
            await self._writer.drain()
            
            # If this was a NEWKEYS message, activate encryption AFTER sending it
            if message.msg_type == MSG_NEWKEYS:
                self._activate_outbound_encryption()
                
            self._sequence_number_out = (self._sequence_number_out + 1) & 0xFFFFFFFF

    async def _recv_message_async(self) -> Message:
        """Async version of _recv_message."""
        async with self._recv_lock:
            # We call the base _read_message which calls our overridden _recv_bytes
            # to handle the actual reading from the asyncio reader.
            msg = await asyncio.to_thread(super()._read_message)
            return msg

    async def _pump_async(self) -> None:
        """
        Pump the transport once to read and dispatch a message.
        Used by channels to wait for data/window adjustments.
        """
        msg = await self._recv_message_async()
        
        # Always queue the message so it can be picked up by _expect_message_async
        # even if it was already dispatched by _read_message.
        async with self._state_lock:
            self._message_queue.append(msg)

    async def _expect_message_async(self, *allowed_types: int) -> Message:
        """Async version of expect_message."""
        while True:
            # 1. Check queue
            async with self._state_lock:
                for i, msg in enumerate(self._message_queue):
                    if msg.msg_type in allowed_types:
                        return self._message_queue.pop(i)
            
            # 2. Read next
            msg = await self._recv_message_async()
            if msg.msg_type in allowed_types:
                return msg
            
            # 3. Queue it
            async with self._state_lock:
                self._message_queue.append(msg)

    # --- Handshake Helpers ---

    async def _send_version_async(self) -> None:
        version_string = create_version_string()
        self._client_version = version_string
        self._writer.write((version_string + "\r\n").encode(SSH_STRING_ENCODING))
        await self._writer.drain()

    async def _recv_version_async(self) -> None:
        while True:
            line = await self._reader.readline()
            if not line: raise TransportException("Connection closed")
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

    async def auth_password(self, username: str, password: str) -> bool:
        if not self._userauth_service_requested:
            await self._send_message_async(ServiceRequestMessage(SERVICE_USERAUTH))
            msg = await self._expect_message_async(MSG_SERVICE_ACCEPT)
            self._userauth_service_requested = True
            
        auth_msg = UserAuthRequestMessage(
            username=username, service=SERVICE_CONNECTION, method=AUTH_PASSWORD,
            method_data=self._build_password_auth_data(password)
        )
        await self._send_message_async(auth_msg)
        res = await self._expect_message_async(MSG_USERAUTH_SUCCESS, MSG_USERAUTH_FAILURE)
        if isinstance(res, UserAuthSuccessMessage):
            self._authenticated = True
            return True
        return False

    async def open_channel(self, kind: str, dest_addr: Optional[tuple] = None) -> Any:
        async with self._state_lock:
            cid = self._next_channel_id
            self._next_channel_id += 1
            
        from .async_channel import AsyncChannel
        chan = AsyncChannel(self, cid)
        
        # Build open message
        msg = ChannelOpenMessage(
            channel_type=kind, sender_channel=cid,
            initial_window_size=DEFAULT_WINDOW_SIZE,
            maximum_packet_size=DEFAULT_MAX_PACKET_SIZE
        )
        await self._send_message_async(msg)
        
        # Wait for confirmation
        res = await self._expect_message_async(MSG_CHANNEL_OPEN_CONFIRMATION, MSG_CHANNEL_OPEN_FAILURE)
        if isinstance(res, ChannelOpenConfirmationMessage):
            chan._remote_channel_id = res.sender_channel
            chan._remote_window_size = res.initial_window_size
            chan._remote_max_packet_size = res.maximum_packet_size
            
            async with self._state_lock:
                self._channels[cid] = chan
            return chan
        raise TransportException("Failed to open channel")

    async def _send_channel_request_async(self, channel_id: int, request_type: str, want_reply: bool, data: bytes) -> None:
        """Send channel request message asynchronously."""
        msg = ChannelRequestMessage(
            recipient_channel=self._channels[channel_id]._remote_channel_id,
            request_type=request_type,
            want_reply=want_reply,
            request_data=data
        )
        await self._send_message_async(msg)

    async def _send_channel_data_async(self, channel_id: int, data: bytes) -> None:
        """Send channel data message asynchronously."""
        msg = ChannelDataMessage(
            recipient_channel=self._channels[channel_id]._remote_channel_id,
            data=data
        )
        await self._send_message_async(msg)

    async def _send_channel_eof_async(self, channel_id: int) -> None:
        """Send channel EOF message asynchronously."""
        msg = ChannelEOFMessage(
            recipient_channel=self._channels[channel_id]._remote_channel_id
        )
        await self._send_message_async(msg)

    async def _send_channel_close_async(self, channel_id: int) -> None:
        """Send channel close message asynchronously."""
        msg = ChannelCloseMessage(
            recipient_channel=self._channels[channel_id]._remote_channel_id
        )
        await self._send_message_async(msg)

    async def _send_channel_window_adjust_async(self, channel_id: int, bytes_to_add: int) -> None:
        """Send channel window adjust message asynchronously."""
        msg = ChannelWindowAdjustMessage(
            recipient_channel=self._channels[channel_id]._remote_channel_id,
            bytes_to_add=bytes_to_add
        )
        await self._send_message_async(msg)

    async def close(self) -> None:
        async with self._state_lock:
            self._active = False
            if self._writer:
                try:
                    self._writer.close()
                    await self._writer.wait_closed()
                except: pass
                self._writer = None
            self._reader = None
            if self._socket:
                try: self._socket.close()
                except: pass
            for c in list(self._channels.values()):
                try: await c.close()
                except: pass
            self._channels.clear()
