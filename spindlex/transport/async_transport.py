"""
Async SSH Transport Layer Implementation

Provides asynchronous SSH transport functionality for high-concurrency applications.
"""

import asyncio
import socket
import struct
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
            if not self._reader or not self._writer:
                self._reader, self._writer = await asyncio.open_connection(sock=self._socket)

            # Handshake
            await self._send_version_async()
            await self._recv_version_async()

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
        if self._kex_in_progress:
            raise TransportException("Key exchange already in progress")

        self._kex_in_progress = True
        try:
            # Exchange KEXINIT
            await self._send_kexinit_async()
            await self._recv_kexinit_async()

            # Run sync KEX in thread. 
            # It will call our overridden _send_message and _recv_message.
            await asyncio.to_thread(self._kex.start_kex)

            self._kex_in_progress = False
        except Exception as e:
            self._kex_in_progress = False
            raise

    # --- Bridge Methods for Sync KEX ---

    def _send_message(self, message: Message) -> None:
        """Bridge sync calls from KEX thread to async send."""
        if self._loop and self._loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(self._send_message_async(message), self._loop)
            fut.result()
        else:
            super()._send_message(message)

    def _recv_message(self, allowed_types: Optional[List[int]] = None) -> Message:
        """Bridge sync calls from KEX thread to async recv."""
        if self._loop and self._loop.is_running():
            fut = asyncio.run_coroutine_threadsafe(self._recv_message_async(), self._loop)
            return fut.result()
        else:
            return super()._recv_message(allowed_types)

    # --- Async Implementation of Packet I/O ---

    async def _send_message_async(self, message: Message) -> None:
        """Async version of _send_message that handles encryption via base class."""
        async with self._send_lock:
            # We use the base class's _build_packet because it handles encryption
            payload = message.pack()
            packet = self._build_packet(payload)
            
            self._writer.write(packet)
            await self._writer.drain()
            self._sequence_number_out += 1

    async def _recv_message_async(self) -> Message:
        """Async version of _recv_message that handles decryption."""
        async with self._recv_lock:
            # We must implement the decryption logic here because we can't 
            # easily call the sync _recv_packet.
            
            # 1. Read the first block (or at least the length)
            block_size = self._decipher.block_size if self._decipher else 8
            if block_size < 4: block_size = 8
            
            first_block = await self._reader.readexactly(block_size)
            
            if self._decipher:
                decrypted_first_block = self._decipher.decrypt(first_block)
                packet_length = struct.unpack(">I", decrypted_first_block[:4])[0]
                remaining_packet = decrypted_first_block[4:]
            else:
                packet_length = struct.unpack(">I", first_block[:4])[0]
                remaining_packet = first_block[4:]

            # 2. Read the rest of the packet
            total_to_read = packet_length + 4 - block_size
            if total_to_read > 0:
                rest = await self._reader.readexactly(total_to_read)
                if self._decipher:
                    remaining_packet += self._decipher.decrypt(rest)
                else:
                    remaining_packet += rest
            
            # 3. Handle MAC if enabled
            if self._mac_in:
                mac_len = self._mac_in.digest_size
                mac_data = await self._reader.readexactly(mac_len)
                # In a full impl we'd verify MAC here
                
            # 4. Extract payload
            padding_len = remaining_packet[0]
            payload = remaining_packet[1 : packet_length - padding_len]
            
            self._sequence_number_in += 1
            return Message.unpack(payload)

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
        self._send_kexinit() # Uses bridged _send_message

    async def _recv_kexinit_async(self) -> None:
        msg = await self._recv_message_async()
        if not isinstance(msg, KexInitMessage):
            raise ProtocolException("Expected KEXINIT")
        self._peer_kexinit = msg

    # --- Common Async Methods ---

    async def auth_password(self, username: str, password: str) -> bool:
        if not self._userauth_service_requested:
            await self._send_message_async(ServiceRequestMessage(SERVICE_USERAUTH))
            msg = await self._recv_message_async()
            if not isinstance(msg, ServiceAcceptMessage):
                raise AuthenticationException("Service request failed")
            self._userauth_service_requested = True
            
        auth_msg = UserAuthRequestMessage(
            username=username, service=SERVICE_CONNECTION, method=AUTH_PASSWORD,
            method_data=self._build_password_auth_data(password)
        )
        await self._send_message_async(auth_msg)
        res = await self._recv_message_async()
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
        res = await self._recv_message_async()
        if isinstance(res, ChannelOpenConfirmationMessage):
            chan._remote_channel_id = res.sender_channel
            async with self._state_lock:
                self._channels[cid] = chan
            return chan
        raise TransportException("Failed to open channel")

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
