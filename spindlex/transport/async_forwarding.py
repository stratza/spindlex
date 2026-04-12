"""
Asynchronous SSH Port Forwarding Implementation

Provides local and remote port forwarding functionality for AsyncSSHClient.
Handles tunnel creation, data relay, and connection management using asyncio.
"""

import asyncio
import logging
from typing import Any

from ..exceptions import SSHException
from ..protocol.constants import (
    CHANNEL_DIRECT_TCPIP,
    DEFAULT_MAX_PACKET_SIZE,
    DEFAULT_WINDOW_SIZE,
    MSG_REQUEST_SUCCESS,
)
from ..protocol.utils import read_string, read_uint32, write_string, write_uint32


class AsyncForwardingTunnel:
    """
    Represents an asynchronous port forwarding tunnel.
    """

    def __init__(
        self,
        tunnel_id: str,
        local_addr: tuple[str, int],
        remote_addr: tuple[str, int],
        tunnel_type: str,
    ) -> None:
        self.tunnel_id = tunnel_id
        self.local_addr = local_addr
        self.remote_addr = remote_addr
        self.tunnel_type = tunnel_type
        self.active = False
        self.tasks: list[asyncio.Task] = []
        self._logger = logging.getLogger(__name__)

    async def close(self) -> None:
        """Close tunnel and cancel all relay tasks."""
        self.active = False
        for task in self.tasks:
            if not task.done():
                task.cancel()
        self.tasks.clear()
        self._logger.debug(f"Tunnel {self.tunnel_id} closed")


class AsyncLocalPortForwarder:
    """
    Handles async local port forwarding (SSH -L).
    """

    def __init__(self, transport: Any) -> None:
        self._transport = transport
        self._tunnels: dict[str, AsyncForwardingTunnel] = {}
        self._servers: dict[str, asyncio.AbstractServer] = {}
        self._logger = logging.getLogger(__name__)

    async def create_tunnel(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        local_host: str = "127.0.0.1",
    ) -> str:
        tunnel_id = f"local_{local_host}_{local_port}_{remote_host}_{remote_port}"

        if tunnel_id in self._tunnels:
            raise SSHException(f"Tunnel already exists: {tunnel_id}")

        local_addr = (local_host, local_port)
        remote_addr = (remote_host, remote_port)

        try:
            # Create tunnel object
            tunnel = AsyncForwardingTunnel(tunnel_id, local_addr, remote_addr, "local")
            tunnel.active = True

            # Start listening
            server = await asyncio.start_server(
                lambda r, w: self._handle_client(tunnel, r, w),
                local_host,
                local_port,
            )

            self._tunnels[tunnel_id] = tunnel
            self._servers[tunnel_id] = server

            self._logger.info(
                f"Async local port forwarding started: {local_host}:{local_port} -> {remote_host}:{remote_port}"
            )
            return tunnel_id

        except Exception as e:
            raise SSHException(f"Failed to create local port forwarding: {e}") from e

    async def _handle_client(
        self,
        tunnel: AsyncForwardingTunnel,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle individual client connection for local forwarding."""
        if not tunnel.active:
            writer.close()
            await writer.wait_closed()
            return

        try:
            # Open SSH channel
            channel = await self._transport.open_channel(
                CHANNEL_DIRECT_TCPIP, dest_addr=tunnel.remote_addr
            )

            # Start bidirectional relay
            relay1 = asyncio.create_task(self._relay_stream_to_channel(reader, channel))
            relay2 = asyncio.create_task(self._relay_channel_to_stream(channel, writer))

            tunnel.tasks.extend([relay1, relay2])

            # Wait for either relay to finish
            done, pending = await asyncio.wait(
                [relay1, relay2], return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel remaining relay
            for task in pending:
                task.cancel()

        except Exception as e:
            self._logger.error(
                f"Error handling local connection in tunnel {tunnel.tunnel_id}: {e}"
            )
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            self._logger.debug(
                f"Local client connection closed for tunnel {tunnel.tunnel_id}"
            )

    async def _relay_stream_to_channel(
        self, reader: asyncio.StreamReader, channel: Any
    ) -> None:
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                await channel.send(data)
        except Exception:
            pass
        finally:
            try:
                await channel.close()
            except Exception:
                pass

    async def _relay_channel_to_stream(
        self, channel: Any, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await channel.recv(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def close_tunnel(self, tunnel_id: str) -> None:
        if tunnel_id in self._tunnels:
            await self._tunnels[tunnel_id].close()
            del self._tunnels[tunnel_id]

        if tunnel_id in self._servers:
            self._servers[tunnel_id].close()
            await self._servers[tunnel_id].wait_closed()
            del self._servers[tunnel_id]

    async def close_all(self) -> None:
        for tid in list(self._tunnels.keys()):
            await self.close_tunnel(tid)


class AsyncRemotePortForwarder:
    """
    Handles async remote port forwarding (SSH -R).
    """

    def __init__(self, transport: Any) -> None:
        self._transport = transport
        self._tunnels: dict[str, AsyncForwardingTunnel] = {}
        self._logger = logging.getLogger(__name__)

    async def create_tunnel(
        self, remote_port: int, local_host: str, local_port: int, remote_host: str = ""
    ) -> str:
        tunnel_id = f"remote_{remote_host}_{remote_port}_{local_host}_{local_port}"

        if tunnel_id in self._tunnels:
            raise SSHException(f"Tunnel already exists: {tunnel_id}")

        # Send global request
        request_data = bytearray()
        request_data.extend(write_string(remote_host))
        request_data.extend(write_uint32(remote_port))

        res = await self._transport._send_global_request_async(
            "tcpip-forward", True, bytes(request_data)
        )

        if not res or res.msg_type != MSG_REQUEST_SUCCESS:
            raise SSHException("Remote port forwarding request denied by server")

        tunnel = AsyncForwardingTunnel(
            tunnel_id, (local_host, local_port), (remote_host, remote_port), "remote"
        )
        tunnel.active = True
        self._tunnels[tunnel_id] = tunnel

        self._logger.info(
            f"Async remote port forwarding started: {remote_host}:{remote_port} -> {local_host}:{local_port}"
        )
        return tunnel_id

    async def handle_forwarded_connection_async(
        self,
        sender_channel: int,
        initial_window_size: int,
        maximum_packet_size: int,
        type_specific_data: bytes,
    ) -> None:
        """Handle incoming forwarded connection from remote server."""
        try:
            # Parse data
            connected_addr_bytes, offset = read_string(type_specific_data, 0)
            connected_port, offset = read_uint32(type_specific_data, offset)

            # Find tunnel
            tunnel = None
            for t in self._tunnels.values():
                if t.remote_addr[1] == connected_port:
                    tunnel = t
                    break

            if not tunnel or not tunnel.active:
                raise SSHException(f"No active tunnel for remote port {connected_port}")

            from .async_channel import AsyncChannel

            channel = AsyncChannel(self._transport, sender_channel)
            # Need to register it in transport channels so it receives packets
            async with self._transport._state_lock:
                # We need to assign a local ID. The sender_channel from the remote is its ID.
                # We use our own next_channel_id for local mapping.
                local_id = self._transport._next_channel_id
                self._transport._next_channel_id += 1
                channel._channel_id = local_id  # Update instance ID
                channel._remote_channel_id = sender_channel
                channel._remote_window_size = initial_window_size
                channel._remote_max_packet_size = maximum_packet_size
                self._transport._channels[local_id] = channel

            # Confirm channel open
            from ..protocol.messages import ChannelOpenConfirmationMessage

            confirm = ChannelOpenConfirmationMessage(
                recipient_channel=sender_channel,
                sender_channel=local_id,
                initial_window_size=DEFAULT_WINDOW_SIZE,
                maximum_packet_size=DEFAULT_MAX_PACKET_SIZE,
            )
            await self._transport._send_message_async(confirm)

            # Connect to local destination
            reader, writer = await asyncio.open_connection(*tunnel.local_addr)

            # Start relay
            relay1 = asyncio.create_task(self._relay_stream_to_channel(reader, channel))
            relay2 = asyncio.create_task(self._relay_channel_to_stream(channel, writer))

            tunnel.tasks.extend([relay1, relay2])

        except Exception as e:
            self._logger.error(f"Failed to handle remote forwarded connection: {e}")
            # Should send ChannelOpenFailureMessage but we need the sender_channel
            try:
                from ..protocol.constants import SSH_OPEN_CONNECT_FAILED
                from ..protocol.messages import ChannelOpenFailureMessage

                fail = ChannelOpenFailureMessage(
                    recipient_channel=sender_channel,
                    reason_code=SSH_OPEN_CONNECT_FAILED,
                    description=str(e),
                )
                await self._transport._send_message_async(fail)
            except Exception:
                pass

    async def _relay_stream_to_channel(
        self, reader: asyncio.StreamReader, channel: Any
    ) -> None:
        try:
            while True:
                data = await reader.read(8192)
                if not data:
                    break
                await channel.send(data)
        except Exception:
            pass
        finally:
            try:
                await channel.close()
            except Exception:
                pass

    async def _relay_channel_to_stream(
        self, channel: Any, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                data = await channel.recv(8192)
                if not data:
                    break
                writer.write(data)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    async def close_tunnel(self, tunnel_id: str) -> None:
        if tunnel_id in self._tunnels:
            tunnel = self._tunnels[tunnel_id]
            # Cancel remote listen
            request_data = bytearray()
            request_data.extend(write_string(tunnel.remote_addr[0]))
            request_data.extend(write_uint32(tunnel.remote_addr[1]))

            await self._transport._send_global_request_async(
                "cancel-tcpip-forward", True, bytes(request_data)
            )

            await tunnel.close()
            del self._tunnels[tunnel_id]

    async def close_all(self) -> None:
        for tid in list(self._tunnels.keys()):
            await self.close_tunnel(tid)


class AsyncPortForwardingManager:
    """
    Unified manager for async port forwarding.
    """

    def __init__(self, transport: Any) -> None:
        self._transport = transport
        self.local_forwarder = AsyncLocalPortForwarder(transport)
        self.remote_forwarder = AsyncRemotePortForwarder(transport)

    async def create_local_tunnel(
        self,
        local_port: int,
        remote_host: str,
        remote_port: int,
        local_host: str = "127.0.0.1",
    ) -> str:
        return await self.local_forwarder.create_tunnel(
            local_port, remote_host, remote_port, local_host
        )

    async def create_remote_tunnel(
        self, remote_port: int, local_host: str, local_port: int, remote_host: str = ""
    ) -> str:
        return await self.remote_forwarder.create_tunnel(
            remote_port, local_host, local_port, remote_host
        )

    async def handle_forwarded_connection_async(
        self,
        sender_channel: int,
        initial_window_size: int,
        maximum_packet_size: int,
        type_specific_data: bytes,
    ) -> None:
        await self.remote_forwarder.handle_forwarded_connection_async(
            sender_channel, initial_window_size, maximum_packet_size, type_specific_data
        )

    async def close_tunnel(self, tunnel_id: str) -> None:
        if tunnel_id.startswith("local_"):
            await self.local_forwarder.close_tunnel(tunnel_id)
        elif tunnel_id.startswith("remote_"):
            await self.remote_forwarder.close_tunnel(tunnel_id)

    async def close_all_tunnels(self) -> None:
        await self.local_forwarder.close_all()
        await self.remote_forwarder.close_all()

    def get_all_tunnels(self) -> dict[str, Any]:
        tunnels = {}
        tunnels.update(self.local_forwarder._tunnels)
        tunnels.update(self.remote_forwarder._tunnels)
        return tunnels
