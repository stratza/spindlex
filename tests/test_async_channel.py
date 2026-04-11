from unittest.mock import AsyncMock

import pytest
from spindlex.protocol.constants import *
from spindlex.transport.async_channel import AsyncChannel, AsyncChannelFile


@pytest.fixture
def mock_transport():
    transport = AsyncMock()
    transport._server_mode = False
    return transport


@pytest.fixture
def async_channel(mock_transport):
    c = AsyncChannel(mock_transport, 1)
    c._remote_channel_id = 10
    c._remote_window_size = 1000
    c._remote_max_packet_size = 500
    c._local_window_size = DEFAULT_WINDOW_SIZE
    return c


@pytest.mark.asyncio
async def test_async_channel_send(async_channel, mock_transport):
    res = await async_channel.send(b"hello")
    assert res == 5
    mock_transport._send_channel_data_async.assert_called_with(1, b"hello")


@pytest.mark.asyncio
async def test_async_channel_send_window_wait(async_channel, mock_transport):
    async_channel._remote_window_size = 0

    # Mock _pump_async to increase window size
    async def pump_effect():
        async_channel._remote_window_size = 10

    mock_transport._pump_async.side_effect = pump_effect

    res = await async_channel.send(b"hi")
    assert res == 2
    assert mock_transport._pump_async.called


@pytest.mark.asyncio
async def test_async_channel_recv(async_channel, mock_transport):
    async_channel._handle_data(b"data")

    res = await async_channel.recv(2)
    assert res == b"da"

    res = await async_channel.recv(2)
    assert res == b"ta"

    # Test wait for data
    async def pump_effect():
        async_channel._handle_data(b"more")

    mock_transport._pump_async.side_effect = pump_effect
    res = await async_channel.recv(4)
    assert res == b"more"


@pytest.mark.asyncio
async def test_async_channel_recv_exactly(async_channel):
    async_channel._handle_data(b"hello world")
    res = await async_channel.recv_exactly(5)
    assert res == b"hello"


@pytest.mark.asyncio
async def test_async_channel_recv_stderr(async_channel, mock_transport):
    async_channel._handle_extended_data(SSH_EXTENDED_DATA_STDERR, b"error")
    res = await async_channel.recv_stderr(5)
    assert res == b"error"


@pytest.mark.asyncio
async def test_async_channel_exec_command(async_channel, mock_transport):
    from spindlex.protocol.messages import Message

    mock_transport._expect_message_async.return_value = Message(MSG_CHANNEL_SUCCESS)

    await async_channel.exec_command("ls")
    assert mock_transport._send_channel_request_async.called


@pytest.mark.asyncio
async def test_async_channel_close(async_channel, mock_transport):
    await async_channel.close()
    assert async_channel.closed
    assert mock_transport._send_channel_close_async.called


@pytest.mark.asyncio
async def test_async_channel_file(async_channel):
    afile = AsyncChannelFile(async_channel, "rb")
    async_channel._handle_data(b"filedata")

    assert await afile.read(4) == b"file"

    await afile.write(b"write")
    assert async_channel._transport._send_channel_data_async.called

    await afile.close()
    assert afile.closed()
