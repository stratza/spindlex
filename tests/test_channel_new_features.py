import pytest
from unittest.mock import MagicMock
from spindlex.transport.channel import Channel
from spindlex.protocol.constants import SSH_STRING_ENCODING

@pytest.fixture
def mock_transport():
    transport = MagicMock()
    transport._server_mode = False
    transport._server_interface = None
    return transport

@pytest.fixture
def channel(mock_transport):
    chan = Channel(mock_transport, channel_id=1)
    chan._remote_channel_id = 100
    chan._remote_window_size = 1024
    chan._remote_max_packet_size = 1024
    return chan

def test_channel_send_string(channel, mock_transport):
    test_str = "Hello World"
    sent = channel.send(test_str)
    
    assert sent == len(test_str)
    # Verify transport called with bytes
    mock_transport._send_channel_data.assert_called_with(1, test_str.encode(SSH_STRING_ENCODING))

def test_channel_send_exit_status(channel, mock_transport):
    channel.send_exit_status(42)
    
    # Verify transport called with correct data
    # exit-status request is 4 bytes uint32
    from spindlex.protocol.utils import write_uint32
    expected_data = write_uint32(42)
    
    mock_transport._send_channel_request.assert_called_with(
        1, "exit-status", False, expected_data
    )
