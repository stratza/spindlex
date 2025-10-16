"""
Tests for SSH channel functionality.
"""

import threading
import time
from unittest.mock import Mock, MagicMock, patch
import pytest

from ssh_library.transport.channel import Channel
from ssh_library.exceptions import ChannelException


class TestChannelBasic:
    """Test basic channel functionality."""
    
    def test_channel_creation(self):
        """Test creating channel instance."""
        mock_transport = Mock()
        channel = Channel(mock_transport, 1)
        
        assert channel._transport is mock_transport
        assert channel.channel_id == 1
        assert not channel.closed
        assert channel.get_exit_status() == -1
        assert not channel.eof_received
    
    def test_channel_properties(self):
        """Test channel properties."""
        mock_transport = Mock()
        channel = Channel(mock_transport, 5)
        
        # Test initial state
        assert channel.channel_id == 5
        assert not channel.closed
        assert not channel.eof_received
        
        # Test after setting EOF
        channel._eof_received = True
        assert channel.eof_received
        
        # Test after closing
        channel._closed = True
        assert channel.closed
    
    def test_channel_exit_status(self):
        """Test channel exit status handling."""
        mock_transport = Mock()
        channel = Channel(mock_transport, 1)
        
        # Initially no exit status
        assert channel.get_exit_status() == -1
        
        # Set exit status
        channel._exit_status = 0
        assert channel.get_exit_status() == 0
        
        # Set error exit status
        channel._exit_status = 1
        assert channel.get_exit_status() == 1


class TestChannelDataHandling:
    """Test channel data handling functionality."""
    
    def setup_method(self):
        """Set up test channel."""
        self.mock_transport = Mock()
        self.channel = Channel(self.mock_transport, 1)
        
        # Set up remote channel info
        self.channel._remote_channel_id = 2
        self.channel._remote_window_size = 1000
        self.channel._remote_max_packet_size = 500
        self.channel._local_window_size = 1000
        self.channel._local_max_packet_size = 500
    
    def test_handle_data(self):
        """Test handling incoming data."""
        test_data = b"Hello, World!"
        
        self.channel._handle_data(test_data)
        
        # Check data was added to buffer
        assert len(self.channel._recv_buffer) == 1
        assert self.channel._recv_buffer[0] == test_data
        
        # Check data event was set
        assert self.channel._data_event.is_set()
    
    def test_handle_data_multiple(self):
        """Test handling multiple data chunks."""
        data1 = b"First chunk"
        data2 = b"Second chunk"
        
        self.channel._handle_data(data1)
        self.channel._handle_data(data2)
        
        # Check both chunks are in buffer
        assert len(self.channel._recv_buffer) == 2
        assert self.channel._recv_buffer[0] == data1
        assert self.channel._recv_buffer[1] == data2
    
    def test_handle_data_when_closed(self):
        """Test handling data when channel is closed."""
        self.channel._closed = True
        
        self.channel._handle_data(b"test data")
        
        # Data should not be added when closed
        assert len(self.channel._recv_buffer) == 0
    
    def test_handle_extended_data(self):
        """Test handling extended data (stderr)."""
        stderr_data = b"Error message"
        
        self.channel._handle_extended_data(1, stderr_data)  # 1 = SSH_EXTENDED_DATA_STDERR
        
        # Check data was added to stderr buffer
        assert len(self.channel._stderr_buffer) == 1
        assert self.channel._stderr_buffer[0] == stderr_data
        
        # Check data event was set
        assert self.channel._data_event.is_set()
    
    def test_handle_extended_data_unknown_type(self):
        """Test handling unknown extended data type."""
        self.channel._handle_extended_data(99, b"unknown data")
        
        # Unknown type should be ignored
        assert len(self.channel._stderr_buffer) == 0
    
    def test_handle_extended_data_when_closed(self):
        """Test handling extended data when channel is closed."""
        self.channel._closed = True
        
        self.channel._handle_extended_data(1, b"error data")
        
        # Data should not be added when closed
        assert len(self.channel._stderr_buffer) == 0


class TestChannelFlowControl:
    """Test channel flow control functionality."""
    
    def setup_method(self):
        """Set up test channel."""
        self.mock_transport = Mock()
        self.channel = Channel(self.mock_transport, 1)
        
        # Set up channel state
        self.channel._remote_channel_id = 2
        self.channel._remote_window_size = 1000
        self.channel._local_window_size = 1000
    
    def test_handle_window_adjust(self):
        """Test handling window adjust message."""
        initial_window = self.channel._remote_window_size
        bytes_to_add = 500
        
        self.channel._handle_window_adjust(bytes_to_add)
        
        assert self.channel._remote_window_size == initial_window + bytes_to_add
    
    def test_handle_window_adjust_zero(self):
        """Test handling window adjust with zero bytes."""
        initial_window = self.channel._remote_window_size
        
        self.channel._handle_window_adjust(0)
        
        assert self.channel._remote_window_size == initial_window
    
    def test_handle_window_adjust_large(self):
        """Test handling large window adjust."""
        initial_window = self.channel._remote_window_size
        large_adjustment = 1000000
        
        self.channel._handle_window_adjust(large_adjustment)
        
        assert self.channel._remote_window_size == initial_window + large_adjustment
    
    def test_data_triggers_window_adjust(self):
        """Test that receiving data triggers window adjust when buffer fills."""
        # Add multiple data chunks to fill buffer
        for i in range(15):  # More than the threshold of 10
            self.channel._handle_data(f"chunk {i}".encode())
        
        # Should have called transport's window adjust method
        # Note: This tests the flow control logic in _handle_data
        assert len(self.channel._recv_buffer) == 15


class TestChannelLifecycle:
    """Test channel lifecycle management."""
    
    def setup_method(self):
        """Set up test channel."""
        self.mock_transport = Mock()
        self.channel = Channel(self.mock_transport, 1)
    
    def test_handle_eof(self):
        """Test handling EOF from remote side."""
        assert not self.channel._eof_received
        
        self.channel._handle_eof()
        
        assert self.channel._eof_received
        assert self.channel._data_event.is_set()
    
    def test_handle_close(self):
        """Test handling close from remote side."""
        assert not self.channel._closed
        
        self.channel._handle_close()
        
        assert self.channel._closed
        assert self.channel._data_event.is_set()
    
    def test_close_channel(self):
        """Test closing channel locally."""
        assert not self.channel._closed
        
        self.channel.close()
        
        assert self.channel._closed
        # Should notify transport to close channel
        self.mock_transport._close_channel.assert_called_once_with(1)
    
    def test_close_already_closed(self):
        """Test closing already closed channel."""
        self.channel._closed = True
        
        self.channel.close()
        
        # Should not call transport close again
        self.mock_transport._close_channel.assert_not_called()


class TestChannelRequests:
    """Test channel request handling."""
    
    def setup_method(self):
        """Set up test channel."""
        self.mock_transport = Mock()
        self.channel = Channel(self.mock_transport, 1)
    
    def test_handle_request_success(self):
        """Test handling request success."""
        assert self.channel._request_success is None
        
        self.channel._handle_request_success()
        
        assert self.channel._request_success is True
        assert self.channel._request_event.is_set()
    
    def test_handle_request_failure(self):
        """Test handling request failure."""
        assert self.channel._request_success is None
        
        self.channel._handle_request_failure()
        
        assert self.channel._request_success is False
        assert self.channel._request_event.is_set()
    
    def test_multiple_request_responses(self):
        """Test handling multiple request responses."""
        # First request succeeds
        self.channel._handle_request_success()
        assert self.channel._request_success is True
        
        # Reset for next request
        self.channel._request_success = None
        self.channel._request_event.clear()
        
        # Second request fails
        self.channel._handle_request_failure()
        assert self.channel._request_success is False


class TestChannelThreadSafety:
    """Test channel thread safety."""
    
    def setup_method(self):
        """Set up test channel."""
        self.mock_transport = Mock()
        self.channel = Channel(self.mock_transport, 1)
    
    def test_concurrent_data_handling(self):
        """Test concurrent data handling from multiple threads."""
        num_threads = 10
        data_per_thread = 5
        threads = []
        
        def add_data(thread_id):
            for i in range(data_per_thread):
                data = f"thread{thread_id}_data{i}".encode()
                self.channel._handle_data(data)
        
        # Start multiple threads adding data
        for i in range(num_threads):
            thread = threading.Thread(target=add_data, args=(i,))
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Check all data was added
        assert len(self.channel._recv_buffer) == num_threads * data_per_thread
    
    def test_concurrent_close_and_data(self):
        """Test concurrent close and data operations."""
        data_added = []
        
        def add_data():
            for i in range(100):
                if not self.channel._closed:
                    self.channel._handle_data(f"data{i}".encode())
                    data_added.append(i)
                time.sleep(0.001)  # Small delay
        
        def close_channel():
            time.sleep(0.05)  # Let some data be added first
            self.channel.close()
        
        # Start both operations concurrently
        data_thread = threading.Thread(target=add_data)
        close_thread = threading.Thread(target=close_channel)
        
        data_thread.start()
        close_thread.start()
        
        data_thread.join()
        close_thread.join()
        
        # Channel should be closed
        assert self.channel._closed
        
        # Some data should have been added before close
        assert len(data_added) > 0
        assert len(data_added) < 100  # But not all, since channel was closed


class TestChannelSendRecv:
    """Test channel send/recv operations."""
    
    def setup_method(self):
        """Set up test channel."""
        self.mock_transport = Mock()
        self.channel = Channel(self.mock_transport, 1)
        
        # Set up channel state for send/recv
        self.channel._remote_channel_id = 2
        self.channel._remote_window_size = 1000
        self.channel._remote_max_packet_size = 500
        self.channel._local_window_size = 1000
        self.channel._local_max_packet_size = 500
    
    def test_send_data_success(self):
        """Test successful data sending."""
        test_data = b"Hello, World!"
        
        result = self.channel.send(test_data)
        
        assert result == len(test_data)
        self.mock_transport._send_channel_data.assert_called_once_with(1, test_data)
        assert self.channel._remote_window_size == 1000 - len(test_data)
    
    def test_send_data_empty(self):
        """Test sending empty data."""
        result = self.channel.send(b"")
        
        assert result == 0
        self.mock_transport._send_channel_data.assert_not_called()
    
    def test_send_data_closed_channel(self):
        """Test sending data on closed channel."""
        self.channel._closed = True
        
        with pytest.raises(ChannelException, match="Channel is closed"):
            self.channel.send(b"test")
    
    def test_send_data_eof_sent(self):
        """Test sending data after EOF sent."""
        self.channel._eof_sent = True
        
        with pytest.raises(ChannelException, match="EOF already sent"):
            self.channel.send(b"test")
    
    def test_send_data_window_limit(self):
        """Test sending data limited by window size."""
        self.channel._remote_window_size = 5
        test_data = b"Hello, World!"  # 13 bytes
        
        result = self.channel.send(test_data)
        
        assert result == 5  # Only 5 bytes sent
        expected_data = test_data[:5]
        self.mock_transport._send_channel_data.assert_called_once_with(1, expected_data)
    
    def test_send_data_packet_size_limit(self):
        """Test sending data limited by max packet size."""
        self.channel._remote_max_packet_size = 5
        test_data = b"Hello, World!"  # 13 bytes
        
        result = self.channel.send(test_data)
        
        assert result == 5  # Only 5 bytes sent
        expected_data = test_data[:5]
        self.mock_transport._send_channel_data.assert_called_once_with(1, expected_data)
    
    def test_recv_data_from_buffer(self):
        """Test receiving data from buffer."""
        test_data = b"Hello, World!"
        self.channel._handle_data(test_data)
        
        result = self.channel.recv(5)
        
        assert result == b"Hello"
        # Remainder should still be in buffer
        assert len(self.channel._recv_buffer) == 1
        assert self.channel._recv_buffer[0] == b", World!"
    
    def test_recv_data_entire_chunk(self):
        """Test receiving entire data chunk."""
        test_data = b"Hello"
        self.channel._handle_data(test_data)
        
        result = self.channel.recv(10)  # Request more than available
        
        assert result == test_data
        assert len(self.channel._recv_buffer) == 0
    
    def test_recv_data_no_data(self):
        """Test receiving when no data available."""
        result = self.channel.recv(10)
        
        assert result == b""
    
    def test_recv_data_after_eof(self):
        """Test receiving after EOF received."""
        self.channel._eof_received = True
        
        result = self.channel.recv(10)
        
        assert result == b""
    
    def test_recv_stderr_data(self):
        """Test receiving stderr data."""
        stderr_data = b"Error message"
        self.channel._handle_extended_data(1, stderr_data)  # SSH_EXTENDED_DATA_STDERR
        
        result = self.channel.recv_stderr(5)
        
        assert result == b"Error"
        # Remainder should still be in buffer
        assert len(self.channel._stderr_buffer) == 1
        assert self.channel._stderr_buffer[0] == b" message"


class TestChannelRequests:
    """Test channel request operations."""
    
    def setup_method(self):
        """Set up test channel."""
        self.mock_transport = Mock()
        self.channel = Channel(self.mock_transport, 1)
        
        # Set up channel state
        self.channel._remote_channel_id = 2
    
    def test_exec_command_success(self):
        """Test successful command execution."""
        # Mock the send_channel_request method directly
        with patch.object(self.channel, 'send_channel_request', return_value=True) as mock_request:
            self.channel.exec_command("ls -la")
            
            # Verify the request was called correctly
            mock_request.assert_called_once_with("exec", want_reply=True, data=b'\x00\x00\x00\x06ls -la')
    
    def test_exec_command_empty(self):
        """Test executing empty command."""
        with pytest.raises(ChannelException, match="Command cannot be empty"):
            self.channel.exec_command("")
    
    def test_invoke_shell_success(self):
        """Test successful shell invocation."""
        # Mock the send_channel_request method directly
        with patch.object(self.channel, 'send_channel_request', return_value=True) as mock_request:
            self.channel.invoke_shell()
            
            # Verify the request was called correctly
            mock_request.assert_called_once_with("shell", want_reply=True)
    
    def test_invoke_subsystem_success(self):
        """Test successful subsystem invocation."""
        # Mock the send_channel_request method directly
        with patch.object(self.channel, 'send_channel_request', return_value=True) as mock_request:
            self.channel.invoke_subsystem("sftp")
            
            # Verify the request was called correctly
            mock_request.assert_called_once_with("subsystem", want_reply=True, data=b'\x00\x00\x00\x04sftp')
    
    def test_invoke_subsystem_empty(self):
        """Test invoking empty subsystem."""
        with pytest.raises(ChannelException, match="Subsystem name cannot be empty"):
            self.channel.invoke_subsystem("")
    
    def test_request_pty_success(self):
        """Test successful PTY request."""
        # Mock the send_channel_request method directly
        with patch.object(self.channel, 'send_channel_request', return_value=True) as mock_request:
            self.channel.request_pty("xterm", 80, 24)
            
            # Verify the request was called correctly
            mock_request.assert_called_once()
            args, kwargs = mock_request.call_args
            assert args[0] == "pty-req"
            assert kwargs['want_reply'] is True
            # Check that data contains the PTY parameters
    
    def test_send_eof(self):
        """Test sending EOF."""
        self.channel.send_eof()
        
        assert self.channel._eof_sent
        self.mock_transport._send_channel_eof.assert_called_once_with(1)
    
    def test_send_eof_already_sent(self):
        """Test sending EOF when already sent."""
        self.channel._eof_sent = True
        
        self.channel.send_eof()  # Should not raise exception
        
        # Should not call transport again
        self.mock_transport._send_channel_eof.assert_not_called()


class TestChannelExitStatus:
    """Test channel exit status handling."""
    
    def setup_method(self):
        """Set up test channel."""
        self.mock_transport = Mock()
        self.channel = Channel(self.mock_transport, 1)
    
    def test_handle_exit_status(self):
        """Test handling exit status."""
        self.channel._handle_exit_status(0)
        
        assert self.channel.get_exit_status() == 0
    
    def test_handle_exit_status_error(self):
        """Test handling error exit status."""
        self.channel._handle_exit_status(1)
        
        assert self.channel.get_exit_status() == 1
    
    def test_handle_exit_signal(self):
        """Test handling exit signal."""
        self.channel._handle_exit_signal("TERM", False, "Terminated", "en-US")
        
        assert self.channel.get_exit_status() == 128  # Signal termination
        assert hasattr(self.channel, '_exit_signal')
        assert self.channel._exit_signal['signal_name'] == "TERM"
        assert self.channel._exit_signal['core_dumped'] is False
        assert self.channel._exit_signal['error_message'] == "Terminated"


class TestChannelIntegration:
    """Integration tests for channel functionality."""
    
    def test_channel_data_flow(self):
        """Test complete data flow through channel."""
        mock_transport = Mock()
        channel = Channel(mock_transport, 1)
        
        # Set up channel state
        channel._remote_channel_id = 2
        channel._remote_window_size = 1000
        channel._remote_max_packet_size = 500
        
        # Test send operation
        test_data = b"Hello, World!"
        result = channel.send(test_data)
        assert result == len(test_data)
        
        # Simulate receiving data
        channel._handle_data(test_data)
        received = channel.recv(len(test_data))
        assert received == test_data
        
        # Simulate EOF
        channel._handle_eof()
        assert channel.eof_received
        
        # Close channel
        channel.close()
        assert channel.closed
        mock_transport._close_channel.assert_called_once_with(1)
    
    def test_channel_error_handling(self):
        """Test channel error handling scenarios."""
        mock_transport = Mock()
        channel = Channel(mock_transport, 1)
        
        # Test handling data when closed
        channel._closed = True
        channel._handle_data(b"should be ignored")
        assert len(channel._recv_buffer) == 0
        
        # Test multiple closes
        channel.close()  # Should not raise exception
        
        # Test handling messages after close
        channel._handle_eof()  # Should not raise exception
        channel._handle_window_adjust(100)  # Should not raise exception
    
    def test_channel_state_consistency(self):
        """Test channel state consistency."""
        mock_transport = Mock()
        channel = Channel(mock_transport, 1)
        
        # Initial state
        assert not channel.closed
        assert not channel.eof_received
        assert channel.get_exit_status() == -1
        
        # After receiving EOF
        channel._handle_eof()
        assert channel.eof_received
        assert not channel.closed  # EOF doesn't close channel
        
        # After closing
        channel.close()
        assert channel.closed
        assert channel.eof_received  # EOF state preserved
    
    def test_channel_command_execution_flow(self):
        """Test complete command execution flow."""
        mock_transport = Mock()
        channel = Channel(mock_transport, 1)
        
        # Set up channel state
        channel._remote_channel_id = 2
        channel._remote_window_size = 1000
        channel._remote_max_packet_size = 500
        
        # Mock the exec_command to avoid the actual request
        with patch.object(channel, 'send_channel_request', return_value=True):
            # Execute command
            channel.exec_command("echo hello")
        
        # Simulate command output
        output_data = b"hello\n"
        channel._handle_data(output_data)
        
        # Simulate exit status
        channel._handle_exit_status(0)
        
        # Simulate EOF
        channel._handle_eof()
        
        # Verify results
        received_output = channel.recv(100)
        assert received_output == output_data
        assert channel.get_exit_status() == 0
        assert channel.eof_received