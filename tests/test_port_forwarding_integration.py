#!/usr/bin/env python3
"""
Integration test for SpindleX port forwarding functionality.

This test demonstrates port forwarding working with local services
to validate data transmission through tunnels.

This script implements task 10.3: Test port forwarding functionality
"""

import sys
import socket
import threading
import time
import logging
import traceback
import tempfile
import http.server
import socketserver
from spindlex.transport.forwarding import PortForwardingManager, LocalPortForwarder
from spindlex.transport.transport import Transport
from spindlex.transport.channel import Channel

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

class MockTransport:
    """Mock transport that creates working channels for data relay."""
    
    def __init__(self):
        self._channels = {}
        self._next_channel_id = 0
        self._active = True
        self._authenticated = True
    
    def open_channel(self, channel_type, dest_addr=None):
        """Create a working mock channel that connects to the destination."""
        channel_id = self._next_channel_id
        self._next_channel_id += 1
        
        # Create a channel that actually connects to the destination
        channel = WorkingMockChannel(self, channel_id, dest_addr)
        channel._remote_channel_id = channel_id + 100
        self._channels[channel_id] = channel
        
        return channel
    
    def _send_global_request(self, request_name, want_reply, data=b""):
        """Mock global request sending."""
        if request_name in ["tcpip-forward", "cancel-tcpip-forward"]:
            return True
        return False

class WorkingMockChannel:
    """Mock channel that actually connects to destinations for testing."""
    
    def __init__(self, transport, channel_id, dest_addr=None):
        self._transport = transport
        self._channel_id = channel_id
        self._remote_channel_id = None
        self.closed = False
        self._dest_addr = dest_addr
        self._socket = None
        
        # If we have a destination, connect to it
        if dest_addr:
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(5)
                self._socket.connect(dest_addr)
                print(f"Mock channel connected to {dest_addr}")
            except Exception as e:
                print(f"Mock channel failed to connect to {dest_addr}: {e}")
                self._socket = None
    
    def send(self, data):
        """Send data through the mock channel."""
        if self._socket:
            try:
                self._socket.sendall(data)
            except Exception as e:
                print(f"Mock channel send error: {e}")
    
    def recv(self, size):
        """Receive data from the mock channel."""
        if self._socket:
            try:
                return self._socket.recv(size)
            except Exception as e:
                print(f"Mock channel recv error: {e}")
                return b""
        return b""
    
    def close(self):
        """Close the mock channel."""
        self.closed = True
        if self._socket:
            try:
                self._socket.close()
            except:
                pass

class IntegrationTester:
    """Integration test class for port forwarding."""
    
    def find_free_port(self):
        """Find a free local port."""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port
    
    def create_echo_server(self, port):
        """Create a simple echo server for testing."""
        def echo_server():
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('127.0.0.1', port))
                server_socket.listen(1)
                server_socket.settimeout(30)  # 30 second timeout
                
                print(f"Echo server listening on 127.0.0.1:{port}")
                
                while True:
                    try:
                        client_socket, addr = server_socket.accept()
                        print(f"Echo server accepted connection from {addr}")
                        
                        # Echo data back
                        while True:
                            data = client_socket.recv(1024)
                            if not data:
                                break
                            print(f"Echo server received: {data}")
                            client_socket.sendall(b"ECHO: " + data)
                        
                        client_socket.close()
                        
                    except socket.timeout:
                        break
                    except Exception as e:
                        print(f"Echo server error: {e}")
                        break
                        
            except Exception as e:
                print(f"Echo server setup error: {e}")
            finally:
                try:
                    server_socket.close()
                except:
                    pass
        
        thread = threading.Thread(target=echo_server, daemon=True)
        thread.start()
        time.sleep(0.5)  # Give server time to start
        return thread
    
    def create_http_server(self, port):
        """Create a simple HTTP server for testing."""
        class TestHTTPHandler(http.server.SimpleHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.end_headers()
                response = f"Hello from HTTP server on port {port}!\nPath: {self.path}\n"
                self.wfile.write(response.encode())
            
            def log_message(self, format, *args):
                print(f"HTTP server: {format % args}")
        
        def http_server():
            try:
                with socketserver.TCPServer(("127.0.0.1", port), TestHTTPHandler) as httpd:
                    print(f"HTTP server listening on 127.0.0.1:{port}")
                    httpd.timeout = 30
                    httpd.serve_forever()
            except Exception as e:
                print(f"HTTP server error: {e}")
        
        thread = threading.Thread(target=http_server, daemon=True)
        thread.start()
        time.sleep(0.5)  # Give server time to start
        return thread
    
    def test_local_port_forwarding_with_echo_server(self):
        """Test local port forwarding with an echo server."""
        print("=" * 60)
        print("Testing local port forwarding with echo server...")
        print("=" * 60)
        
        try:
            # Create echo server
            echo_port = self.find_free_port()
            echo_thread = self.create_echo_server(echo_port)
            print(f"✓ Echo server created on port {echo_port}")
            
            # Create mock transport
            mock_transport = MockTransport()
            
            # Create local port forwarder
            local_forwarder = LocalPortForwarder(mock_transport)
            
            # Create tunnel to echo server
            local_port = self.find_free_port()
            tunnel_id = local_forwarder.create_tunnel(
                local_port=local_port,
                remote_host="127.0.0.1",
                remote_port=echo_port
            )
            print(f"✓ Local tunnel created: {local_port} -> 127.0.0.1:{echo_port}")
            
            # Give tunnel time to establish
            time.sleep(1)
            
            # Test data transmission through tunnel
            print("Testing data transmission through tunnel...")
            
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.settimeout(10)
            
            try:
                # Connect through the tunnel
                test_socket.connect(('127.0.0.1', local_port))
                print("✓ Connected through tunnel")
                
                # Send test data
                test_message = b"Hello through port forwarding!"
                test_socket.sendall(test_message)
                print(f"✓ Sent test message: {test_message}")
                
                # Receive echoed data
                response = test_socket.recv(1024)
                print(f"✓ Received response: {response}")
                
                # Verify echo response
                expected_response = b"ECHO: " + test_message
                if response == expected_response:
                    print("✓ Echo response matches expected data")
                else:
                    print(f"✗ Echo response mismatch. Expected: {expected_response}, Got: {response}")
                    return False
                
                test_socket.close()
                
            except Exception as e:
                print(f"✗ Data transmission test failed: {e}")
                return False
            
            # Clean up
            local_forwarder.close_tunnel(tunnel_id)
            print("✓ Tunnel closed")
            
            return True
            
        except Exception as e:
            print(f"✗ Local port forwarding with echo server failed: {e}")
            traceback.print_exc()
            return False
    
    def test_local_port_forwarding_with_http_server(self):
        """Test local port forwarding with an HTTP server."""
        print("\n" + "=" * 60)
        print("Testing local port forwarding with HTTP server...")
        print("=" * 60)
        
        try:
            # Create HTTP server
            http_port = self.find_free_port()
            http_thread = self.create_http_server(http_port)
            print(f"✓ HTTP server created on port {http_port}")
            
            # Create mock transport
            mock_transport = MockTransport()
            
            # Create local port forwarder
            local_forwarder = LocalPortForwarder(mock_transport)
            
            # Create tunnel to HTTP server
            local_port = self.find_free_port()
            tunnel_id = local_forwarder.create_tunnel(
                local_port=local_port,
                remote_host="127.0.0.1",
                remote_port=http_port
            )
            print(f"✓ Local tunnel created: {local_port} -> 127.0.0.1:{http_port}")
            
            # Give tunnel time to establish
            time.sleep(1)
            
            # Test HTTP request through tunnel
            print("Testing HTTP request through tunnel...")
            
            try:
                # Create HTTP request
                http_request = (
                    "GET /test HTTP/1.1\r\n"
                    "Host: localhost\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                ).encode()
                
                # Connect and send request through tunnel
                test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                test_socket.settimeout(10)
                test_socket.connect(('127.0.0.1', local_port))
                
                print("✓ Connected to HTTP server through tunnel")
                
                test_socket.sendall(http_request)
                print("✓ Sent HTTP request")
                
                # Receive HTTP response
                response = b""
                while True:
                    chunk = test_socket.recv(1024)
                    if not chunk:
                        break
                    response += chunk
                
                test_socket.close()
                
                print(f"✓ Received HTTP response ({len(response)} bytes)")
                
                # Verify HTTP response
                response_str = response.decode('utf-8', errors='replace')
                if "HTTP/1.0 200 OK" in response_str or "HTTP/1.1 200 OK" in response_str:
                    print("✓ HTTP response has correct status code")
                else:
                    print(f"✗ HTTP response missing 200 OK status")
                    print(f"Response preview: {response_str[:200]}...")
                    return False
                
                if f"Hello from HTTP server on port {http_port}" in response_str:
                    print("✓ HTTP response contains expected content")
                else:
                    print(f"✗ HTTP response missing expected content")
                    print(f"Response preview: {response_str[:200]}...")
                    return False
                
                if "Path: /test" in response_str:
                    print("✓ HTTP response shows correct path")
                else:
                    print(f"✗ HTTP response missing path information")
                    return False
                
            except Exception as e:
                print(f"✗ HTTP request test failed: {e}")
                return False
            
            # Clean up
            local_forwarder.close_tunnel(tunnel_id)
            print("✓ Tunnel closed")
            
            return True
            
        except Exception as e:
            print(f"✗ Local port forwarding with HTTP server failed: {e}")
            traceback.print_exc()
            return False
    
    def test_multiple_concurrent_connections(self):
        """Test multiple concurrent connections through port forwarding."""
        print("\n" + "=" * 60)
        print("Testing multiple concurrent connections...")
        print("=" * 60)
        
        try:
            # Create echo server
            echo_port = self.find_free_port()
            echo_thread = self.create_echo_server(echo_port)
            print(f"✓ Echo server created on port {echo_port}")
            
            # Create mock transport
            mock_transport = MockTransport()
            
            # Create local port forwarder
            local_forwarder = LocalPortForwarder(mock_transport)
            
            # Create tunnel
            local_port = self.find_free_port()
            tunnel_id = local_forwarder.create_tunnel(
                local_port=local_port,
                remote_host="127.0.0.1",
                remote_port=echo_port
            )
            print(f"✓ Local tunnel created: {local_port} -> 127.0.0.1:{echo_port}")
            
            time.sleep(1)
            
            # Test multiple concurrent connections
            print("Testing 3 concurrent connections...")
            
            def test_connection(conn_id):
                """Test a single connection."""
                try:
                    test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    test_socket.settimeout(10)
                    test_socket.connect(('127.0.0.1', local_port))
                    
                    test_message = f"Message from connection {conn_id}".encode()
                    test_socket.sendall(test_message)
                    
                    response = test_socket.recv(1024)
                    expected = b"ECHO: " + test_message
                    
                    test_socket.close()
                    
                    if response == expected:
                        print(f"  ✓ Connection {conn_id} successful")
                        return True
                    else:
                        print(f"  ✗ Connection {conn_id} response mismatch")
                        return False
                        
                except Exception as e:
                    print(f"  ✗ Connection {conn_id} failed: {e}")
                    return False
            
            # Run concurrent connections
            threads = []
            results = [False] * 3
            
            def run_test(conn_id):
                results[conn_id] = test_connection(conn_id)
            
            for i in range(3):
                thread = threading.Thread(target=run_test, args=(i,))
                threads.append(thread)
                thread.start()
            
            # Wait for all threads to complete
            for thread in threads:
                thread.join()
            
            # Check results
            successful_connections = sum(results)
            print(f"✓ {successful_connections}/3 concurrent connections successful")
            
            if successful_connections == 3:
                print("✓ All concurrent connections successful")
            else:
                print(f"✗ Only {successful_connections}/3 connections successful")
                return False
            
            # Clean up
            local_forwarder.close_tunnel(tunnel_id)
            print("✓ Tunnel closed")
            
            return True
            
        except Exception as e:
            print(f"✗ Multiple concurrent connections test failed: {e}")
            traceback.print_exc()
            return False

def main():
    """Run all integration tests."""
    print("SpindleX Port Forwarding Integration Tests")
    print("=" * 60)
    print("Testing port forwarding with real data transmission")
    print("=" * 60)
    
    tester = IntegrationTester()
    
    tests = [
        ("Local Port Forwarding with Echo Server", tester.test_local_port_forwarding_with_echo_server),
        ("Local Port Forwarding with HTTP Server", tester.test_local_port_forwarding_with_http_server),
        ("Multiple Concurrent Connections", tester.test_multiple_concurrent_connections),
    ]
    
    results = []
    
    for test_name, test_func in tests:
        print(f"\n{'='*20} Starting: {test_name} {'='*20}")
        try:
            result = test_func()
            results.append((test_name, result))
            
            if result:
                print(f"✓ {test_name}: PASSED")
            else:
                print(f"✗ {test_name}: FAILED")
                
        except Exception as e:
            print(f"✗ Test '{test_name}' crashed: {e}")
            traceback.print_exc()
            results.append((test_name, False))
    
    # Print final summary
    print("\n" + "=" * 80)
    print("FINAL TEST SUMMARY")
    print("=" * 80)
    
    passed = 0
    total = len(results)
    
    for test_name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {test_name:<40} {status}")
        if result:
            passed += 1
    
    print("-" * 80)
    print(f"Results: {passed}/{total} tests passed ({passed/total*100:.1f}%)")
    
    if passed == total:
        print("🎉 All tests passed! Port forwarding data transmission is working correctly.")
        print("\nNote: These tests validate port forwarding with actual data transmission")
        print("using local test servers to demonstrate tunnel functionality.")
        return 0
    else:
        print("❌ Some tests failed! Check the output above for details.")
        return 1

if __name__ == "__main__":
    sys.exit(main())