Performance Guide
================

This guide covers performance optimization techniques, benchmarking, and best practices for achieving optimal performance with SSH Library.

Performance Overview
--------------------

SSH Library is designed for high performance while maintaining security. Key performance factors include:

- **Connection Management**: Efficient connection pooling and reuse
- **Cryptographic Operations**: Hardware acceleration and algorithm selection
- **Data Transfer**: Optimized buffering and parallel operations
- **Memory Usage**: Efficient memory management and streaming
- **Network Utilization**: Compression and pipelining

Benchmarking and Profiling
--------------------------

Built-in Performance Monitoring
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SSH Library includes built-in performance monitoring::

    from ssh_library.logging.monitoring import PerformanceMonitor
    from ssh_library import SSHClient
    import time
    
    # Enable performance monitoring
    monitor = PerformanceMonitor()
    
    client = SSHClient()
    
    # Time connection establishment
    with monitor.time_operation('ssh_connect'):
        client.connect('server.example.com', username='user', pkey=private_key)
    
    # Time command execution
    with monitor.time_operation('command_execution'):
        stdin, stdout, stderr = client.exec_command('ls -la')
        output = stdout.read()
    
    # Time file transfer
    with monitor.time_operation('file_transfer'):
        sftp = client.open_sftp()
        sftp.put('/local/file.txt', '/remote/file.txt')
        sftp.close()
    
    # Get performance statistics
    stats = monitor.get_statistics()
    
    for operation, metrics in stats.items():
        print(f"{operation}:")
        print(f"  Average: {metrics['avg']:.3f}s")
        print(f"  Min: {metrics['min']:.3f}s")
        print(f"  Max: {metrics['max']:.3f}s")
        print(f"  Count: {metrics['count']}")

Custom Benchmarking
~~~~~~~~~~~~~~~~~~~

Create custom benchmarks for your use case::

    import time
    import statistics
    from ssh_library import SSHClient
    from ssh_library.crypto.pkey import Ed25519Key
    
    class SSHBenchmark:
        def __init__(self, hostname, username, private_key_path):
            self.hostname = hostname
            self.username = username
            self.private_key = Ed25519Key.from_private_key_file(private_key_path)
        
        def benchmark_connection(self, iterations=10):
            """Benchmark connection establishment."""
            times = []
            
            for i in range(iterations):
                client = SSHClient()
                
                start_time = time.time()
                client.connect(
                    hostname=self.hostname,
                    username=self.username,
                    pkey=self.private_key
                )
                end_time = time.time()
                
                times.append(end_time - start_time)
                client.close()
            
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'stdev': statistics.stdev(times) if len(times) > 1 else 0,
                'min': min(times),
                'max': max(times),
                'iterations': iterations
            }
        
        def benchmark_command_execution(self, command='echo "test"', iterations=100):
            """Benchmark command execution."""
            client = SSHClient()
            client.connect(
                hostname=self.hostname,
                username=self.username,
                pkey=self.private_key
            )
            
            times = []
            
            try:
                for i in range(iterations):
                    start_time = time.time()
                    stdin, stdout, stderr = client.exec_command(command)
                    output = stdout.read()
                    end_time = time.time()
                    
                    times.append(end_time - start_time)
            
            finally:
                client.close()
            
            return {
                'mean': statistics.mean(times),
                'median': statistics.median(times),
                'stdev': statistics.stdev(times) if len(times) > 1 else 0,
                'min': min(times),
                'max': max(times),
                'iterations': iterations,
                'commands_per_second': iterations / sum(times)
            }
        
        def benchmark_file_transfer(self, file_sizes=[1024, 10240, 102400, 1048576]):
            """Benchmark file transfer performance."""
            import tempfile
            import os
            
            client = SSHClient()
            client.connect(
                hostname=self.hostname,
                username=self.username,
                pkey=self.private_key
            )
            
            results = {}
            
            try:
                sftp = client.open_sftp()
                
                for size in file_sizes:
                    # Create test file
                    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                        temp_file.write(b'x' * size)
                        local_path = temp_file.name
                    
                    remote_path = f'/tmp/benchmark_file_{size}'
                    
                    try:
                        # Upload benchmark
                        start_time = time.time()
                        sftp.put(local_path, remote_path)
                        upload_time = time.time() - start_time
                        
                        # Download benchmark
                        download_path = local_path + '_download'
                        start_time = time.time()
                        sftp.get(remote_path, download_path)
                        download_time = time.time() - start_time
                        
                        results[size] = {
                            'upload_time': upload_time,
                            'download_time': download_time,
                            'upload_rate_mbps': (size / upload_time) / (1024 * 1024),
                            'download_rate_mbps': (size / download_time) / (1024 * 1024)
                        }
                        
                        # Cleanup
                        sftp.remove(remote_path)
                        os.unlink(download_path)
                    
                    finally:
                        os.unlink(local_path)
                
                sftp.close()
            
            finally:
                client.close()
            
            return results
    
    # Usage
    benchmark = SSHBenchmark('server.example.com', 'user', '/path/to/key')
    
    # Run benchmarks
    connection_stats = benchmark.benchmark_connection()
    print(f"Connection time: {connection_stats['mean']:.3f}s ± {connection_stats['stdev']:.3f}s")
    
    command_stats = benchmark.benchmark_command_execution()
    print(f"Command execution: {command_stats['commands_per_second']:.1f} commands/sec")
    
    transfer_stats = benchmark.benchmark_file_transfer()
    for size, stats in transfer_stats.items():
        print(f"File size {size} bytes:")
        print(f"  Upload: {stats['upload_rate_mbps']:.2f} MB/s")
        print(f"  Download: {stats['download_rate_mbps']:.2f} MB/s")

Connection Optimization
-----------------------

Connection Pooling
~~~~~~~~~~~~~~~~~~

Implement connection pooling for better performance::

    import threading
    import queue
    import time
    from ssh_library import SSHClient
    from ssh_library.crypto.pkey import Ed25519Key
    
    class SSHConnectionPool:
        def __init__(self, hostname, username, private_key_path, 
                     pool_size=5, max_idle_time=300):
            self.hostname = hostname
            self.username = username
            self.private_key = Ed25519Key.from_private_key_file(private_key_path)
            self.pool_size = pool_size
            self.max_idle_time = max_idle_time
            
            self.pool = queue.Queue(maxsize=pool_size)
            self.active_connections = {}
            self.lock = threading.Lock()
            
            # Start cleanup thread
            self.cleanup_thread = threading.Thread(target=self._cleanup_idle_connections, daemon=True)
            self.cleanup_thread.start()
        
        def get_connection(self, timeout=30):
            """Get connection from pool or create new one."""
            try:
                # Try to get existing connection from pool
                connection_info = self.pool.get_nowait()
                client = connection_info['client']
                
                # Test if connection is still alive
                if self._test_connection(client):
                    with self.lock:
                        self.active_connections[id(client)] = time.time()
                    return client
                else:
                    # Connection is dead, close it
                    try:
                        client.close()
                    except:
                        pass
            
            except queue.Empty:
                pass
            
            # Create new connection
            client = SSHClient()
            client.connect(
                hostname=self.hostname,
                username=self.username,
                pkey=self.private_key,
                timeout=timeout
            )
            
            with self.lock:
                self.active_connections[id(client)] = time.time()
            
            return client
        
        def return_connection(self, client):
            """Return connection to pool."""
            with self.lock:
                if id(client) in self.active_connections:
                    del self.active_connections[id(client)]
            
            if self._test_connection(client):
                try:
                    self.pool.put_nowait({
                        'client': client,
                        'last_used': time.time()
                    })
                except queue.Full:
                    # Pool is full, close connection
                    client.close()
            else:
                # Connection is dead, close it
                try:
                    client.close()
                except:
                    pass
        
        def _test_connection(self, client):
            """Test if connection is still alive."""
            try:
                transport = client.get_transport()
                return transport and transport.is_active()
            except:
                return False
        
        def _cleanup_idle_connections(self):
            """Clean up idle connections."""
            while True:
                time.sleep(60)  # Check every minute
                
                current_time = time.time()
                connections_to_close = []
                
                # Check pooled connections
                temp_queue = queue.Queue()
                
                while not self.pool.empty():
                    try:
                        connection_info = self.pool.get_nowait()
                        
                        if current_time - connection_info['last_used'] > self.max_idle_time:
                            connections_to_close.append(connection_info['client'])
                        else:
                            temp_queue.put(connection_info)
                    
                    except queue.Empty:
                        break
                
                # Put back non-expired connections
                while not temp_queue.empty():
                    self.pool.put(temp_queue.get())
                
                # Close expired connections
                for client in connections_to_close:
                    try:
                        client.close()
                    except:
                        pass
        
        def close_all(self):
            """Close all connections in pool."""
            # Close pooled connections
            while not self.pool.empty():
                try:
                    connection_info = self.pool.get_nowait()
                    connection_info['client'].close()
                except:
                    pass
            
            # Close active connections
            with self.lock:
                for client_id in list(self.active_connections.keys()):
                    # Note: This doesn't actually close active connections
                    # as they might be in use. In a real implementation,
                    # you'd need a more sophisticated approach.
                    pass
    
    # Usage
    pool = SSHConnectionPool('server.example.com', 'user', '/path/to/key')
    
    # Use connection from pool
    client = pool.get_connection()
    try:
        stdin, stdout, stderr = client.exec_command('ls -la')
        output = stdout.read()
    finally:
        pool.return_connection(client)

Connection Reuse
~~~~~~~~~~~~~~~~

Reuse connections for multiple operations::

    class SSHSession:
        def __init__(self, hostname, username, private_key_path):
            self.hostname = hostname
            self.username = username
            self.private_key = Ed25519Key.from_private_key_file(private_key_path)
            self.client = None
            self.sftp = None
        
        def __enter__(self):
            self.connect()
            return self
        
        def __exit__(self, exc_type, exc_val, exc_tb):
            self.close()
        
        def connect(self):
            """Establish connection."""
            if not self.client or not self.client.get_transport().is_active():
                self.client = SSHClient()
                self.client.connect(
                    hostname=self.hostname,
                    username=self.username,
                    pkey=self.private_key
                )
        
        def get_sftp(self):
            """Get SFTP session (reuse existing if available)."""
            if not self.sftp or self.sftp.sock.closed:
                self.sftp = self.client.open_sftp()
            return self.sftp
        
        def exec_command(self, command):
            """Execute command."""
            self.connect()  # Ensure connection is active
            return self.client.exec_command(command)
        
        def close(self):
            """Close all connections."""
            if self.sftp:
                self.sftp.close()
                self.sftp = None
            
            if self.client:
                self.client.close()
                self.client = None
    
    # Usage - single connection for multiple operations
    with SSHSession('server.example.com', 'user', '/path/to/key') as session:
        # Execute multiple commands
        for i in range(10):
            stdin, stdout, stderr = session.exec_command(f'echo "Command {i}"')
            print(stdout.read().decode().strip())
        
        # File operations
        sftp = session.get_sftp()
        sftp.put('/local/file1.txt', '/remote/file1.txt')
        sftp.put('/local/file2.txt', '/remote/file2.txt')
        
        # More commands
        stdin, stdout, stderr = session.exec_command('ls -la /remote/')
        print(stdout.read().decode())

Cryptographic Optimization
--------------------------

Algorithm Selection
~~~~~~~~~~~~~~~~~~~

Choose optimal cryptographic algorithms::

    from ssh_library import SSHClient
    from ssh_library.crypto.backend import get_crypto_backend
    
    # Get available algorithms
    backend = get_crypto_backend()
    
    print("Available ciphers:", backend.get_supported_ciphers())
    print("Available MACs:", backend.get_supported_macs())
    print("Available KEX algorithms:", backend.get_supported_kex())
    
    # Configure client with preferred algorithms
    client = SSHClient()
    
    # Set algorithm preferences (fastest to slowest)
    client.set_preferred_ciphers([
        'chacha20-poly1305@openssh.com',  # Fast AEAD cipher
        'aes256-gcm@openssh.com',         # Hardware accelerated on modern CPUs
        'aes128-gcm@openssh.com',         # Faster than AES-256 on older hardware
        'aes256-ctr',                     # Fallback
        'aes128-ctr'
    ])
    
    client.set_preferred_macs([
        'hmac-sha2-256-etm@openssh.com',  # Encrypt-then-MAC
        'hmac-sha2-256',
        'hmac-sha1'
    ])
    
    client.set_preferred_kex([
        'curve25519-sha256@libssh.org',   # Fast elliptic curve
        'ecdh-sha2-nistp256',             # NIST curve
        'diffie-hellman-group14-sha256'   # Fallback
    ])
    
    client.connect('server.example.com', username='user', pkey=private_key)

Hardware Acceleration
~~~~~~~~~~~~~~~~~~~~~

Leverage hardware acceleration when available::

    from ssh_library.crypto.backend import CryptographyBackend
    
    # Check for hardware acceleration support
    backend = CryptographyBackend()
    
    if backend.has_aes_ni_support():
        print("AES-NI hardware acceleration available")
        # Prefer AES-GCM ciphers
        preferred_ciphers = [
            'aes256-gcm@openssh.com',
            'aes128-gcm@openssh.com',
            'chacha20-poly1305@openssh.com'
        ]
    else:
        print("No AES-NI support, preferring ChaCha20")
        # Prefer ChaCha20 on systems without AES-NI
        preferred_ciphers = [
            'chacha20-poly1305@openssh.com',
            'aes256-ctr',
            'aes128-ctr'
        ]
    
    client = SSHClient()
    client.set_preferred_ciphers(preferred_ciphers)

Data Transfer Optimization
--------------------------

Buffering and Streaming
~~~~~~~~~~~~~~~~~~~~~~~

Optimize data transfer with proper buffering::

    def optimized_file_transfer(client, local_path, remote_path, 
                               chunk_size=256*1024, window_size=2*1024*1024):
        """Transfer file with optimized buffering."""
        
        sftp = client.open_sftp()
        
        # Configure SFTP parameters
        sftp.get_channel().settimeout(300)  # 5 minute timeout
        sftp.get_channel().set_combine_stderr(True)
        
        # Set window size for better throughput
        transport = client.get_transport()
        transport.set_window_size(window_size)
        
        try:
            # Stream transfer with optimal chunk size
            with open(local_path, 'rb') as local_file:
                with sftp.open(remote_path, 'wb') as remote_file:
                    # Enable write-ahead buffering
                    remote_file.set_pipelined(True)
                    
                    while True:
                        chunk = local_file.read(chunk_size)
                        if not chunk:
                            break
                        remote_file.write(chunk)
        
        finally:
            sftp.close()

Compression
~~~~~~~~~~~

Use compression for text files and slow connections::

    from ssh_library import SSHClient
    
    client = SSHClient()
    
    # Enable compression
    client.set_compression(True)
    
    # Set compression level (1-9, higher = better compression, slower)
    client.set_compression_level(6)
    
    client.connect('server.example.com', username='user', pkey=private_key)
    
    # Compression is most effective for text files
    sftp = client.open_sftp()
    sftp.put('/local/large_text_file.log', '/remote/large_text_file.log')

Parallel Operations
~~~~~~~~~~~~~~~~~~~

Use parallel transfers for multiple files::

    import concurrent.futures
    import threading
    
    def parallel_file_upload(client, file_pairs, max_workers=4):
        """Upload multiple files in parallel."""
        
        # Create thread-local SFTP sessions
        thread_local = threading.local()
        
        def get_sftp():
            if not hasattr(thread_local, 'sftp'):
                thread_local.sftp = client.open_sftp()
            return thread_local.sftp
        
        def upload_file(local_path, remote_path):
            sftp = get_sftp()
            start_time = time.time()
            sftp.put(local_path, remote_path)
            return {
                'local_path': local_path,
                'remote_path': remote_path,
                'duration': time.time() - start_time,
                'size': os.path.getsize(local_path)
            }
        
        results = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all upload tasks
            future_to_file = {
                executor.submit(upload_file, local, remote): (local, remote)
                for local, remote in file_pairs
            }
            
            # Collect results
            for future in concurrent.futures.as_completed(future_to_file):
                try:
                    result = future.result()
                    results.append(result)
                    
                    rate_mbps = (result['size'] / result['duration']) / (1024 * 1024)
                    print(f"Uploaded {result['local_path']}: {rate_mbps:.2f} MB/s")
                    
                except Exception as e:
                    local_path, remote_path = future_to_file[future]
                    print(f"Upload failed {local_path}: {e}")
        
        return results

Memory Optimization
-------------------

Streaming Large Files
~~~~~~~~~~~~~~~~~~~~~

Handle large files without loading into memory::

    def stream_large_file(client, local_path, remote_path, chunk_size=1024*1024):
        """Stream large file transfer to minimize memory usage."""
        
        sftp = client.open_sftp()
        
        try:
            file_size = os.path.getsize(local_path)
            transferred = 0
            
            with open(local_path, 'rb') as local_file:
                with sftp.open(remote_path, 'wb') as remote_file:
                    while transferred < file_size:
                        # Read chunk
                        remaining = file_size - transferred
                        current_chunk_size = min(chunk_size, remaining)
                        
                        chunk = local_file.read(current_chunk_size)
                        if not chunk:
                            break
                        
                        # Write chunk
                        remote_file.write(chunk)
                        transferred += len(chunk)
                        
                        # Progress reporting
                        progress = (transferred / file_size) * 100
                        print(f"Progress: {progress:.1f}% ({transferred}/{file_size} bytes)")
        
        finally:
            sftp.close()

Memory Pool Management
~~~~~~~~~~~~~~~~~~~~~~

Implement memory pools for frequent operations::

    import io
    from collections import deque
    
    class BufferPool:
        def __init__(self, buffer_size=64*1024, pool_size=10):
            self.buffer_size = buffer_size
            self.pool = deque()
            
            # Pre-allocate buffers
            for _ in range(pool_size):
                self.pool.append(bytearray(buffer_size))
        
        def get_buffer(self):
            """Get buffer from pool or create new one."""
            if self.pool:
                return self.pool.popleft()
            else:
                return bytearray(self.buffer_size)
        
        def return_buffer(self, buffer):
            """Return buffer to pool."""
            if len(buffer) == self.buffer_size:
                # Clear buffer and return to pool
                buffer[:] = b'\x00' * self.buffer_size
                self.pool.append(buffer)
    
    # Global buffer pool
    buffer_pool = BufferPool()
    
    def efficient_file_copy(sftp, source_path, dest_path):
        """Copy file using buffer pool."""
        buffer = buffer_pool.get_buffer()
        
        try:
            with sftp.open(source_path, 'rb') as src:
                with sftp.open(dest_path, 'wb') as dst:
                    while True:
                        bytes_read = src.readinto(buffer)
                        if bytes_read == 0:
                            break
                        dst.write(buffer[:bytes_read])
        
        finally:
            buffer_pool.return_buffer(buffer)

Network Optimization
--------------------

TCP Tuning
~~~~~~~~~~

Optimize TCP settings for better performance::

    import socket
    from ssh_library import SSHClient
    
    def create_optimized_socket(hostname, port=22):
        """Create socket with optimized TCP settings."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Enable TCP_NODELAY to reduce latency
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        
        # Set socket buffer sizes
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 256*1024)  # 256KB send buffer
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 256*1024)  # 256KB receive buffer
        
        # Set keepalive options
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        
        # Platform-specific keepalive settings
        if hasattr(socket, 'TCP_KEEPIDLE'):
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)    # Start after 60s
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)   # Interval 10s
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)      # 3 probes
        
        sock.connect((hostname, port))
        return sock
    
    # Use optimized socket with SSH client
    sock = create_optimized_socket('server.example.com')
    client = SSHClient()
    client.connect_with_socket(sock, username='user', pkey=private_key)

Bandwidth Management
~~~~~~~~~~~~~~~~~~~~

Implement bandwidth throttling when needed::

    import time
    
    class BandwidthThrottler:
        def __init__(self, max_bytes_per_second):
            self.max_bytes_per_second = max_bytes_per_second
            self.last_time = time.time()
            self.bytes_sent = 0
        
        def throttle(self, bytes_to_send):
            """Throttle bandwidth usage."""
            current_time = time.time()
            time_elapsed = current_time - self.last_time
            
            if time_elapsed >= 1.0:
                # Reset counter every second
                self.bytes_sent = 0
                self.last_time = current_time
            
            # Check if we need to throttle
            if self.bytes_sent + bytes_to_send > self.max_bytes_per_second:
                sleep_time = 1.0 - time_elapsed
                if sleep_time > 0:
                    time.sleep(sleep_time)
                
                # Reset after sleep
                self.bytes_sent = 0
                self.last_time = time.time()
            
            self.bytes_sent += bytes_to_send
    
    def throttled_file_upload(client, local_path, remote_path, max_mbps=10):
        """Upload file with bandwidth throttling."""
        throttler = BandwidthThrottler(max_mbps * 1024 * 1024)  # Convert to bytes/sec
        
        sftp = client.open_sftp()
        
        try:
            with open(local_path, 'rb') as local_file:
                with sftp.open(remote_path, 'wb') as remote_file:
                    chunk_size = 64 * 1024  # 64KB chunks
                    
                    while True:
                        chunk = local_file.read(chunk_size)
                        if not chunk:
                            break
                        
                        throttler.throttle(len(chunk))
                        remote_file.write(chunk)
        
        finally:
            sftp.close()

Performance Monitoring
----------------------

Real-time Monitoring
~~~~~~~~~~~~~~~~~~~

Monitor performance in real-time::

    import threading
    import time
    from collections import deque
    
    class PerformanceTracker:
        def __init__(self, window_size=60):
            self.window_size = window_size
            self.metrics = {
                'bytes_sent': deque(maxlen=window_size),
                'bytes_received': deque(maxlen=window_size),
                'operations': deque(maxlen=window_size),
                'timestamps': deque(maxlen=window_size)
            }
            self.lock = threading.Lock()
            
            # Start monitoring thread
            self.monitoring = True
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()
        
        def record_transfer(self, bytes_sent=0, bytes_received=0, operations=0):
            """Record transfer metrics."""
            with self.lock:
                current_time = time.time()
                self.metrics['bytes_sent'].append(bytes_sent)
                self.metrics['bytes_received'].append(bytes_received)
                self.metrics['operations'].append(operations)
                self.metrics['timestamps'].append(current_time)
        
        def get_current_rates(self):
            """Get current transfer rates."""
            with self.lock:
                if len(self.metrics['timestamps']) < 2:
                    return {'send_rate': 0, 'receive_rate': 0, 'ops_rate': 0}
                
                time_window = self.metrics['timestamps'][-1] - self.metrics['timestamps'][0]
                if time_window == 0:
                    return {'send_rate': 0, 'receive_rate': 0, 'ops_rate': 0}
                
                total_sent = sum(self.metrics['bytes_sent'])
                total_received = sum(self.metrics['bytes_received'])
                total_ops = sum(self.metrics['operations'])
                
                return {
                    'send_rate': total_sent / time_window,
                    'receive_rate': total_received / time_window,
                    'ops_rate': total_ops / time_window
                }
        
        def _monitor_loop(self):
            """Background monitoring loop."""
            while self.monitoring:
                rates = self.get_current_rates()
                
                print(f"Send: {rates['send_rate']/1024/1024:.2f} MB/s, "
                      f"Receive: {rates['receive_rate']/1024/1024:.2f} MB/s, "
                      f"Ops: {rates['ops_rate']:.1f}/s")
                
                time.sleep(5)  # Update every 5 seconds
        
        def stop(self):
            """Stop monitoring."""
            self.monitoring = False

Profiling Integration
~~~~~~~~~~~~~~~~~~~~

Integrate with Python profiling tools::

    import cProfile
    import pstats
    import io
    
    def profile_ssh_operations(func, *args, **kwargs):
        """Profile SSH operations."""
        profiler = cProfile.Profile()
        
        # Run function with profiling
        profiler.enable()
        result = func(*args, **kwargs)
        profiler.disable()
        
        # Generate report
        s = io.StringIO()
        ps = pstats.Stats(profiler, stream=s)
        ps.sort_stats('cumulative')
        ps.print_stats(20)  # Top 20 functions
        
        print("Profiling Results:")
        print(s.getvalue())
        
        return result
    
    # Usage
    def ssh_workload():
        client = SSHClient()
        client.connect('server.example.com', username='user', pkey=private_key)
        
        # Perform operations
        for i in range(10):
            stdin, stdout, stderr = client.exec_command(f'echo "test {i}"')
            output = stdout.read()
        
        client.close()
    
    # Profile the workload
    profile_ssh_operations(ssh_workload)

Best Practices Summary
---------------------

Connection Management
~~~~~~~~~~~~~~~~~~~~

1. **Use connection pooling** for applications with multiple SSH operations
2. **Reuse connections** when performing multiple operations
3. **Set appropriate timeouts** to avoid hanging connections
4. **Monitor connection health** and reconnect when necessary

Cryptographic Performance
~~~~~~~~~~~~~~~~~~~~~~~~

1. **Choose modern algorithms** (Ed25519, ChaCha20-Poly1305, AES-GCM)
2. **Leverage hardware acceleration** when available
3. **Use appropriate key sizes** (balance security and performance)
4. **Enable compression** for text data over slow connections

Data Transfer
~~~~~~~~~~~~~

1. **Use optimal chunk sizes** (64KB-256KB for most cases)
2. **Implement parallel transfers** for multiple files
3. **Stream large files** to minimize memory usage
4. **Set appropriate buffer sizes** based on network conditions

Monitoring and Optimization
~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Benchmark your specific use case** regularly
2. **Monitor performance metrics** in production
3. **Profile bottlenecks** and optimize accordingly
4. **Test different configurations** for your environment

Platform-Specific Optimizations
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. **Tune TCP settings** for your network environment
2. **Use platform-specific optimizations** (epoll on Linux, IOCP on Windows)
3. **Consider NUMA topology** for multi-socket systems
4. **Optimize for your specific hardware** (CPU, network, storage)