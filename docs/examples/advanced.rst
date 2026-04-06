Advanced Examples
=================

This section provides advanced usage examples for SpindleX, including async operations, custom protocols, and complex integrations.

Async SSH Operations
--------------------

Async SSH Client::

    #!/usr/bin/env python3
    """
    Asynchronous SSH operations for high-performance applications.
    """
    
    import asyncio
    import aiofiles
    from spindlex.async_client import AsyncSSHClient
    from spindlex.exceptions import SSHException
    from typing import List, Dict, Any, Optional
    import time
    
    class AsyncSSHManager:
        def __init__(self, max_concurrent: int = 10):
            self.max_concurrent = max_concurrent
            self.semaphore = asyncio.Semaphore(max_concurrent)
        
        async def execute_on_multiple_servers(self, 
                                            servers: List[Dict[str, Any]], 
                                            command: str) -> Dict[str, Any]:
            """Execute command on multiple servers concurrently."""
            tasks = []
            
            for server in servers:
                task = asyncio.create_task(
                    self.execute_on_server(server, command)
                )
                tasks.append(task)
            
            # Wait for all tasks to complete
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            output = {}
            for i, result in enumerate(results):
                hostname = servers[i]['hostname']
                if isinstance(result, Exception):
                    output[hostname] = {
                        'success': False,
                        'error': str(result)
                    }
                else:
                    output[hostname] = result
            
            return output
        
        async def execute_on_server(self, server: Dict[str, Any], command: str) -> Dict[str, Any]:
            """Execute command on a single server with concurrency control."""
            async with self.semaphore:
                client = AsyncSSHClient()
                
                try:
                    # Connect to server
                    await client.connect(
                        hostname=server['hostname'],
                        username=server['username'],
                        password=server.get('password'),
                        pkey=server.get('private_key'),
                        timeout=30
                    )
                    
                    # Execute command
                    result = await client.exec_command(command)
                    
                    return {
                        'success': True,
                        'stdout': result.stdout,
                        'stderr': result.stderr,
                        'exit_code': result.exit_code,
                        'execution_time': result.execution_time
                    }
                    
                except Exception as e:
                    return {
                        'success': False,
                        'error': str(e)
                    }
                
                finally:
                    await client.close()
        
        async def parallel_file_transfer(self, 
                                       transfers: List[Dict[str, Any]]) -> Dict[str, Any]:
            """Perform multiple file transfers in parallel."""
            tasks = []
            
            for transfer in transfers:
                task = asyncio.create_task(
                    self.transfer_file(transfer)
                )
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            output = {}
            for i, result in enumerate(results):
                transfer_id = transfers[i].get('id', f'transfer_{i}')
                if isinstance(result, Exception):
                    output[transfer_id] = {
                        'success': False,
                        'error': str(result)
                    }
                else:
                    output[transfer_id] = result
            
            return output
        
        async def transfer_file(self, transfer: Dict[str, Any]) -> Dict[str, Any]:
            """Transfer a single file."""
            async with self.semaphore:
                client = AsyncSSHClient()
                
                try:
                    await client.connect(
                        hostname=transfer['hostname'],
                        username=transfer['username'],
                        password=transfer.get('password'),
                        pkey=transfer.get('private_key')
                    )
                    
                    sftp = await client.open_sftp()
                    
                    start_time = time.time()
                    
                    if transfer['direction'] == 'upload':
                        await sftp.put(transfer['local_path'], transfer['remote_path'])
                    elif transfer['direction'] == 'download':
                        await sftp.get(transfer['remote_path'], transfer['local_path'])
                    else:
                        raise ValueError(f"Invalid direction: {transfer['direction']}")
                    
                    end_time = time.time()
                    
                    # Get file size for transfer rate calculation
                    if transfer['direction'] == 'upload':
                        file_size = await aiofiles.os.path.getsize(transfer['local_path'])
                    else:
                        stat_result = await sftp.stat(transfer['remote_path'])
                        file_size = stat_result.st_size
                    
                    transfer_time = end_time - start_time
                    transfer_rate = file_size / transfer_time if transfer_time > 0 else 0
                    
                    return {
                        'success': True,
                        'file_size': file_size,
                        'transfer_time': transfer_time,
                        'transfer_rate_bps': transfer_rate
                    }
                    
                except Exception as e:
                    return {
                        'success': False,
                        'error': str(e)
                    }
                
                finally:
                    await client.close()
        
        async def stream_command_output(self, 
                                      server: Dict[str, Any], 
                                      command: str,
                                      callback: Optional[callable] = None) -> Dict[str, Any]:
            """Stream command output in real-time."""
            client = AsyncSSHClient()
            
            try:
                await client.connect(
                    hostname=server['hostname'],
                    username=server['username'],
                    password=server.get('password'),
                    pkey=server.get('private_key')
                )
                
                # Start command execution
                channel = await client.open_channel('session')
                await channel.exec_command(command)
                
                stdout_data = []
                stderr_data = []
                
                # Stream output
                while not channel.exit_status_ready():
                    # Check for stdout data
                    if channel.recv_ready():
                        data = await channel.recv(1024)
                        stdout_data.append(data)
                        if callback:
                            await callback('stdout', data)
                    
                    # Check for stderr data
                    if channel.recv_stderr_ready():
                        data = await channel.recv_stderr(1024)
                        stderr_data.append(data)
                        if callback:
                            await callback('stderr', data)
                    
                    # Small delay to prevent busy waiting
                    await asyncio.sleep(0.01)
                
                # Get final output
                while channel.recv_ready():
                    data = await channel.recv(1024)
                    stdout_data.append(data)
                    if callback:
                        await callback('stdout', data)
                
                while channel.recv_stderr_ready():
                    data = await channel.recv_stderr(1024)
                    stderr_data.append(data)
                    if callback:
                        await callback('stderr', data)
                
                exit_code = channel.recv_exit_status()
                
                return {
                    'success': True,
                    'stdout': b''.join(stdout_data).decode('utf-8'),
                    'stderr': b''.join(stderr_data).decode('utf-8'),
                    'exit_code': exit_code
                }
                
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e)
                }
            
            finally:
                await client.close()
    
    # Usage examples
    async def main():
        manager = AsyncSSHManager(max_concurrent=5)
        
        servers = [
            {
                'hostname': 'server1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key'
            },
            {
                'hostname': 'server2.example.com',
                'username': 'admin',
                'private_key': '/path/to/key'
            },
            {
                'hostname': 'server3.example.com',
                'username': 'admin',
                'private_key': '/path/to/key'
            }
        ]
        
        # Execute command on multiple servers
        print("Executing command on multiple servers...")
        results = await manager.execute_on_multiple_servers(servers, 'uname -a')
        
        for hostname, result in results.items():
            if result['success']:
                print(f"{hostname}: {result['stdout'].strip()}")
            else:
                print(f"{hostname}: ERROR - {result['error']}")
        
        # Parallel file transfers
        transfers = [
            {
                'id': 'config_upload_1',
                'hostname': 'server1.example.com',
                'username': 'admin',
                'private_key': '/path/to/key',
                'direction': 'upload',
                'local_path': './config.txt',
                'remote_path': '/tmp/config.txt'
            },
            {
                'id': 'log_download_1',
                'hostname': 'server2.example.com',
                'username': 'admin',
                'private_key': '/path/to/key',
                'direction': 'download',
                'remote_path': '/var/log/app.log',
                'local_path': './server2_app.log'
            }
        ]
        
        print("\nPerforming parallel file transfers...")
        transfer_results = await manager.parallel_file_transfer(transfers)
        
        for transfer_id, result in transfer_results.items():
            if result['success']:
                rate_mbps = result['transfer_rate_bps'] / (1024 * 1024)
                print(f"{transfer_id}: {result['file_size']} bytes in {result['transfer_time']:.2f}s ({rate_mbps:.2f} MB/s)")
            else:
                print(f"{transfer_id}: ERROR - {result['error']}")
        
        # Stream command output
        async def output_callback(stream_type, data):
            print(f"[{stream_type}] {data.decode('utf-8')}", end='')
        
        print("\nStreaming command output...")
        stream_result = await manager.stream_command_output(
            servers[0], 
            'for i in {1..5}; do echo "Line $i"; sleep 1; done',
            callback=output_callback
        )
        
        print(f"\nCommand completed with exit code: {stream_result.get('exit_code', 'unknown')}")
    
    # Run the async example
    if __name__ == "__main__":
        asyncio.run(main())

Custom Protocol Implementation
------------------------------

Custom SSH Subsystem::

    #!/usr/bin/env python3
    """
    Custom SSH subsystem implementation for specialized protocols.
    """
    
    import json
    import struct
    from spindlex.server import SSHServer, SFTPServer
    from spindlex.transport.channel import Channel
    from spindlex.exceptions import SSHException
    from typing import Dict, Any, Optional, Callable
    import threading
    import queue
    
    class CustomProtocolServer(SSHServer):
        """Custom SSH server with specialized subsystem support."""
        
        def __init__(self):
            super().__init__()
            self.subsystem_handlers = {
                'custom-api': CustomAPISubsystem,
                'file-sync': FileSyncSubsystem,
                'remote-shell': RemoteShellSubsystem
            }
            self.active_sessions = {}
        
        def check_channel_subsystem_request(self, channel: Channel, name: str) -> bool:
            """Handle subsystem requests."""
            if name in self.subsystem_handlers:
                # Create subsystem handler
                handler_class = self.subsystem_handlers[name]
                handler = handler_class(channel, self)
                
                # Start handler in separate thread
                thread = threading.Thread(
                    target=handler.start,
                    daemon=True
                )
                thread.start()
                
                # Track active session
                self.active_sessions[channel] = {
                    'subsystem': name,
                    'handler': handler,
                    'thread': thread
                }
                
                return True
            
            return False
        
        def channel_closed(self, channel: Channel):
            """Clean up when channel is closed."""
            if channel in self.active_sessions:
                session = self.active_sessions[channel]
                session['handler'].stop()
                del self.active_sessions[channel]
    
    class BaseSubsystem:
        """Base class for custom subsystems."""
        
        def __init__(self, channel: Channel, server: SSHServer):
            self.channel = channel
            self.server = server
            self.running = False
            self.message_queue = queue.Queue()
        
        def start(self):
            """Start the subsystem."""
            self.running = True
            try:
                self.handle_subsystem()
            except Exception as e:
                self.send_error(f"Subsystem error: {e}")
            finally:
                self.stop()
        
        def stop(self):
            """Stop the subsystem."""
            self.running = False
            if not self.channel.closed:
                self.channel.close()
        
        def handle_subsystem(self):
            """Override this method to implement subsystem logic."""
            raise NotImplementedError
        
        def send_message(self, message_type: str, data: Dict[str, Any]):
            """Send a structured message to the client."""
            message = {
                'type': message_type,
                'data': data
            }
            json_data = json.dumps(message).encode('utf-8')
            
            # Send length prefix + JSON data
            length = struct.pack('!I', len(json_data))
            self.channel.send(length + json_data)
        
        def receive_message(self) -> Optional[Dict[str, Any]]:
            """Receive a structured message from the client."""
            try:
                # Read length prefix
                length_data = self.channel.recv(4)
                if len(length_data) != 4:
                    return None
                
                length = struct.unpack('!I', length_data)[0]
                
                # Read JSON data
                json_data = self.channel.recv(length)
                if len(json_data) != length:
                    return None
                
                return json.loads(json_data.decode('utf-8'))
                
            except Exception:
                return None
        
        def send_error(self, error_message: str):
            """Send an error message to the client."""
            self.send_message('error', {'message': error_message})
        
        def send_response(self, data: Dict[str, Any]):
            """Send a response message to the client."""
            self.send_message('response', data)
    
    class CustomAPISubsystem(BaseSubsystem):
        """Custom API subsystem for remote procedure calls."""
        
        def __init__(self, channel: Channel, server: SSHServer):
            super().__init__(channel, server)
            self.api_methods = {
                'get_system_info': self.get_system_info,
                'execute_command': self.execute_command,
                'list_files': self.list_files,
                'read_file': self.read_file,
                'write_file': self.write_file
            }
        
        def handle_subsystem(self):
            """Handle API requests."""
            self.send_message('ready', {'api_version': '1.0'})
            
            while self.running:
                message = self.receive_message()
                if not message:
                    break
                
                if message['type'] == 'request':
                    self.handle_api_request(message['data'])
                elif message['type'] == 'ping':
                    self.send_message('pong', {})
                else:
                    self.send_error(f"Unknown message type: {message['type']}")
        
        def handle_api_request(self, request_data: Dict[str, Any]):
            """Handle a single API request."""
            method = request_data.get('method')
            params = request_data.get('params', {})
            request_id = request_data.get('id')
            
            if method not in self.api_methods:
                self.send_message('response', {
                    'id': request_id,
                    'error': f"Unknown method: {method}"
                })
                return
            
            try:
                result = self.api_methods[method](**params)
                self.send_message('response', {
                    'id': request_id,
                    'result': result
                })
            except Exception as e:
                self.send_message('response', {
                    'id': request_id,
                    'error': str(e)
                })
        
        def get_system_info(self) -> Dict[str, Any]:
            """Get system information."""
            import platform
            import psutil
            
            return {
                'hostname': platform.node(),
                'platform': platform.platform(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': {
                    mount.mountpoint: {
                        'total': psutil.disk_usage(mount.mountpoint).total,
                        'used': psutil.disk_usage(mount.mountpoint).used,
                        'free': psutil.disk_usage(mount.mountpoint).free
                    }
                    for mount in psutil.disk_partitions()
                }
            }
        
        def execute_command(self, command: str, timeout: int = 30) -> Dict[str, Any]:
            """Execute a system command."""
            import subprocess
            
            try:
                result = subprocess.run(
                    command,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=timeout
                )
                
                return {
                    'stdout': result.stdout,
                    'stderr': result.stderr,
                    'returncode': result.returncode
                }
            except subprocess.TimeoutExpired:
                return {
                    'error': 'Command timed out',
                    'timeout': timeout
                }
        
        def list_files(self, path: str = '.') -> Dict[str, Any]:
            """List files in a directory."""
            import os
            import stat
            
            try:
                files = []
                for item in os.listdir(path):
                    item_path = os.path.join(path, item)
                    stat_info = os.stat(item_path)
                    
                    files.append({
                        'name': item,
                        'size': stat_info.st_size,
                        'mode': stat.filemode(stat_info.st_mode),
                        'mtime': stat_info.st_mtime,
                        'is_dir': os.path.isdir(item_path)
                    })
                
                return {'files': files}
            except OSError as e:
                raise Exception(f"Cannot list directory: {e}")
        
        def read_file(self, path: str, max_size: int = 1024*1024) -> Dict[str, Any]:
            """Read file contents."""
            try:
                file_size = os.path.getsize(path)
                if file_size > max_size:
                    raise Exception(f"File too large: {file_size} > {max_size}")
                
                with open(path, 'r') as f:
                    content = f.read()
                
                return {
                    'content': content,
                    'size': file_size
                }
            except Exception as e:
                raise Exception(f"Cannot read file: {e}")
        
        def write_file(self, path: str, content: str, mode: str = 'w') -> Dict[str, Any]:
            """Write file contents."""
            try:
                with open(path, mode) as f:
                    f.write(content)
                
                return {
                    'bytes_written': len(content.encode('utf-8')),
                    'path': path
                }
            except Exception as e:
                raise Exception(f"Cannot write file: {e}")
    
    class FileSyncSubsystem(BaseSubsystem):
        """File synchronization subsystem."""
        
        def handle_subsystem(self):
            """Handle file sync operations."""
            self.send_message('ready', {'sync_version': '1.0'})
            
            while self.running:
                message = self.receive_message()
                if not message:
                    break
                
                if message['type'] == 'sync_request':
                    self.handle_sync_request(message['data'])
                elif message['type'] == 'file_chunk':
                    self.handle_file_chunk(message['data'])
                else:
                    self.send_error(f"Unknown message type: {message['type']}")
        
        def handle_sync_request(self, request_data: Dict[str, Any]):
            """Handle file synchronization request."""
            operation = request_data.get('operation')
            
            if operation == 'list_changes':
                self.list_changes(request_data)
            elif operation == 'send_file':
                self.receive_file(request_data)
            elif operation == 'get_file':
                self.send_file(request_data)
            else:
                self.send_error(f"Unknown sync operation: {operation}")
        
        def list_changes(self, request_data: Dict[str, Any]):
            """List file changes since last sync."""
            import os
            import hashlib
            
            base_path = request_data.get('path', '.')
            last_sync = request_data.get('last_sync', 0)
            
            changes = []
            
            for root, dirs, files in os.walk(base_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    relative_path = os.path.relpath(file_path, base_path)
                    
                    try:
                        stat_info = os.stat(file_path)
                        
                        if stat_info.st_mtime > last_sync:
                            # Calculate file hash
                            with open(file_path, 'rb') as f:
                                file_hash = hashlib.md5(f.read()).hexdigest()
                            
                            changes.append({
                                'path': relative_path,
                                'size': stat_info.st_size,
                                'mtime': stat_info.st_mtime,
                                'hash': file_hash,
                                'action': 'modified'
                            })
                    except OSError:
                        continue
            
            self.send_response({
                'changes': changes,
                'sync_time': time.time()
            })
        
        def receive_file(self, request_data: Dict[str, Any]):
            """Receive a file from client."""
            file_path = request_data.get('path')
            file_size = request_data.get('size')
            
            # Prepare to receive file
            self.receiving_file = {
                'path': file_path,
                'size': file_size,
                'received': 0,
                'chunks': []
            }
            
            self.send_response({'ready': True})
        
        def handle_file_chunk(self, chunk_data: Dict[str, Any]):
            """Handle incoming file chunk."""
            if not hasattr(self, 'receiving_file'):
                self.send_error("No file transfer in progress")
                return
            
            chunk = chunk_data.get('data')
            chunk_size = len(chunk)
            
            self.receiving_file['chunks'].append(chunk)
            self.receiving_file['received'] += chunk_size
            
            if self.receiving_file['received'] >= self.receiving_file['size']:
                # File complete, write to disk
                file_data = ''.join(self.receiving_file['chunks'])
                
                try:
                    os.makedirs(os.path.dirname(self.receiving_file['path']), exist_ok=True)
                    with open(self.receiving_file['path'], 'w') as f:
                        f.write(file_data)
                    
                    self.send_response({
                        'file_received': True,
                        'path': self.receiving_file['path'],
                        'size': len(file_data)
                    })
                except Exception as e:
                    self.send_error(f"Failed to write file: {e}")
                
                del self.receiving_file
            else:
                # Request next chunk
                self.send_response({'continue': True})
        
        def send_file(self, request_data: Dict[str, Any]):
            """Send a file to client."""
            file_path = request_data.get('path')
            chunk_size = request_data.get('chunk_size', 8192)
            
            try:
                with open(file_path, 'r') as f:
                    file_content = f.read()
                
                # Send file in chunks
                for i in range(0, len(file_content), chunk_size):
                    chunk = file_content[i:i+chunk_size]
                    self.send_message('file_chunk', {
                        'data': chunk,
                        'offset': i,
                        'total_size': len(file_content)
                    })
                
                self.send_response({'file_sent': True})
                
            except Exception as e:
                self.send_error(f"Failed to send file: {e}")
    
    # Client example for custom protocol
    class CustomProtocolClient:
        """Client for custom SSH protocol."""
        
        def __init__(self, client):
            self.ssh_client = client
            self.channel = None
        
        async def connect_subsystem(self, subsystem_name: str):
            """Connect to custom subsystem."""
            self.channel = await self.ssh_client.open_channel('session')
            await self.channel.invoke_subsystem(subsystem_name)
        
        async def send_message(self, message_type: str, data: Dict[str, Any]):
            """Send message to subsystem."""
            message = {
                'type': message_type,
                'data': data
            }
            json_data = json.dumps(message).encode('utf-8')
            length = struct.pack('!I', len(json_data))
            await self.channel.send(length + json_data)
        
        async def receive_message(self) -> Optional[Dict[str, Any]]:
            """Receive message from subsystem."""
            try:
                length_data = await self.channel.recv(4)
                if len(length_data) != 4:
                    return None
                
                length = struct.unpack('!I', length_data)[0]
                json_data = await self.channel.recv(length)
                
                return json.loads(json_data.decode('utf-8'))
            except Exception:
                return None
        
        async def api_call(self, method: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
            """Make API call to custom subsystem."""
            request_id = f"req_{int(time.time() * 1000)}"
            
            await self.send_message('request', {
                'id': request_id,
                'method': method,
                'params': params or {}
            })
            
            # Wait for response
            while True:
                message = await self.receive_message()
                if not message:
                    raise Exception("Connection lost")
                
                if message['type'] == 'response' and message['data'].get('id') == request_id:
                    if 'error' in message['data']:
                        raise Exception(message['data']['error'])
                    return message['data']['result']
        
        async def close(self):
            """Close the subsystem connection."""
            if self.channel:
                await self.channel.close()
    
    # Usage example
    async def custom_protocol_example():
        from spindlex.async_client import AsyncSSHClient
        
        client = AsyncSSHClient()
        await client.connect('server.example.com', username='user', pkey=private_key)
        
        # Connect to custom API subsystem
        api_client = CustomProtocolClient(client)
        await api_client.connect_subsystem('custom-api')
        
        try:
            # Make API calls
            system_info = await api_client.api_call('get_system_info')
            print(f"System: {system_info['hostname']}")
            
            # Execute command
            result = await api_client.api_call('execute_command', {
                'command': 'ls -la /tmp',
                'timeout': 10
            })
            print(f"Command output: {result['stdout']}")
            
            # List files
            files = await api_client.api_call('list_files', {'path': '/var/log'})
            print(f"Found {len(files['files'])} files")
            
        finally:
            await api_client.close()
            await client.close()

High-Performance File Operations
--------------------------------

Optimized File Transfer::

    #!/usr/bin/env python3
    """
    High-performance file transfer with optimization techniques.
    """
    
    import os
    import hashlib
    import asyncio
    import aiofiles
    from spindlex.async_client import AsyncSSHClient
    from typing import Dict, Any, Optional, List
    import time
    import concurrent.futures
    
    class OptimizedFileTransfer:
        def __init__(self, 
                     chunk_size: int = 64*1024,
                     max_concurrent_chunks: int = 4,
                     compression: bool = True,
                     verify_checksums: bool = True):
            self.chunk_size = chunk_size
            self.max_concurrent_chunks = max_concurrent_chunks
            self.compression = compression
            self.verify_checksums = verify_checksums
        
        async def transfer_file_optimized(self, 
                                        client: AsyncSSHClient,
                                        local_path: str,
                                        remote_path: str,
                                        direction: str = 'upload') -> Dict[str, Any]:
            """Transfer file with optimizations."""
            start_time = time.time()
            
            # Get file info
            if direction == 'upload':
                file_size = await aiofiles.os.path.getsize(local_path)
                source_path = local_path
                dest_path = remote_path
            else:
                sftp = await client.open_sftp()
                stat_result = await sftp.stat(remote_path)
                file_size = stat_result.st_size
                source_path = remote_path
                dest_path = local_path
            
            # Calculate checksums if requested
            source_checksum = None
            if self.verify_checksums:
                source_checksum = await self.calculate_checksum(
                    client if direction == 'download' else None,
                    source_path
                )
            
            # Determine optimal transfer method
            if file_size > self.chunk_size * 4:
                # Use parallel chunked transfer for large files
                result = await self.parallel_chunked_transfer(
                    client, source_path, dest_path, direction, file_size
                )
            else:
                # Use standard transfer for small files
                result = await self.standard_transfer(
                    client, source_path, dest_path, direction
                )
            
            # Verify transfer if requested
            if self.verify_checksums and result['success']:
                dest_checksum = await self.calculate_checksum(
                    client if direction == 'upload' else None,
                    dest_path
                )
                
                if source_checksum != dest_checksum:
                    result['success'] = False
                    result['error'] = 'Checksum verification failed'
                else:
                    result['checksum_verified'] = True
            
            result['total_time'] = time.time() - start_time
            result['transfer_rate'] = file_size / result['total_time'] if result['total_time'] > 0 else 0
            
            return result
        
        async def parallel_chunked_transfer(self, 
                                          client: AsyncSSHClient,
                                          source_path: str,
                                          dest_path: str,
                                          direction: str,
                                          file_size: int) -> Dict[str, Any]:
            """Transfer file using parallel chunks."""
            num_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
            
            # Create temporary files for chunks
            temp_dir = f"/tmp/transfer_{int(time.time())}"
            
            if direction == 'upload':
                # Upload chunks in parallel
                await self.create_remote_temp_dir(client, temp_dir)
                
                # Upload chunks
                chunk_tasks = []
                semaphore = asyncio.Semaphore(self.max_concurrent_chunks)
                
                for i in range(num_chunks):
                    start_offset = i * self.chunk_size
                    end_offset = min((i + 1) * self.chunk_size, file_size)
                    chunk_size = end_offset - start_offset
                    
                    task = asyncio.create_task(
                        self.upload_chunk(
                            client, source_path, f"{temp_dir}/chunk_{i}",
                            start_offset, chunk_size, semaphore
                        )
                    )
                    chunk_tasks.append(task)
                
                # Wait for all chunks to upload
                chunk_results = await asyncio.gather(*chunk_tasks, return_exceptions=True)
                
                # Check for errors
                for i, result in enumerate(chunk_results):
                    if isinstance(result, Exception):
                        return {
                            'success': False,
                            'error': f'Chunk {i} upload failed: {result}'
                        }
                
                # Reassemble file on remote server
                await self.reassemble_remote_file(client, temp_dir, dest_path, num_chunks)
                
            else:
                # Download chunks in parallel
                await self.split_remote_file(client, source_path, temp_dir, num_chunks)
                
                # Download chunks
                chunk_tasks = []
                semaphore = asyncio.Semaphore(self.max_concurrent_chunks)
                
                for i in range(num_chunks):
                    local_chunk_path = f"{dest_path}.chunk_{i}"
                    remote_chunk_path = f"{temp_dir}/chunk_{i}"
                    
                    task = asyncio.create_task(
                        self.download_chunk(
                            client, remote_chunk_path, local_chunk_path, semaphore
                        )
                    )
                    chunk_tasks.append(task)
                
                # Wait for all chunks to download
                chunk_results = await asyncio.gather(*chunk_tasks, return_exceptions=True)
                
                # Check for errors
                for i, result in enumerate(chunk_results):
                    if isinstance(result, Exception):
                        return {
                            'success': False,
                            'error': f'Chunk {i} download failed: {result}'
                        }
                
                # Reassemble local file
                await self.reassemble_local_file(dest_path, num_chunks)
            
            # Cleanup temporary files
            await self.cleanup_temp_files(client, temp_dir, direction, dest_path, num_chunks)
            
            return {
                'success': True,
                'method': 'parallel_chunked',
                'chunks': num_chunks,
                'file_size': file_size
            }
        
        async def upload_chunk(self, 
                             client: AsyncSSHClient,
                             source_path: str,
                             remote_chunk_path: str,
                             offset: int,
                             chunk_size: int,
                             semaphore: asyncio.Semaphore):
            """Upload a single chunk."""
            async with semaphore:
                # Read chunk from source file
                async with aiofiles.open(source_path, 'rb') as f:
                    await f.seek(offset)
                    chunk_data = await f.read(chunk_size)
                
                # Write chunk to temporary file
                with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                    temp_file.write(chunk_data)
                    temp_path = temp_file.name
                
                try:
                    # Upload chunk
                    sftp = await client.open_sftp()
                    await sftp.put(temp_path, remote_chunk_path)
                finally:
                    # Clean up local temp file
                    os.unlink(temp_path)
        
        async def download_chunk(self, 
                               client: AsyncSSHClient,
                               remote_chunk_path: str,
                               local_chunk_path: str,
                               semaphore: asyncio.Semaphore):
            """Download a single chunk."""
            async with semaphore:
                sftp = await client.open_sftp()
                await sftp.get(remote_chunk_path, local_chunk_path)
        
        async def create_remote_temp_dir(self, client: AsyncSSHClient, temp_dir: str):
            """Create temporary directory on remote server."""
            channel = await client.open_channel('session')
            await channel.exec_command(f'mkdir -p {temp_dir}')
            exit_code = await channel.recv_exit_status()
            if exit_code != 0:
                raise Exception(f"Failed to create remote temp directory: {temp_dir}")
        
        async def reassemble_remote_file(self, 
                                       client: AsyncSSHClient,
                                       temp_dir: str,
                                       dest_path: str,
                                       num_chunks: int):
            """Reassemble file from chunks on remote server."""
            # Create reassembly command
            chunk_files = ' '.join([f"{temp_dir}/chunk_{i}" for i in range(num_chunks)])
            command = f"cat {chunk_files} > {dest_path}"
            
            channel = await client.open_channel('session')
            await channel.exec_command(command)
            exit_code = await channel.recv_exit_status()
            
            if exit_code != 0:
                raise Exception("Failed to reassemble remote file")
        
        async def split_remote_file(self, 
                                  client: AsyncSSHClient,
                                  source_path: str,
                                  temp_dir: str,
                                  num_chunks: int):
            """Split remote file into chunks."""
            # Create temp directory
            await self.create_remote_temp_dir(client, temp_dir)
            
            # Split file into chunks
            command = f"split -n {num_chunks} -d {source_path} {temp_dir}/chunk_"
            
            channel = await client.open_channel('session')
            await channel.exec_command(command)
            exit_code = await channel.recv_exit_status()
            
            if exit_code != 0:
                raise Exception("Failed to split remote file")
        
        async def reassemble_local_file(self, dest_path: str, num_chunks: int):
            """Reassemble local file from chunks."""
            async with aiofiles.open(dest_path, 'wb') as dest_file:
                for i in range(num_chunks):
                    chunk_path = f"{dest_path}.chunk_{i}"
                    async with aiofiles.open(chunk_path, 'rb') as chunk_file:
                        chunk_data = await chunk_file.read()
                        await dest_file.write(chunk_data)
                    
                    # Remove chunk file
                    os.unlink(chunk_path)
        
        async def cleanup_temp_files(self, 
                                   client: AsyncSSHClient,
                                   temp_dir: str,
                                   direction: str,
                                   dest_path: str,
                                   num_chunks: int):
            """Clean up temporary files."""
            # Remove remote temp directory
            channel = await client.open_channel('session')
            await channel.exec_command(f'rm -rf {temp_dir}')
            
            # Remove local chunk files if they exist
            if direction == 'download':
                for i in range(num_chunks):
                    chunk_path = f"{dest_path}.chunk_{i}"
                    if os.path.exists(chunk_path):
                        os.unlink(chunk_path)
        
        async def standard_transfer(self, 
                                  client: AsyncSSHClient,
                                  source_path: str,
                                  dest_path: str,
                                  direction: str) -> Dict[str, Any]:
            """Standard file transfer."""
            try:
                sftp = await client.open_sftp()
                
                if direction == 'upload':
                    await sftp.put(source_path, dest_path)
                else:
                    await sftp.get(source_path, dest_path)
                
                return {
                    'success': True,
                    'method': 'standard'
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e)
                }
        
        async def calculate_checksum(self, 
                                   client: Optional[AsyncSSHClient],
                                   file_path: str) -> str:
            """Calculate file checksum."""
            if client:
                # Remote file checksum
                channel = await client.open_channel('session')
                await channel.exec_command(f'md5sum {file_path}')
                output = await channel.recv(1024)
                checksum = output.decode().split()[0]
            else:
                # Local file checksum
                hash_md5 = hashlib.md5()
                async with aiofiles.open(file_path, 'rb') as f:
                    async for chunk in aiofiles.iter_chunked(f, 8192):
                        hash_md5.update(chunk)
                checksum = hash_md5.hexdigest()
            
            return checksum
    
    # Usage example
    async def optimized_transfer_example():
        client = AsyncSSHClient()
        await client.connect('server.example.com', username='user', pkey=private_key)
        
        transfer = OptimizedFileTransfer(
            chunk_size=128*1024,  # 128KB chunks
            max_concurrent_chunks=8,
            compression=True,
            verify_checksums=True
        )
        
        # Upload large file
        result = await transfer.transfer_file_optimized(
            client,
            '/local/large_file.zip',
            '/remote/large_file.zip',
            direction='upload'
        )
        
        if result['success']:
            rate_mbps = result['transfer_rate'] / (1024 * 1024)
            print(f"Upload completed: {result['file_size']} bytes in {result['total_time']:.2f}s ({rate_mbps:.2f} MB/s)")
            if result.get('checksum_verified'):
                print("Checksum verified successfully")
        else:
            print(f"Upload failed: {result['error']}")
        
        await client.close()
    
    # Run the example
    if __name__ == "__main__":
        asyncio.run(optimized_transfer_example())