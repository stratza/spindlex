# 🚀 Quick Start Tutorial

Get up and running with SpindleX in just 5 minutes! This tutorial will walk you through the basics of using SpindleX for SSH connections and file transfers.

## 📋 Prerequisites

- Python 3.8+ installed
- SpindleX installed (`pip install spindlex`)
- Access to an SSH server (or use a local test server)

## 🎯 Your First SpindleX Program

### 1. Basic SSH Connection

```python
from spindlex import SSHClient

# Create an SSH client
client = SSHClient()

try:
    # Connect to your server
    client.connect(
        hostname='your-server.com',
        port=22,
        username='your-username',
        password='your-password'
    )
    
    print("✅ Connected successfully!")
    
    # Execute a simple command
    stdin, stdout, stderr = client.exec_command('whoami')
    result = stdout.read().decode().strip()
    print(f"👤 Connected as: {result}")
    
finally:
    # Always close the connection
    client.close()
```

### 2. Using Context Manager (Recommended)

```python
from spindlex import SSHClient

# Automatically handles connection cleanup
with SSHClient() as client:
    client.connect('your-server.com', username='user', password='pass')
    
    # Execute multiple commands
    commands = ['pwd', 'ls -la', 'df -h']
    
    for cmd in commands:
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode()
        print(f"📋 {cmd}:")
        print(output)
        print("-" * 40)
```

## 🔑 Key-Based Authentication

More secure than passwords:

```python
from spindlex import SSHClient
from spindlex.crypto.pkey import RSAKey, Ed25519Key

# Load your private key
try:
    # Try Ed25519 first (more secure)
    private_key = Ed25519Key.from_private_key_file('~/.ssh/id_ed25519')
except FileNotFoundError:
    # Fallback to RSA
    private_key = RSAKey.from_private_key_file('~/.ssh/id_rsa')

with SSHClient() as client:
    client.connect(
        hostname='your-server.com',
        username='your-username',
        pkey=private_key
    )
    
    print("🔐 Authenticated with private key!")
    
    # Your commands here
    stdin, stdout, stderr = client.exec_command('echo "Hello from SpindleX!"')
    print(stdout.read().decode())
```

## 📁 File Transfer with SFTP

### Basic File Operations

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('your-server.com', username='user', password='pass')
    
    # Open SFTP session
    with client.open_sftp() as sftp:
        # Upload a file
        sftp.put('/local/path/file.txt', '/remote/path/file.txt')
        print("📤 File uploaded!")
        
        # Download a file
        sftp.get('/remote/path/data.json', '/local/path/data.json')
        print("📥 File downloaded!")
        
        # List remote directory
        files = sftp.listdir('/remote/directory')
        print("📂 Remote files:")
        for file in files:
            print(f"  📄 {file}")
```

### Advanced SFTP Operations

```python
from spindlex import SSHClient
import os

with SSHClient() as client:
    client.connect('your-server.com', username='user', password='pass')
    
    with client.open_sftp() as sftp:
        # Create remote directory
        try:
            sftp.mkdir('/remote/new-directory')
            print("📁 Directory created!")
        except Exception as e:
            print(f"Directory might already exist: {e}")
        
        # Get file statistics
        file_stats = sftp.stat('/remote/path/file.txt')
        print(f"📊 File size: {file_stats.size} bytes")
        print(f"📅 Modified: {file_stats.mtime}")
        
        # Change file permissions
        sftp.chmod('/remote/path/script.sh', 0o755)
        print("🔧 Permissions updated!")
```

## ⚡ Async Programming

For high-performance applications:

```python
import asyncio
from spindlex import AsyncSSHClient

async def async_ssh_example():
    async with AsyncSSHClient() as client:
        await client.connect('your-server.com', username='user', password='pass')
        
        # Execute command asynchronously
        stdin, stdout, stderr = await client.exec_command('ls -la')
        output = await stdout.read()
        print(output.decode())
        
        # SFTP operations
        async with client.open_sftp() as sftp:
            await sftp.put('/local/file.txt', '/remote/file.txt')
            print("📤 Async upload complete!")

# Run the async function
asyncio.run(async_ssh_example())
```

## 🌐 Port Forwarding

Create secure tunnels:

```python
from spindlex import SSHClient
import time

with SSHClient() as client:
    client.connect('bastion-server.com', username='user', password='pass')
    
    # Forward local port 8080 to remote service
    tunnel_id = client.create_local_port_forward(
        local_port=8080,
        remote_host='internal-service.local',
        remote_port=80
    )
    
    print("🔗 Tunnel created! Access http://localhost:8080")
    print("Press Ctrl+C to close tunnel...")
    
    try:
        # Keep tunnel open
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        client.close_port_forward(tunnel_id)
        print("🔒 Tunnel closed!")
```

## 🛡️ Host Key Verification

Secure your connections:

```python
from spindlex import SSHClient
from spindlex.hostkeys.policy import AutoAddPolicy, RejectPolicy

client = SSHClient()

# Option 1: Automatically accept new host keys (less secure)
client.set_missing_host_key_policy(AutoAddPolicy())

# Option 2: Reject unknown host keys (more secure)
client.set_missing_host_key_policy(RejectPolicy())

try:
    client.connect('new-server.com', username='user', password='pass')
    print("🔐 Host key verified!")
except Exception as e:
    print(f"❌ Host key verification failed: {e}")
finally:
    client.close()
```

## 🔄 Multiple Server Management

Connect to multiple servers:

```python
from spindlex import SSHClient
import concurrent.futures

def execute_on_server(server_info):
    hostname, username, password = server_info
    
    with SSHClient() as client:
        client.connect(hostname, username=username, password=password)
        
        # Execute command
        stdin, stdout, stderr = client.exec_command('hostname && uptime')
        result = stdout.read().decode()
        
        return f"🖥️ {hostname}:\n{result}"

# List of servers
servers = [
    ('web1.example.com', 'admin', 'password1'),
    ('web2.example.com', 'admin', 'password2'),
    ('db.example.com', 'admin', 'password3'),
]

# Execute on all servers concurrently
with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    results = executor.map(execute_on_server, servers)
    
    for result in results:
        print(result)
        print("-" * 50)
```

## 🧪 Interactive Shell

For interactive sessions:

```python
from spindlex import SSHClient
import threading
import sys

def read_output(channel):
    """Read and print output from the channel"""
    while True:
        try:
            data = channel.recv(1024)
            if not data:
                break
            sys.stdout.write(data.decode())
            sys.stdout.flush()
        except:
            break

with SSHClient() as client:
    client.connect('your-server.com', username='user', password='pass')
    
    # Start interactive shell
    shell = client.invoke_shell()
    
    # Start output reader thread
    output_thread = threading.Thread(target=read_output, args=(shell,))
    output_thread.daemon = True
    output_thread.start()
    
    print("🐚 Interactive shell started. Type 'exit' to quit.")
    
    try:
        while True:
            command = input()
            if command.lower() == 'exit':
                break
            shell.send(command + '\n')
    except KeyboardInterrupt:
        pass
    
    shell.close()
    print("🔒 Shell closed!")
```

## 🚨 Error Handling

Robust error handling:

```python
from spindlex import SSHClient
from spindlex.exceptions import (
    AuthenticationException,
    BadHostKeyException,
    SSHException
)

def safe_ssh_connection(hostname, username, password):
    try:
        with SSHClient() as client:
            client.connect(hostname, username=username, password=password)
            
            stdin, stdout, stderr = client.exec_command('whoami')
            result = stdout.read().decode().strip()
            
            return f"✅ Success: Connected as {result}"
            
    except AuthenticationException:
        return "❌ Authentication failed - check credentials"
    
    except BadHostKeyException:
        return "❌ Host key verification failed - potential security risk"
    
    except ConnectionRefusedError:
        return "❌ Connection refused - server might be down"
    
    except TimeoutError:
        return "❌ Connection timeout - check network connectivity"
    
    except SSHException as e:
        return f"❌ SSH error: {e}"
    
    except Exception as e:
        return f"❌ Unexpected error: {e}"

# Test the function
result = safe_ssh_connection('your-server.com', 'user', 'pass')
print(result)
```

## 📊 Performance Tips

### 1. Connection Reuse

```python
from spindlex import SSHClient

# Keep connection alive for multiple operations
with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    # Multiple operations on same connection
    for i in range(10):
        stdin, stdout, stderr = client.exec_command(f'echo "Operation {i}"')
        print(stdout.read().decode().strip())
```

### 2. Async for Concurrency

```python
import asyncio
from spindlex import AsyncSSHClient

async def concurrent_operations():
    async with AsyncSSHClient() as client:
        await client.connect('server.com', username='user', password='pass')
        
        # Run multiple commands concurrently
        tasks = []
        for i in range(5):
            task = client.exec_command(f'sleep 1 && echo "Task {i}"')
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        for i, (stdin, stdout, stderr) in enumerate(results):
            output = await stdout.read()
            print(f"Task {i}: {output.decode().strip()}")

asyncio.run(concurrent_operations())
```

## 🎯 Next Steps

Now that you've mastered the basics, explore more advanced topics:

- 📖 [SSH Client Guide](ssh-client-guide) - Comprehensive client documentation
- 🔐 [Authentication Methods](authentication) - All supported auth methods
- 📁 [SFTP Operations](sftp-operations) - Advanced file operations
- ⚡ [Async Programming](async-programming) - High-performance async patterns
- 🌐 [Port Forwarding](port-forwarding) - Advanced tunneling techniques

## 🆘 Need Help?

- 📚 [Full Documentation](https://spindlex.readthedocs.io/)
- 🐛 [Report Issues](https://gitlab.com/daveops.world/development/python/spindlex/-/issues)
- 💬 [Community Discussions](https://gitlab.com/daveops.world/development/python/spindlex/-/issues)

---

**Congratulations!** 🎉 You've completed the SpindleX quick start tutorial. You're now ready to build amazing SSH-powered applications!