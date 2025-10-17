# 🔌 SSH Client Guide

Complete guide to using SpindleX's SSH client for secure remote connections and command execution.

## 📋 Table of Contents

- [Basic Usage](#-basic-usage)
- [Connection Management](#-connection-management)
- [Authentication Methods](#-authentication-methods)
- [Command Execution](#-command-execution)
- [Interactive Sessions](#-interactive-sessions)
- [Host Key Management](#-host-key-management)
- [Configuration Options](#-configuration-options)
- [Error Handling](#-error-handling)
- [Best Practices](#-best-practices)

## 🚀 Basic Usage

### Simple Connection

```python
from spindlex import SSHClient

# Basic connection
client = SSHClient()
client.connect('server.example.com', username='user', password='password')

# Execute a command
stdin, stdout, stderr = client.exec_command('ls -la')
print(stdout.read().decode())

# Clean up
client.close()
```

### Using Context Manager (Recommended)

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('server.example.com', username='user', password='password')
    
    # Your operations here
    stdin, stdout, stderr = client.exec_command('whoami')
    print(f"Connected as: {stdout.read().decode().strip()}")
```

## 🔗 Connection Management

### Connection Parameters

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect(
        hostname='server.example.com',
        port=22,                    # Default SSH port
        username='myuser',
        password='mypassword',      # Or use key-based auth
        timeout=30,                 # Connection timeout in seconds
        compress=True,              # Enable compression
        look_for_keys=True,         # Look for SSH keys automatically
        allow_agent=True,           # Use SSH agent if available
        banner_timeout=30,          # Banner timeout
        auth_timeout=30,            # Authentication timeout
        channel_timeout=None,       # Channel timeout (None = no timeout)
    )
```

### Connection Status

```python
from spindlex import SSHClient

client = SSHClient()

# Check connection status
print(f"Connected: {client.is_connected()}")

# Get connection info
if client.is_connected():
    transport = client.get_transport()
    print(f"Server version: {transport.remote_version}")
    print(f"Cipher: {transport.get_cipher()}")
    print(f"Authenticated: {transport.is_authenticated()}")
```

### Connection Pooling

```python
from spindlex import SSHClient
import threading
from queue import Queue

class SSHConnectionPool:
    def __init__(self, hostname, username, password, pool_size=5):
        self.hostname = hostname
        self.username = username
        self.password = password
        self.pool = Queue(maxsize=pool_size)
        
        # Pre-create connections
        for _ in range(pool_size):
            client = SSHClient()
            client.connect(hostname, username=username, password=password)
            self.pool.put(client)
    
    def get_connection(self):
        return self.pool.get()
    
    def return_connection(self, client):
        if client.is_connected():
            self.pool.put(client)
        else:
            # Reconnect if needed
            client.connect(self.hostname, username=self.username, password=self.password)
            self.pool.put(client)
    
    def close_all(self):
        while not self.pool.empty():
            client = self.pool.get()
            client.close()

# Usage
pool = SSHConnectionPool('server.com', 'user', 'pass')

def worker_task(task_id):
    client = pool.get_connection()
    try:
        stdin, stdout, stderr = client.exec_command(f'echo "Task {task_id}"')
        result = stdout.read().decode().strip()
        print(f"Task {task_id}: {result}")
    finally:
        pool.return_connection(client)

# Run multiple tasks
threads = []
for i in range(10):
    t = threading.Thread(target=worker_task, args=(i,))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

pool.close_all()
```

## 🔐 Authentication Methods

### Password Authentication

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect(
        hostname='server.com',
        username='user',
        password='secure_password'
    )
```

### Public Key Authentication

```python
from spindlex import SSHClient
from spindlex.crypto.pkey import RSAKey, Ed25519Key, ECDSAKey

# Load different key types
rsa_key = RSAKey.from_private_key_file('~/.ssh/id_rsa')
ed25519_key = Ed25519Key.from_private_key_file('~/.ssh/id_ed25519')
ecdsa_key = ECDSAKey.from_private_key_file('~/.ssh/id_ecdsa')

# Connect with key
with SSHClient() as client:
    client.connect(
        hostname='server.com',
        username='user',
        pkey=ed25519_key  # Most secure option
    )
```

### Key with Passphrase

```python
from spindlex import SSHClient
from spindlex.crypto.pkey import RSAKey
import getpass

# Load encrypted key
passphrase = getpass.getpass("Enter key passphrase: ")
private_key = RSAKey.from_private_key_file('~/.ssh/id_rsa', password=passphrase)

with SSHClient() as client:
    client.connect('server.com', username='user', pkey=private_key)
```

### Agent Authentication

```python
from spindlex import SSHClient

with SSHClient() as client:
    # SpindleX will automatically try SSH agent keys
    client.connect(
        hostname='server.com',
        username='user',
        allow_agent=True,      # Enable SSH agent
        look_for_keys=True     # Also look for local keys
    )
```

### Multi-Factor Authentication

```python
from spindlex import SSHClient
from spindlex.crypto.pkey import Ed25519Key

# First authenticate with key, then password (if server requires both)
private_key = Ed25519Key.from_private_key_file('~/.ssh/id_ed25519')

with SSHClient() as client:
    try:
        # Try key first
        client.connect('server.com', username='user', pkey=private_key)
    except AuthenticationException:
        # If key auth fails, try password
        password = getpass.getpass("Password: ")
        client.connect('server.com', username='user', password=password)
```

### GSSAPI/Kerberos Authentication

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect(
        hostname='server.com',
        username='user',
        gss_auth=True,                    # Enable GSSAPI
        gss_kex=True,                     # GSSAPI key exchange
        gss_deleg_creds=False,            # Don't delegate credentials
        gss_host='server.example.com'     # GSSAPI hostname
    )
```

## 💻 Command Execution

### Basic Command Execution

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    # Execute command
    stdin, stdout, stderr = client.exec_command('ls -la /home')
    
    # Read output
    output = stdout.read().decode()
    errors = stderr.read().decode()
    exit_status = stdout.channel.recv_exit_status()
    
    print(f"Output:\n{output}")
    if errors:
        print(f"Errors:\n{errors}")
    print(f"Exit status: {exit_status}")
```

### Command with Input

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    # Command that expects input
    stdin, stdout, stderr = client.exec_command('sudo -S ls /root')
    
    # Send password to sudo
    stdin.write('your_sudo_password\n')
    stdin.flush()
    
    # Read output
    output = stdout.read().decode()
    print(output)
```

### Long-Running Commands

```python
from spindlex import SSHClient
import time

with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    # Start long-running command
    stdin, stdout, stderr = client.exec_command('tail -f /var/log/syslog')
    
    # Read output in real-time
    try:
        while True:
            line = stdout.readline()
            if line:
                print(f"LOG: {line.strip()}")
            else:
                time.sleep(0.1)
    except KeyboardInterrupt:
        print("Stopping log monitoring...")
        stdout.channel.close()
```

### Parallel Command Execution

```python
from spindlex import SSHClient
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def execute_command(client, command):
    stdin, stdout, stderr = client.exec_command(command)
    return {
        'command': command,
        'output': stdout.read().decode(),
        'error': stderr.read().decode(),
        'exit_status': stdout.channel.recv_exit_status()
    }

with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    commands = [
        'ps aux | head -10',
        'df -h',
        'free -m',
        'uptime',
        'who'
    ]
    
    # Execute commands in parallel
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_command = {
            executor.submit(execute_command, client, cmd): cmd 
            for cmd in commands
        }
        
        for future in as_completed(future_to_command):
            result = future.result()
            print(f"Command: {result['command']}")
            print(f"Output: {result['output']}")
            print(f"Exit Status: {result['exit_status']}")
            print("-" * 50)
```

## 🖥️ Interactive Sessions

### Basic Shell Session

```python
from spindlex import SSHClient
import threading
import sys

def read_shell_output(channel):
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
    client.connect('server.com', username='user', password='pass')
    
    # Start interactive shell
    shell = client.invoke_shell()
    
    # Start output reader
    output_thread = threading.Thread(target=read_shell_output, args=(shell,))
    output_thread.daemon = True
    output_thread.start()
    
    # Interactive input loop
    try:
        while True:
            command = input()
            if command.lower() in ['exit', 'quit']:
                break
            shell.send(command + '\n')
    except (KeyboardInterrupt, EOFError):
        pass
    
    shell.close()
```

### Shell with PTY

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    # Request a pseudo-terminal
    shell = client.invoke_shell(
        term='xterm',           # Terminal type
        width=80,               # Terminal width
        height=24,              # Terminal height
        width_pixels=0,         # Width in pixels (0 = use character width)
        height_pixels=0         # Height in pixels (0 = use character height)
    )
    
    # Send commands
    shell.send('export PS1="[SpindleX] $ "\n')
    shell.send('ls -la\n')
    
    # Read output
    import time
    time.sleep(1)  # Wait for command to complete
    
    output = ""
    while shell.recv_ready():
        output += shell.recv(1024).decode()
    
    print(output)
    shell.close()
```

## 🔑 Host Key Management

### Host Key Policies

```python
from spindlex import SSHClient
from spindlex.hostkeys.policy import AutoAddPolicy, RejectPolicy, WarningPolicy

client = SSHClient()

# Automatically accept and save new host keys (less secure)
client.set_missing_host_key_policy(AutoAddPolicy())

# Reject all unknown host keys (more secure)
client.set_missing_host_key_policy(RejectPolicy())

# Warn about unknown host keys but allow connection
client.set_missing_host_key_policy(WarningPolicy())
```

### Custom Host Key Policy

```python
from spindlex import SSHClient
from spindlex.hostkeys.policy import MissingHostKeyPolicy
import logging

class CustomHostKeyPolicy(MissingHostKeyPolicy):
    def missing_host_key(self, client, hostname, key):
        # Log the event
        logging.warning(f"Unknown host key for {hostname}: {key.get_fingerprint()}")
        
        # Ask user for confirmation
        response = input(f"Accept host key for {hostname}? (y/n): ")
        if response.lower() == 'y':
            # Add to known hosts
            client.get_host_keys().add(hostname, key.get_name(), key)
            return
        else:
            # Reject connection
            raise Exception(f"Host key rejected for {hostname}")

client = SSHClient()
client.set_missing_host_key_policy(CustomHostKeyPolicy())
```

### Managing Known Hosts

```python
from spindlex import SSHClient
from spindlex.hostkeys.storage import HostKeyStorage

client = SSHClient()

# Get host key storage
host_keys = client.get_host_keys()

# Load from custom file
host_keys.load('~/.ssh/custom_known_hosts')

# Add a host key manually
from spindlex.crypto.pkey import RSAKey
server_key = RSAKey.from_private_key_file('server_host_key.pub')
host_keys.add('server.com', 'ssh-rsa', server_key)

# Save to file
host_keys.save('~/.ssh/known_hosts')

# Check if host is known
if host_keys.check('server.com', server_key):
    print("Host key is known and trusted")
```

## ⚙️ Configuration Options

### Client Configuration

```python
from spindlex import SSHClient

client = SSHClient()

# Set various options
client.set_log_channel('spindlex.client')  # Enable logging
client.set_keepalive(30)                   # Send keepalive every 30 seconds

# Connect with advanced options
client.connect(
    hostname='server.com',
    username='user',
    password='pass',
    
    # Timeouts
    timeout=30,                 # Initial connection timeout
    auth_timeout=30,            # Authentication timeout
    banner_timeout=30,          # Banner timeout
    
    # Compression
    compress=True,              # Enable compression
    
    # Security
    disabled_algorithms={       # Disable weak algorithms
        'kex': ['diffie-hellman-group1-sha1'],
        'cipher': ['3des-cbc'],
        'mac': ['hmac-md5']
    },
    
    # Key management
    look_for_keys=True,         # Look for SSH keys
    allow_agent=True,           # Use SSH agent
    
    # Socket options
    sock=None,                  # Custom socket
    
    # GSS-API
    gss_auth=False,             # GSSAPI authentication
    gss_kex=False,              # GSSAPI key exchange
    gss_deleg_creds=False,      # Delegate credentials
    gss_host=None,              # GSSAPI hostname
)
```

### Transport Configuration

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    # Get transport for advanced configuration
    transport = client.get_transport()
    
    # Set security options
    transport.set_hexdump(True)                    # Enable hex dump logging
    transport.set_subsystem_handler('sftp', None) # Custom SFTP handler
    
    # Window and packet size
    transport.window_size = 2097152                # 2MB window
    transport.packetizer.REKEY_BYTES = 1073741824  # 1GB rekey threshold
```

## 🚨 Error Handling

### Exception Types

```python
from spindlex import SSHClient
from spindlex.exceptions import (
    SSHException,              # Base SSH exception
    AuthenticationException,   # Authentication failed
    BadHostKeyException,       # Host key verification failed
    ChannelException,          # Channel operation failed
    TransportException,        # Transport layer error
    ProtocolException,         # Protocol violation
    TimeoutException,          # Operation timed out
)

def robust_ssh_connection(hostname, username, password):
    try:
        with SSHClient() as client:
            client.connect(hostname, username=username, password=password)
            
            stdin, stdout, stderr = client.exec_command('whoami')
            return stdout.read().decode().strip()
            
    except AuthenticationException as e:
        print(f"Authentication failed: {e}")
        return None
        
    except BadHostKeyException as e:
        print(f"Host key verification failed: {e}")
        return None
        
    except TimeoutException as e:
        print(f"Connection timed out: {e}")
        return None
        
    except ChannelException as e:
        print(f"Channel error: {e}")
        return None
        
    except TransportException as e:
        print(f"Transport error: {e}")
        return None
        
    except SSHException as e:
        print(f"SSH error: {e}")
        return None
        
    except Exception as e:
        print(f"Unexpected error: {e}")
        return None
```

### Retry Logic

```python
from spindlex import SSHClient
from spindlex.exceptions import SSHException
import time
import random

def connect_with_retry(hostname, username, password, max_retries=3):
    for attempt in range(max_retries):
        try:
            client = SSHClient()
            client.connect(hostname, username=username, password=password)
            return client
            
        except SSHException as e:
            if attempt == max_retries - 1:
                raise e
            
            # Exponential backoff with jitter
            delay = (2 ** attempt) + random.uniform(0, 1)
            print(f"Connection failed (attempt {attempt + 1}), retrying in {delay:.1f}s...")
            time.sleep(delay)
    
    return None

# Usage
try:
    client = connect_with_retry('unreliable-server.com', 'user', 'pass')
    if client:
        # Use the connection
        stdin, stdout, stderr = client.exec_command('whoami')
        print(stdout.read().decode())
        client.close()
except Exception as e:
    print(f"Failed to connect after retries: {e}")
```

## 🎯 Best Practices

### 1. Always Use Context Managers

```python
# ✅ Good - automatic cleanup
with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    # Operations here

# ❌ Bad - manual cleanup required
client = SSHClient()
client.connect('server.com', username='user', password='pass')
# ... operations ...
client.close()  # Easy to forget!
```

### 2. Use Key-Based Authentication

```python
# ✅ Good - more secure
from spindlex.crypto.pkey import Ed25519Key

private_key = Ed25519Key.from_private_key_file('~/.ssh/id_ed25519')
with SSHClient() as client:
    client.connect('server.com', username='user', pkey=private_key)

# ❌ Bad - less secure
with SSHClient() as client:
    client.connect('server.com', username='user', password='password')
```

### 3. Handle Errors Gracefully

```python
# ✅ Good - comprehensive error handling
try:
    with SSHClient() as client:
        client.connect('server.com', username='user', password='pass')
        stdin, stdout, stderr = client.exec_command('risky_command')
        
        exit_status = stdout.channel.recv_exit_status()
        if exit_status != 0:
            error_output = stderr.read().decode()
            raise Exception(f"Command failed with exit status {exit_status}: {error_output}")
            
except Exception as e:
    logging.error(f"SSH operation failed: {e}")
    # Handle the error appropriately
```

### 4. Use Connection Pooling for Multiple Operations

```python
# ✅ Good - reuse connections
with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    # Multiple operations on same connection
    for command in ['ls', 'pwd', 'whoami']:
        stdin, stdout, stderr = client.exec_command(command)
        print(f"{command}: {stdout.read().decode().strip()}")

# ❌ Bad - new connection for each operation
for command in ['ls', 'pwd', 'whoami']:
    with SSHClient() as client:
        client.connect('server.com', username='user', password='pass')
        stdin, stdout, stderr = client.exec_command(command)
        print(f"{command}: {stdout.read().decode().strip()}")
```

### 5. Set Appropriate Timeouts

```python
# ✅ Good - reasonable timeouts
with SSHClient() as client:
    client.connect(
        'server.com',
        username='user',
        password='pass',
        timeout=30,        # 30 second connection timeout
        auth_timeout=30,   # 30 second auth timeout
        banner_timeout=30  # 30 second banner timeout
    )
```

### 6. Use Secure Host Key Policies

```python
# ✅ Good - secure policy
from spindlex.hostkeys.policy import RejectPolicy

client = SSHClient()
client.set_missing_host_key_policy(RejectPolicy())

# ❌ Bad - insecure policy
from spindlex.hostkeys.policy import AutoAddPolicy
client.set_missing_host_key_policy(AutoAddPolicy())
```

---

## 📚 Related Documentation

- [Authentication Methods](authentication) - Detailed auth guide
- [SFTP Operations](sftp-operations) - File transfer operations
- [Port Forwarding](port-forwarding) - Tunneling and proxies
- [Async Programming](async-programming) - High-performance async patterns
- [Security Best Practices](security-best-practices) - Security guidelines

---

*Need help? Check our [FAQ](faq) or [create an issue](https://gitlab.com/daveops.world/development/python/spindlex/-/issues).*