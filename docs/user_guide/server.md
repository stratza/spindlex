# SSH Server Guide

SpindleX provides a modular framework for building SSH and SFTP servers. This guide covers how to implement custom server logic, handle authentication, and manage client connections.

## Core Concepts

Developing an SSH server with SpindleX involves two main components:

1.  **`SSHServer`**: A base class that defines the server's behavior (authentication policies, channel authorization, etc.).
2.  **`SSHServerManager`**: Orchestrates the server lifecycle, listening for incoming socket connections and handing them off to the transport layer.

## Basic Server Implementation

To create an SSH server, you must subclass `SSHServer` and override the relevant methods for your needs.

### 1. Define Server Interface

```python
from spindlex import SSHServer, SSHServerManager
from spindlex.protocol.constants import AUTH_SUCCESSFUL, AUTH_FAILED

class MySSHServer(SSHServer):
    def check_auth_password(self, username, password):
        if username == 'admin' and password == 'secret':
            return AUTH_SUCCESSFUL
        return AUTH_FAILED

    def get_allowed_auths(self, username):
        return ["password"]

    def check_channel_request(self, kind, chanid):
        # Allow session channels
        if kind == "session":
            return 0  # SSH_OPEN_CONNECT_SUCCESS
        return 3      # Unknown channel type
```

### 2. Run the Server

Use `SSHServerManager` to bind the server to a port and start accepting connections.

```python
import socket
from spindlex import SSHServerManager
from spindlex.crypto import PKey

# Load or generate server host key
server_key = PKey.generate(key_type='ed25519')
```

# Initialize interface and manager
interface = MySSHServer()
manager = SSHServerManager(
    server_interface=interface,
    server_key=server_key,
    bind_address='0.0.0.0',
    port=2222
)

try:
    print("Starting SSH server on port 2222...")
    manager.start_server()
    # Keep main thread alive
    import time
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    manager.stop_server()
```

## Handling Exec Requests

To allow clients to execute commands, override `check_channel_exec_request`.

```python
class ExecServer(SSHServer):
    def check_channel_exec_request(self, channel, command):
        cmd_str = command.decode('utf-8')
        print(f"Client requested: {cmd_str}")
        
        # In a real server, you might spawn a process
        # channel.send accepts both bytes and strings
        channel.send(f"Executed: {cmd_str}\n")
        channel.send_exit_status(0)
        channel.close()
        return True
```

## SFTP Server

To implement an SFTP server, override `check_channel_subsystem_request` and handle the "sftp" subsystem.

```python
from spindlex import SFTPServer

class MySFTPServer(SSHServer):
    def check_channel_subsystem_request(self, channel, name):
        if name == "sftp":
            # SFTPServer handles the SFTP protocol over the channel
            sftp_handler = SFTPServer(channel, root_path="/tmp/sftp_root")
            return True
        return False
```

## Advanced Configuration

`SSHServerManager` provides several settings to tune server behavior. **Note: These methods must be called before calling `start_server()` to take effect.**

- `set_max_connections(n)`: Limit concurrent connections.
- `set_connection_timeout(s)`: Timeout for the initial socket connection.
- `set_auth_timeout(s)`: Timeout for the authentication handshake.
