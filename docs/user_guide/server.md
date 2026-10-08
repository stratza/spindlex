# SSH Server Guide

SpindleX provides a modular framework for building SSH and SFTP servers. This guide covers how to implement custom server logic, handle authentication, and manage client connections.

## Core Concepts

Developing an SSH server with SpindleX involves two main components:

1.  **`SSHServer`**: A base class that defines the server's behavior (authentication policies, channel authorization, etc.).
2.  **`SSHServerManager`**: Orchestrates the server lifecycle, listening for incoming socket connections and handing them off to the transport layer.

> [!IMPORTANT]
> **Async Support**: Currently, SpindleX only supports **synchronous** SSH and SFTP server implementations. `AsyncSSHServer` is on the roadmap but is not yet available. However, synchronous servers can still handle multiple connections efficiently using the built-in threading model.

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
from spindlex import SSHServerManager
from spindlex.crypto import PKey

# Load or generate server host key
server_key = PKey.generate(key_type='ed25519')

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

        # In a real server, you might spawn a process.
        # sendall()/sendall_stderr() accept both bytes and strings.
        channel.sendall(f"Executed: {cmd_str}\n")
        channel.sendall_stderr("warning: this is a demo server\n")
        channel.send_exit_status(0)
        channel.send_eof()
        channel.close()
        return True
```

It is fine to finish the command and close the channel inside the callback:
SpindleX sends the reply to the exec request before the channel's CLOSE.

Long-running commands should run on their own thread and read the client's
input with `channel.recv()`, which returns `b""` once the client sends EOF
(for example after `stdin.close()` on a SpindleX client).

## Authentication Hooks

Besides `check_auth_password()` and `check_auth_publickey()`, `SSHServer`
offers these hooks:

```python
from spindlex.protocol.constants import AUTH_FAILED, AUTH_PARTIAL, AUTH_SUCCESSFUL

class MFAServer(SSHServer):
    def get_banner(self):
        # Sent once, before the first authentication reply.
        return "Authorized use only\n"

    def get_allowed_auths(self, username):
        return ["publickey", "keyboard-interactive"]

    def check_auth_publickey(self, username, key):
        # AUTH_PARTIAL: the key is accepted, but another method must follow.
        return AUTH_PARTIAL if key_is_known(username, key) else AUTH_FAILED

    def get_keyboard_interactive_prompts(self, username, submethods):
        # (name, instruction, [(prompt, echo), ...])
        return ("Verification", "Enter your one-time code", [("Code: ", False)])

    def check_auth_keyboard_interactive_response(self, username, responses):
        return AUTH_SUCCESSFUL if otp_is_valid(username, responses[0]) else AUTH_FAILED
```

`AUTH_PARTIAL` tells the client that the method succeeded but more are needed
(multi-factor authentication). SpindleX clients continue with the next method
automatically.

## Connection Hooks

- `check_global_request(kind, msg)`: called for global requests other than
  `tcpip-forward`/`cancel-tcpip-forward` (for example
  `keepalive@openssh.com`). Return `True` to accept.
- `on_channel_closed(channel)`: called once both sides have closed a channel.
- `is_channel_authorized(channel, username)`: true only when the channel's own
  connection authenticated as `username`.

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

The SFTP server supports the operations OpenSSH's `sftp` client uses,
including `SETSTAT`/`FSETSTAT` (permissions, times and size - so `truncate()`
works), `SYMLINK` and `READLINK`. The session ends, and its open files are
closed, when the client disconnects.

## Advanced Configuration

`SSHServerManager` provides several settings to tune server behavior. **Note: These methods must be called before calling `start_server()` to take effect.**

- `set_max_connections(n)`: Limit concurrent connections.
- `set_connection_timeout(s)`: Timeout for the initial socket connection.
- `set_auth_timeout(s)`: Timeout for the authentication handshake.
