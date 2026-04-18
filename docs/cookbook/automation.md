# Automation Recipes

Solve infrastructure problems with these automation scripts.

## Sudo Command Execution {#sudo-execution}

Automate `sudo` commands by providing the password when prompted.

```python
from spindlex import SSHClient

def run_sudo(client, command, password):
    """
    Executes a command with sudo, handling the password prompt.
    """
    stdin, stdout, stderr = client.exec_command(f"sudo -S {command}")
    
    # Provide password when sudo asks
    stdin.write(f"{password}\n")
    stdin.flush()
    
    # Read the response
    return stdout.read().decode()

with SSHClient() as client:
    client.connect('server01', username='admin')
    result = run_sudo(client, "apt-get update", "my-secret-pass")
    print(result)
```

## Parallel Command Execution {#parallel-commands}

Run commands on multiple servers concurrently using SpindleX's native async support.

```python
import asyncio
from spindlex import AsyncSSHClient

async def run_on_server(hostname, command):
    try:
        async with AsyncSSHClient() as client:
            await client.connect(hostname, username='admin')
            stdin, stdout, stderr = await client.exec_command(command)
            output = await stdout.read()
            print(f"[{hostname}] {output.strip()}")
    except Exception as e:
        print(f"[{hostname}] Error: {e}")

async def main():
    servers = ['srv1', 'srv2', 'srv3', 'srv4']
    tasks = [run_on_server(s, 'uptime') for s in servers]
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())
```

## SSH ProxyJump (Bastion Hosts) {#proxy-jump}

Connect to a target host through a bastion (jump) host.

```python
from spindlex import SSHClient

with SSHClient() as bastion:
    bastion.connect('bastion.example.com', username='gatekeeper')
    
    # Open a direct channel to the internal target through the bastion
    transport = bastion.get_transport()
    dest_addr = ('internal-target.lan', 22)
    local_addr = ('localhost', 0)
    
    channel = transport.open_channel(
        "direct-tcpip", 
        dest_addr, 
        local_addr
    )

    # Connect to target using the channel as a socket
    with SSHClient() as target:
        target.connect(
            'internal-target.lan', 
            username='admin', 
            sock=channel
        )
        stdin, stdout, stderr = target.exec_command('hostname')
        print(f"Connected to: {stdout.read().decode()}")
```

## Real-time Log Tailing {#log-tailing}

Stream remote log files to your local console in real-time.

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('prod-app-01', username='devops')
    
    stdin, stdout, stderr = client.exec_command('tail -f /var/log/nginx/access.log')
    
    print("--- Streaming Remote Logs (Ctrl+C to stop) ---")
    try:
        for line in stdout:
            print(line.strip())
    except KeyboardInterrupt:
        print("Stopping log stream...")

## Custom Rekeying Policy

For high-security or high-compliance environments, you can tighten the rekeying thresholds.

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('secure-host', username='audit-user')
    
    # Rekey every 100MB or every 15 minutes
    transport = client.get_transport()
    transport.set_rekey_policy(
        bytes_limit=100 * 1024 * 1024, 
        time_limit=900
    )
    
    # Continue with secure operations
    # ...
```

## Keyboard-Interactive Authentication {#interactive-auth}

Use a custom handler to respond to server-driven authentication challenges.

```python
import getpass
from spindlex import SSHClient

def interactive_handler(title, instructions, prompts):
    """
    Handles keyboard-interactive challenges.
    'prompts' is a list of (prompt_text, echo_boolean) tuples.
    """
    answers = []
    print(f"\n--- {title} ---")
    if instructions:
        print(instructions)
        
    for text, echo in prompts:
        if echo:
            ans = input(text)
        else:
            ans = getpass.getpass(text)
        answers.append(ans)
    return answers

with SSHClient() as client:
    # This will trigger the interactive_handler if the server requests it
    client.connect(
        'mfa-enabled-host', 
        username='user', 
        handler=interactive_handler
    )
```

## GSSAPI/Kerberos Authentication {#gssapi-auth}

Authenticate using Kerberos tickets (SSO) in enterprise environments.

```python
from spindlex import SSHClient

with SSHClient() as client:
    # Set gss_auth=True to attempt Kerberos authentication
    client.connect(
        'kerberos-host.internal', 
        username='jdoe',
        gss_auth=True,
        gss_deleg_creds=True
    )
    print("Authenticated via Kerberos!")
```

## SSH Key Rotation {#key-rotation}

Automate the rotation of public keys across multiple servers.

```python
from spindlex import SSHClient
import os

def rotate_key(client, new_key_path):
    with open(new_key_path, 'r') as f:
        new_key = f.read().strip()
    
    # Append new key to authorized_keys
    client.exec_command(f'echo "{new_key}" >> ~/.ssh/authorized_keys')
    print("New key added.")

# Example usage
# ...
```

## Backing up Network Configs {#backup-configs}

Example of a script that backs up a remote configuration file with timestamping.

```python
from spindlex import SSHClient
from datetime import datetime

def backup_config(hostname, remote_path, local_dir):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    local_path = f"{local_dir}/{hostname}_{timestamp}.conf"
    
    with SSHClient() as client:
        client.connect(hostname, username='admin')
        with client.open_sftp() as sftp:
            sftp.get(remote_path, local_path)
            print(f"Backup saved to {local_path}")

# backup_config('router01', '/etc/config', './backups')
```
```
