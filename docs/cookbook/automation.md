# Automation Recipes

Solve infrastructure problems with these automation scripts.

## <a name="sudo-execution"></a>Sudo Command Execution

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

## <a name="parallel-commands"></a>Parallel Command Execution

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

## <a name="proxy-jump"></a>SSH ProxyJump (Bastion Hosts)

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

## <a name="log-tailing"></a>Real-time Log Tailing

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
```
