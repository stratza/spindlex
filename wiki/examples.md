# 💡 Code Examples & Recipes

Real-world examples and code recipes for common SpindleX use cases.

## 🚀 Quick Examples

### Basic SSH Connection
```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    stdin, stdout, stderr = client.exec_command('ls -la')
    print(stdout.read().decode())
```

### File Transfer
```python
from spindlex import SSHClient

with SSHClient() as client:
    client.connect('server.com', username='user', password='pass')
    
    with client.open_sftp() as sftp:
        # Upload file
        sftp.put('/local/file.txt', '/remote/file.txt')
        
        # Download file
        sftp.get('/remote/data.json', '/local/data.json')
```

### Key-Based Authentication
```python
from spindlex import SSHClient
from spindlex.crypto.pkey import Ed25519Key

private_key = Ed25519Key.from_private_key_file('~/.ssh/id_ed25519')

with SSHClient() as client:
    client.connect('server.com', username='user', pkey=private_key)
    stdin, stdout, stderr = client.exec_command('whoami')
    print(f"Connected as: {stdout.read().decode().strip()}")
```

## 🔧 DevOps Automation

### Server Deployment
```python
from spindlex import SSHClient
import concurrent.futures

def deploy_to_server(server_info):
    hostname, username, key_file = server_info
    
    with SSHClient() as client:
        private_key = Ed25519Key.from_private_key_file(key_file)
        client.connect(hostname, username=username, pkey=private_key)
        
        # Deployment commands
        commands = [
            'cd /app',
            'git pull origin main',
            'docker-compose down',
            'docker-compose up -d',
            'docker-compose ps'
        ]
        
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            print(f"{hostname}: {cmd}")
            print(stdout.read().decode())

# Deploy to multiple servers
servers = [
    ('web1.example.com', 'deploy', '~/.ssh/deploy_key'),
    ('web2.example.com', 'deploy', '~/.ssh/deploy_key'),
    ('web3.example.com', 'deploy', '~/.ssh/deploy_key'),
]

with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
    executor.map(deploy_to_server, servers)
```

## 📊 More Examples

For comprehensive examples, see our detailed guides:

- [SSH Client Guide](ssh-client-guide) - Complete client documentation
- [SFTP Operations](sftp-operations) - File transfer examples
- [Async Programming](async-programming) - High-performance patterns
- [Port Forwarding](port-forwarding) - Tunneling examples
- [DevOps Automation](devops-automation) - Automation recipes