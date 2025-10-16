# SSH Library

A pure-Python SSHv2 client/server library offering secure, high-performance SSH and SFTP operations without GPL/LGPL dependencies.

## Features

- **Pure Python**: No native dependencies, works across platforms
- **Modern Security**: Ed25519/ECDSA keys by default, modern cipher suites
- **RFC Compliant**: Full SSHv2 protocol implementation (RFC 4251-4254)
- **Pluggable Crypto**: Uses cryptography library backend
- **Apache License**: No GPL/LGPL restrictions

## Installation

```bash
pip install ssh-library
```

## Quick Start

```python
import ssh_library

# SSH Client
with ssh_library.SSHClient() as client:
    client.connect('hostname', username='user', password='pass')
    stdin, stdout, stderr = client.exec_command('ls -la')
    print(stdout.read().decode())

# SFTP Operations
with ssh_library.SSHClient() as client:
    client.connect('hostname', username='user', key_filename='~/.ssh/id_ed25519')
    with client.open_sftp() as sftp:
        sftp.put('local_file.txt', 'remote_file.txt')
        sftp.get('remote_file.txt', 'downloaded_file.txt')
```

## Development Status

This library is currently under development. See the implementation tasks in `.kiro/specs/python-ssh-library/tasks.md` for current progress.

## License

Apache License 2.0 - see LICENSE file for details.