# Spindle

[![Build Status](https://github.com/spindle-dev/spindle/workflows/Build%20and%20Test/badge.svg)](https://github.com/spindle-dev/spindle/actions)
[![Coverage Status](https://codecov.io/gh/spindle-dev/spindle/branch/main/graph/badge.svg)](https://codecov.io/gh/spindle-dev/spindle)
[![PyPI version](https://badge.fury.io/py/spindle.svg)](https://badge.fury.io/py/spindle)
[![Python versions](https://img.shields.io/pypi/pyversions/spindle.svg)](https://pypi.org/project/spindle/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A pure-Python SSHv2 client/server library that provides secure, high-performance SSH and SFTP operations without GPL/LGPL dependencies. Built with modern security practices and comprehensive RFC 4251-4254 compliance.

## Features

- **🔒 Modern Security**: Ed25519, ECDSA, ChaCha20-Poly1305, and other modern cryptographic algorithms
- **🐍 Pure Python**: No C extensions or system dependencies required
- **🚀 High Performance**: Optimized for speed with optional async/await support
- **📡 Full SSH Support**: Complete client and server implementations
- **📁 SFTP Support**: Comprehensive SFTP client and server functionality
- **🔄 Port Forwarding**: Local and remote port forwarding capabilities
- **🔐 Multiple Auth Methods**: Password, public key, keyboard-interactive, and GSSAPI
- **🛡️ Host Key Policies**: Flexible host key verification and management
- **📊 Comprehensive Logging**: Structured logging with security event monitoring
- **🧪 Well Tested**: Extensive test suite with high code coverage
- **📝 Type Hints**: Fully typed codebase for better development experience
- **⚖️ Apache 2.0 License**: No GPL/LGPL restrictions

## Quick Start

### Installation

```bash
pip install spindle
```

### Basic Usage

```python
from spindle import SSHClient, AutoAddPolicy

# Create and configure client
client = SSHClient()
client.set_missing_host_key_policy(AutoAddPolicy())

# Connect and execute commands
client.connect('example.com', username='user', password='password')
stdin, stdout, stderr = client.exec_command('ls -la')
print(stdout.read().decode())

# Use SFTP
sftp = client.open_sftp()
sftp.get('/remote/file.txt', '/local/file.txt')
sftp.close()

client.close()
```

### Key-Based Authentication

```python
from spindle import SSHClient
from spindle.crypto.pkey import Ed25519Key

# Load private key
private_key = Ed25519Key.from_private_key_file('/path/to/private_key')

client = SSHClient()
client.connect('example.com', username='user', pkey=private_key)
```

### Context Manager Support

```python
from spindle import SSHClient

with SSHClient() as client:
    client.connect('example.com', username='user', password='password')
    
    stdin, stdout, stderr = client.exec_command('whoami')
    print(f"Logged in as: {stdout.read().decode().strip()}")
    
    with client.open_sftp() as sftp:
        files = sftp.listdir('.')
        print(f"Files: {files}")
```

## Advanced Features

### Async Support

```python
import asyncio
from spindle.client.async_ssh_client import AsyncSSHClient

async def main():
    async with AsyncSSHClient() as client:
        await client.connect('example.com', username='user', password='password')
        result = await client.exec_command('echo "Hello, Async World!"')
        print(result.stdout.decode())

asyncio.run(main())
```

### Port Forwarding

```python
from spindle import SSHClient

client = SSHClient()
client.connect('jump-server.com', username='user', password='password')

# Local port forwarding
transport = client.get_transport()
local_port = transport.request_port_forward('', 8080, 'internal-server', 80)
print(f"Forwarding localhost:{local_port} -> internal-server:80")
```

### SSH Server

```python
from spindle import SSHServer
from spindle.crypto.pkey import Ed25519Key

class MySSHServer(SSHServer):
    def check_auth_password(self, username, password):
        return self.AUTH_SUCCESSFUL if password == 'secret' else self.AUTH_FAILED
    
    def check_channel_exec_request(self, channel, command):
        if command == b'whoami':
            channel.send(b'ssh-library-user\n')
            channel.send_exit_status(0)
        channel.close()
        return True

# Start server
host_key = Ed25519Key.generate()
server = MySSHServer()
# ... (additional server setup)
```

## Security

Spindle is designed with security as a primary concern:

- **Secure Defaults**: Modern algorithms enabled by default
- **Host Key Verification**: Strict host key checking available
- **Constant-Time Operations**: Protection against timing attacks
- **Sanitized Logging**: Automatic redaction of sensitive data
- **Regular Security Audits**: Continuous security monitoring

See our [Security Guidelines](https://spindle.readthedocs.io/en/latest/security.html) for detailed security information.

## Performance

Spindle is optimized for performance:

- **Efficient Crypto**: Leverages the `cryptography` library's optimized implementations
- **Async Support**: Optional asyncio support for high-concurrency applications
- **Connection Pooling**: Reuse connections for multiple operations
- **Streaming**: Support for streaming large file transfers

## Documentation

- **[Quick Start Guide](https://spindle.readthedocs.io/en/latest/quickstart.html)**
- **[User Guide](https://spindle.readthedocs.io/en/latest/user_guide/index.html)**
- **[API Reference](https://spindle.readthedocs.io/en/latest/api_reference/index.html)**
- **[Examples](https://spindle.readthedocs.io/en/latest/examples/index.html)**
- **[Security Guidelines](https://spindle.readthedocs.io/en/latest/security.html)**

## Installation Options

### Basic Installation

```bash
pip install spindle
```

### Development Installation

```bash
pip install spindle[dev]
```

### Optional Features

```bash
# Async support
pip install spindle[async]

# GSSAPI authentication (Unix only)
pip install spindle[gssapi]

# Documentation building
pip install spindle[docs]

# All features
pip install spindle[dev,async,gssapi,docs]
```

## Requirements

- Python 3.8+
- cryptography >= 41.0.0
- typing-extensions >= 4.0.0 (Python < 3.10)

## Supported Platforms

- Linux
- macOS
- Windows

## Supported Algorithms

### Key Exchange
- curve25519-sha256
- ecdh-sha2-nistp256
- diffie-hellman-group14-sha256

### Host Key Types
- ssh-ed25519
- ecdsa-sha2-nistp256
- rsa-sha2-256
- rsa-sha2-512

### Ciphers
- chacha20-poly1305@openssh.com
- aes256-gcm@openssh.com
- aes128-gcm@openssh.com
- aes256-ctr
- aes192-ctr
- aes128-ctr

### MAC Algorithms
- hmac-sha2-256
- hmac-sha2-512
- hmac-sha2-256-etm@openssh.com
- hmac-sha2-512-etm@openssh.com

## Command Line Tools

Spindle includes useful command-line tools:

### SSH Key Generation

```bash
# Generate Ed25519 key
spindle-keygen -t ed25519 -f ~/.ssh/id_ed25519

# Generate RSA key
spindle-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa
```

### Performance Benchmarking

```bash
# Benchmark cryptographic operations
spindle-benchmark --crypto-only

# Benchmark SSH operations
spindle-benchmark -H example.com -u user -p password
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/spindle-dev/spindle.git
cd spindle

# Install in development mode
pip install -e .[dev]

# Run tests
pytest

# Run linting
black ssh_library tests
isort ssh_library tests
flake8 ssh_library tests
mypy ssh_library
```

## License

Spindle is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and changes.

## Support

- **Documentation**: https://spindle.readthedocs.io/
- **Issues**: https://github.com/spindle-dev/spindle/issues
- **Discussions**: https://github.com/spindle-dev/spindle/discussions

## Comparison with Other Libraries

| Feature | Spindle | Paramiko | AsyncSSH | Fabric |
|---------|-------------|----------|----------|--------|
| Pure Python | ✅ | ✅ | ✅ | ✅ |
| Modern Crypto | ✅ | ⚠️ | ✅ | ⚠️ |
| Async Support | ✅ | ❌ | ✅ | ❌ |
| Type Hints | ✅ | ⚠️ | ✅ | ⚠️ |
| Server Support | ✅ | ✅ | ✅ | ❌ |
| License | Apache 2.0 | LGPL | EPL | BSD |
| Python 3.8+ | ✅ | ✅ | ✅ | ✅ |

## Acknowledgments

Spindle builds upon the excellent work of:

- The [cryptography](https://cryptography.io/) library for cryptographic operations
- The SSH protocol specifications (RFC 4251-4254)
- The OpenSSH project for algorithm implementations and security practices

---

**Made with ❤️ by the Spindle Team**