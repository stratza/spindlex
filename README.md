# Spindle

A pure-Python SSHv2 client/server library that provides secure, high-performance SSH and SFTP operations without GPL/LGPL dependencies.

## Features

- **Pure Python**: No C extensions or system dependencies
- **Modern Security**: Ed25519, ECDSA, ChaCha20-Poly1305, and other modern algorithms
- **Full SSH Support**: Client and server implementations with all major features
- **SFTP Support**: Complete SFTP client and server functionality
- **Async Support**: Optional asyncio support for high-performance applications
- **Comprehensive**: Port forwarding, authentication methods, host key policies
- **Well-Tested**: Extensive test suite with high code coverage
- **Type Hints**: Fully typed codebase for better development experience

## Quick Start

### Installation

```bash
pip install spindle
```

### Basic Usage

```python
from spindle import SSHClient

# Create client and connect
client = SSHClient()
client.connect('example.com', username='user', password='password')

# Execute a command
stdin, stdout, stderr = client.exec_command('ls -la')
print(stdout.read().decode())

# Use SFTP
sftp = client.open_sftp()
sftp.get('/remote/file.txt', '/local/file.txt')
sftp.close()

# Clean up
client.close()
```

### Key-based Authentication

```python
from spindle import SSHClient
from spindle.crypto.pkey import Ed25519Key

# Load private key
private_key = Ed25519Key.from_private_key_file('/path/to/private_key')

client = SSHClient()
client.connect(
    hostname='example.com',
    username='user',
    pkey=private_key
)
```

## Documentation

- [Quick Start Guide](https://spindle.readthedocs.io/en/latest/quickstart.html)
- [User Guide](https://spindle.readthedocs.io/en/latest/user_guide/)
- [API Reference](https://spindle.readthedocs.io/en/latest/api_reference/)
- [Examples](https://spindle.readthedocs.io/en/latest/examples/)
- [Security Guide](https://spindle.readthedocs.io/en/latest/security.html)

## Requirements

- Python 3.8+
- cryptography >= 3.0

## Optional Dependencies

- `asyncio` support: `pip install spindle[async]`
- Development tools: `pip install spindle[dev]`
- GSSAPI authentication: `pip install spindle[gssapi]` (Unix only)

## Contributing

We welcome contributions! Please see our [Contributing Guide](https://spindle.readthedocs.io/en/latest/contributing.html) for details.

## Security

For security issues, please email security@spindle.org instead of creating a public issue.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with modern Python cryptography
- Inspired by the need for a pure-Python SSH library
- Thanks to all contributors and the Python community
