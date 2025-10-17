# ❓ Frequently Asked Questions

Common questions and answers about SpindleX.

## 🚀 General Questions

### What is SpindleX?
SpindleX is a pure-Python SSH client and server library designed for modern applications. It provides secure, high-performance SSH and SFTP operations without GPL/LGPL dependencies.

### Why choose SpindleX over other SSH libraries?
- **Pure Python**: No C extensions, easy deployment
- **Modern Security**: Ed25519, ChaCha20-Poly1305, and other modern algorithms
- **Async Support**: Built-in asyncio support for high-performance applications
- **Business-Friendly**: Apache 2.0 license
- **Developer Experience**: Full type hints and modern APIs

### Is SpindleX production-ready?
Yes! SpindleX is built with production use in mind, featuring comprehensive error handling, security best practices, and extensive testing.

## 🔧 Installation & Setup

### What Python versions are supported?
SpindleX supports Python 3.8+ on Linux, macOS, and Windows.

### How do I install SpindleX?
```bash
pip install spindlex
```

### Can I use SpindleX in Docker containers?
Yes! SpindleX works perfectly in Docker containers. See our [Installation Guide](installation) for Docker-specific instructions.

## 🔐 Security Questions

### Is SpindleX secure?
Yes! SpindleX implements modern cryptographic algorithms and follows SSH security best practices. It supports Ed25519, ECDSA, ChaCha20-Poly1305, and other secure algorithms.

### How do I verify host keys?
Use SpindleX's host key policies:
```python
from spindlex.hostkeys.policy import RejectPolicy
client.set_missing_host_key_policy(RejectPolicy())
```

### Can I use SpindleX with SSH agents?
Yes! SpindleX automatically supports SSH agents when `allow_agent=True` is set.

## ⚡ Performance Questions

### How fast is SpindleX?
SpindleX is optimized for performance with async support, connection pooling, and efficient protocols. See our [Performance Guide](performance-optimization) for benchmarks.

### Can I use SpindleX for high-concurrency applications?
Absolutely! Use the async version for maximum concurrency:
```python
from spindlex import AsyncSSHClient
```

## 🐛 Troubleshooting

### I'm getting "Connection refused" errors
- Check if the SSH server is running
- Verify the hostname and port
- Check firewall settings

### Authentication is failing
- Verify username and password/key
- Check SSH server configuration
- Ensure key permissions are correct (600 for private keys)

### SFTP operations are slow
- Enable compression: `client.connect(..., compress=True)`
- Use larger buffer sizes for file transfers
- Consider using async operations for multiple files

## 📚 More Help

- [Installation Guide](installation)
- [Quick Start Tutorial](quick-start)
- [Troubleshooting Guide](troubleshooting)
- [GitHub Issues](https://gitlab.com/daveops.world/development/python/spindlex/-/issues)