# SpindleX

**A high-performance, pure-Python SSHv2 and SFTP library.**

[![PyPI version](https://img.shields.io/pypi/v/spindlex.svg?style=flat-square&color=blue)](https://badge.fury.io/py/spindlex)
[![Python Support](https://img.shields.io/badge/python-3-blue.svg?style=flat-square)](https://pypi.org/project/spindlex/)
[![Coverage](https://img.shields.io/badge/coverage-50%25-success?style=flat-square)](https://gitlab.com/daveops.world/development/python/spindle/-/commits/main)
[![License](https://img.shields.io/badge/license-MIT-informational?style=flat-square)](https://opensource.org/licenses/MIT)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000?style=flat-square)](https://github.com/psf/black)

SpindleX is a modern SSH protocol implementation engineered for speed, security, and a seamless developer experience. By leveraging optimized protocol parsing and modern cryptographic primitives, SpindleX delivers a significantly more performant alternative to legacy Python SSH libraries.

[Quick Start](#quick-start) • [Performance](#performance) • [Architecture](#architecture) • [Security](#security-policy) • [Documentation](https://spindlex.readthedocs.io/)

---

## Technical Highlights

*   **Optimized I/O**: Intelligent 32KB read buffering architecture minimizes syscall overhead.
*   **Modern Cryptography**: Native support for Ed25519, Curve25519, and ChaCha20-Poly1305.
*   **Zero Dependencies**: Pure-Python core with no C extensions, ensuring universal compatibility.
*   **High Concurrency**: Built-in `async/await` primitives for modern, scalable network applications.
*   **Type Safety**: 100% type-hinted codebase for robust IDE integration and static analysis.

---

## Performance Benchmarks

SpindleX is designed for low-latency environments. In head-to-head comparisons with `paramiko`, SpindleX demonstrates a commanding lead in protocol efficiency:

| Operation | SpindleX (avg) | Traditional (avg) | Improvement |
| :--- | :--- | :--- | :--- |
| **Handshake & Connect** | **0.035s** | 0.077s | **54% Faster** |
| **SFTP Transfer (10MB)** | **0.019s** | 0.061s | **69% Faster** |
| **Command Execution** | **0.129s** | 0.127s | **Comparable** |

### Engineering for Speed
1.  **Adaptive Buffering**: Reduces `socket.recv()` frequency by chunking protocol data.
2.  **TCP Fast-Path**: Automatically manages `TCP_NODELAY` to bypass Nagle's algorithm.
3.  **Streamlined KEX**: Optimized version exchange and key-re-exchange logic.

---

## Quick Start

### Installation

```bash
pip install spindlex
```

### Basic Usage

```python
from spindlex import SSHClient

# High-level client with automatic resource management
with SSHClient() as client:
    client.connect('deploy.production.local', username='admin')
    
    # Execute commands with captured streams
    stdin, stdout, stderr = client.exec_command('uptime')
    print(f"Status: {stdout.read().decode().strip()}")
    
    # Atomic SFTP operations
    with client.open_sftp() as sftp:
        sftp.put('payload.tar.gz', '/tmp/payload.tar.gz')
```

---

## Architecture

The library is structured into four distinct, auditable layers:

1.  **Transport**: Manages the encrypted tunnel and binary packet protocol.
2.  **Authentication**: Implements Password, Public Key (RSA, ECDSA, Ed25519), and GSSAPI.
3.  **Channel**: Multiplexes shell, exec, and port-forwarding over a single connection.
4.  **Application**: High-level abstractions for SSH and SFTP workflows.

---

## Security Policy

*   **Hardened Defaults**: Legacy SHA-1 and weak ciphers are disabled by design.
*   **Mandatory Verification**: Host key verification is enforced unless explicitly overridden.
*   **Privacy Aware**: Built-in log sanitizers ensure credentials never reach telemetry.

To report a vulnerability, please use the [GitLab Security Issue Tracker](https://gitlab.com/daveops.world/development/python/spindle/-/issues) with the `security` label.

---

## License

SpindleX is released under the **MIT License**. See [LICENSE](LICENSE) for the full text.

---

<div align="center">
  <sub>Developed with precision by <strong>Di3Z1E</strong>.</sub>
</div>
