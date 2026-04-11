# SpindleX

**A modern, high-performance, pure-Python SSHv2 and SFTP library.**

[![CI Status](https://img.shields.io/github/actions/workflow/status/Di3Z1E/spindlex/ci.yml?branch=main&style=flat-square)](https://github.com/Di3Z1E/spindlex/actions)
[![Coverage](https://img.shields.io/badge/coverage-50%25-orange?style=flat-square)](https://codecov.io/gh/Di3Z1E/spindlex)
[![PyPI Version](https://img.shields.io/pypi/v/spindlex?style=flat-square)](https://pypi.org/project/spindlex/)
[![Python Support](https://img.shields.io/pypi/pyversions/spindlex?style=flat-square)](https://pypi.org/project/spindlex/)
[![License](https://img.shields.io/pypi/l/spindlex?style=flat-square)](https://github.com/Di3Z1E/spindlex/blob/main/LICENSE)

SpindleX is a modern SSH protocol implementation engineered for speed, security, and a seamless developer experience. It provides a significantly more performant and cleaner alternative to legacy Python SSH libraries like Paramiko.

---

## 🚀 Quick Start (with [uv](https://github.com/astral-sh/uv))

```bash
uv pip install spindlex
```

---

[**Explore the Full Documentation »**](https://spindlex.readthedocs.io/)

[Quick Start](#quick-start) • [Migration Guide](https://spindlex.readthedocs.io/migration/paramiko/) • [Cookbook](https://spindlex.readthedocs.io/cookbook/) • [Performance](#performance) • [Security](#security)

---

## Why SpindleX?

*   ⚡ **High Performance**: Optimized with **Adaptive Buffering** and **TCP Fast-Path** for minimal latency. Up to 60% faster SFTP transfers than traditional libraries.
*   📦 **Zero Dependencies**: Pure-Python core. No `gcc`, no `python-dev`, no system headers. Perfect for minimal Docker images.
*   🔄 **Native Async**: First-class support for `asyncio` with `AsyncSSHClient` and `AsyncSFTPClient`.
*   🛡️ **Modern Security**: Supports Ed25519, ECDSA, ChaCha20-Poly1305, and other modern algorithms by default.
*   🏷️ **Fully Typed**: 100% type-hinted codebase for robust IDE integration and static analysis.

---

## Quick Start

### Installation

```bash
pip install spindlex
```

### Basic Usage

#### Synchronous Example

```python
from spindlex import SSHClient
from spindlex.hostkeys.policy import AutoAddPolicy

with SSHClient() as client:
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect('example.com', username='admin')
    
    stdin, stdout, stderr = client.exec_command('uptime')
    print(f"Status: {stdout.read().decode().strip()}")
```

#### Asynchronous Example

```python
import asyncio
from spindlex import AsyncSSHClient

async def run():
    async with AsyncSSHClient() as client:
        await client.connect('example.com', username='admin')
        stdin, stdout, stderr = await client.exec_command('uptime')
        print(await stdout.read())

asyncio.run(run())
```

---

## Performance

SpindleX is designed for low-latency environments. In head-to-head comparisons, SpindleX demonstrates a commanding lead in protocol efficiency:

| Operation | SpindleX (avg) | Traditional (avg) | Improvement |
| :--- | :--- | :--- | :--- |
| **Handshake & Connect** | **0.035s** | 0.077s | **54% Faster** |
| **SFTP Transfer (10MB)** | **0.019s** | 0.061s | **69% Faster** |

---

## Security

*   **Hardened Defaults**: Legacy SHA-1 and weak ciphers are disabled by design.
*   **Mandatory Verification**: Host key verification is enforced unless explicitly overridden.
*   **Privacy Aware**: Built-in log sanitizers ensure credentials never reach telemetry.
*   **Vulnerability Reporting**: To report a security issue, please open a GitHub issue with the 'security' label.

---

## License

SpindleX is released under the **MIT License**. See [LICENSE](LICENSE) for the full text.

---

<div align="center">
  <sub>Developed with precision by <strong>Di3Z1E</strong>.</sub>
</div>
