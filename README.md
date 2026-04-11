<div align="center">
  <img src="docs/_static/figure.png" width="160" height="160" alt="SpindleX Logo">
  <h1>SpindleX</h1>
  <p><strong>A modern, high-performance, pure-Python SSHv2 and SFTP library.</strong></p>

[![CI Status](https://img.shields.io/github/actions/workflow/status/Di3Z1E/spindlex/ci.yml?branch=main&style=for-the-badge&logo=github)](https://github.com/Di3Z1E/spindlex/actions)
[![Coverage](https://codecov.io/gh/Di3Z1E/spindlex/branch/main/graph/badge.svg)](https://codecov.io/gh/Di3Z1E/spindlex)
[![PyPI Version](https://img.shields.io/pypi/v/spindlex?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/spindlex/)
[![Python Support](https://img.shields.io/pypi/pyversions/spindlex?style=for-the-badge&logo=python&logoColor=white)](https://pypi.org/project/spindlex/)
[![License](https://img.shields.io/pypi/l/spindlex?style=for-the-badge&color=blue)](https://github.com/Di3Z1E/spindlex/blob/main/LICENSE)
[![PyPI Downloads](https://img.shields.io/pypi/dm/spindlex?style=for-the-badge&logo=pypi&logoColor=white&color=brightgreen)](https://pepy.tech/projects/spindlex)
[![Socket Badge](https://badge.socket.dev/pypi/package/spindlex/0.4.1?artifact_id=tar-gz&style=for-the-badge)](https://badge.socket.dev/pypi/package/spindlex/0.4.1?artifact_id=tar-gz)

<p align="center">
  <a href="https://spindlex.readthedocs.io/"><strong>Explore the Docs »</strong></a>
  <br />
  <br />
  <a href="#-quick-start">Quick Start</a>
  •
  <a href="https://spindlex.readthedocs.io/migration/paramiko/">Migration Guide</a>
  •
  <a href="https://spindlex.readthedocs.io/cookbook/">Cookbook</a>
  •
  <a href="#-performance">Performance</a>
  •
  <a href="#-security">Security</a>
  •
  <a href="meta/CONTRIBUTING.md">Contributing</a>
</p>
</div>

---

SpindleX is a modern SSH protocol implementation engineered for **speed**, **security**, and a **seamless developer experience**. It provides a significantly more performant and cleaner alternative to legacy Python SSH libraries.

## ✨ Key Features

*   🚀 **High Performance**: Optimized with **Adaptive Buffering** and **TCP Fast-Path**. Up to 60% faster SFTP transfers.
*   📦 **Zero Dependencies**: Pure-Python core. No `gcc`, no `python-dev`. Perfect for minimal Docker images.
*   🔄 **Native Async**: First-class support for `asyncio` with `AsyncSSHClient` and `AsyncSFTPClient`.
*   🛡️ **Modern Security**: Ed25519, ECDSA, ChaCha20-Poly1305 by default.
*   🏷️ **Fully Typed**: 100% type-hinted codebase for robust IDE integration.

---

## 🚀 Quick Start

### Installation

```bash
# Using pip
pip install spindlex

# Using uv (recommended)
uv pip install spindlex
```

### Basic Usage

<details>
<summary><b>Synchronous Example</b></summary>

```python
from spindlex import SSHClient
from spindlex.hostkeys.policy import AutoAddPolicy

with SSHClient() as client:
    client.set_missing_host_key_policy(AutoAddPolicy())
    client.connect('example.com', username='admin')
    
    stdin, stdout, stderr = client.exec_command('uptime')
    print(f"Status: {stdout.read().decode().strip()}")
```
</details>

<details>
<summary><b>Asynchronous Example</b></summary>

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
</details>

---

## ⚡ Performance

SpindleX is designed for low-latency environments. In head-to-head comparisons, SpindleX demonstrates a commanding lead in protocol efficiency:

| Operation | SpindleX (avg) | Traditional (avg) | Improvement |
| :--- | :--- | :--- | :--- |
| **Handshake & Connect** | **0.035s** | 0.077s | **54% Faster** |
| **SFTP Transfer (10MB)** | **0.019s** | 0.061s | **69% Faster** |

---

## 🛡️ Security

*   **Hardened Defaults**: Legacy SHA-1 and weak ciphers are disabled by design.
*   **Mandatory Verification**: Host key verification is enforced unless explicitly overridden.
*   **Privacy Aware**: Built-in log sanitizers ensure credentials never reach telemetry.
*   **Vulnerability Reporting**: See [meta/SECURITY.md](meta/SECURITY.md).

---

## 🤝 Contributing

Contributions are welcome! See [meta/CONTRIBUTING.md](meta/CONTRIBUTING.md) to get started.

---

## 📄 License

SpindleX is released under the **MIT License**. See [LICENSE](LICENSE) for the full text.

---

<div align="center">
  <sub>Developed with precision by <strong>Di3Z1E</strong>.</sub>
  <br/>
  <sub>&copy; 2024 SpindleX Project</sub>
</div>
