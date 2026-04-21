<div align="center">
  <img src="docs/_static/figure.png" width="160" height="160" alt="SpindleX - High-Performance SSH and SFTP Library for Python">
  <h1>SpindleX</h1>
  <p><strong>Modern SSH library for secure automation, recursive SFTP, and high-performance deployments.</strong></p>

[![CI Status](https://img.shields.io/github/actions/workflow/status/Di3Z1E/spindlex/ci.yml?branch=main&style=for-the-badge&logo=github)](https://github.com/Di3Z1E/spindlex/actions)
[![Coverage](https://img.shields.io/codecov/c/github/Di3Z1E/spindlex?style=for-the-badge&logo=codecov)](https://codecov.io/gh/Di3Z1E/spindlex)
[![PyPI Version](https://img.shields.io/pypi/v/spindlex?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/spindlex/)
[![Python Support](https://img.shields.io/pypi/pyversions/spindlex?style=for-the-badge&logo=python&logoColor=white)](https://pypi.org/project/spindlex/)
[![License](https://img.shields.io/pypi/l/spindlex?style=for-the-badge&color=blue)](https://github.com/Di3Z1E/spindlex/blob/main/LICENSE)
[![PyPI Downloads](https://img.shields.io/pypi/dm/spindlex?style=for-the-badge&logo=pypi&logoColor=white&color=brightgreen)](https://pypi.org/project/spindlex/)
[![Security Status](https://img.shields.io/badge/socket-security-brightgreen?style=for-the-badge&logo=socket.io)](https://badge.socket.dev/pypi/package/spindlex/0.6.3)

  <br />
  <a href="#-quick-start">Quick Start</a>
  •
  <a href="https://spindlex.readthedocs.io/">Docs</a>
  •
  <a href="#-security">Security</a>
  •
  <a href="meta/CONTRIBUTING.md">Contributing</a>
</div>

---

SpindleX is a modern SSH protocol implementation engineered for **speed**, **security**, and a **seamless developer experience**. It provides a clean, performant alternative to legacy Python SSH libraries.

## ✨ Key Features

*   🚀 **High Performance**: Optimized protocol implementation with internal buffering designed for high-throughput SFTP and command execution.
*   📦 **Modern Architecture**: Clean, modular codebase built from the ground up for maintainability. Leverages the industry-standard `cryptography` library for robust, hardware-accelerated security.
*   🔄 **Native Async**: First-class support for `asyncio` with `AsyncSSHClient` and `AsyncSFTPClient`.
*   🛡️ **Secure by Default**: Modern algorithms like Ed25519, ECDSA, and AES-256-CTR with HMAC-SHA2 are prioritized. Legacy SHA-1 and weak ciphers are disabled in the default configuration.
*   🏷️ **Fully Typed**: Comprehensive type hints across the codebase for robust IDE integration and static analysis.

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

## 📺 Demos

> [!TIP]
> **View Live Execution Results**: See the [Verified Demo Outputs](docs/demo_results.md) from the latest run.


See SpindleX in action across various high-performance scenarios:

### 🏗️ Full Cycle Automation
**[complex_setup_demo.py](demo/complex_setup_demo.py)**: Watch SpindleX generate Ed25519 keys, deploy them via SFTP, and execute privileged `sudo` commands—all in under 6 seconds.

![Full Cycle Demo](demo/gifs/complex-demo.gif)

---

### 🚀 Performance & Multi-Tasking

| **Command Execution** | **SFTP Operations** |
|:---:|:---:|
| ![SSH Demo](demo/gifs/basic-ssh-commands.gif) | ![SFTP Demo](demo/gifs/sftp-demo.gif) |
| *Blazing fast command processing* | *High-throughput recursive transfers* |

| **Async Concurrency** | **Benchmark vs Paramiko** |
|:---:|:---:|
| ![Async Demo](demo/gifs/async-demo.gif) | ![Benchmark](demo/gifs/benchmark.gif) |
| *Native asyncio integration* | *Up to ~2.6x faster (results vary by environment)* |


---

## ⚡ Performance

SpindleX is designed for high-throughput, low-latency environments. It utilizes internal read buffering (32KB chunks) and optimized packet handling to reduce system call overhead and improve protocol efficiency. Actual performance gains are environment-dependent.

### 📊 Benchmark vs Paramiko
In testing, SpindleX has been observed to outperform legacy libraries in connection establishment and bulk SFTP transfers. Results are environment-dependent — run the included benchmark to verify on your setup.

| Library | Connection Time (Avg)* | Overhead |
|:---|:---:|:---:|
| **SpindleX** | **0.32s** | **Low** |
| Paramiko | 0.85s | High |

*\*Results from a sample run. Your numbers will vary based on network, server, and hardware.*

> [!TIP]
> Run the included benchmark script to compare performance in your environment:
> ```bash
> python demo/benchmark.py
> ```

---

## 🛡️ Security

*   **Hardened Defaults**: Modern cryptographic primitives are used by default. Legacy algorithms are disabled unless explicitly configured.
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
  <sub>&copy; 2026 SpindleX Project</sub>
</div>
