<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=18,18,18,48,25,52,18,18,18&height=200&section=header&text=SpindleX&fontSize=80&fontColor=bb86fc&fontAlignY=45&desc=High-Performance%20SSH%20%26%20SFTP%20for%20Python&descSize=22&descColor=b39ddb&descAlignY=70&animation=fadeIn" width="100%" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=24&duration=3000&pause=1000&color=bb86fc&center=true&vCenter=true&width=600&lines=High-Performance+SSHv2+%E2%9A%A1;Native+AsyncIO+Support+%F0%9F%8C%91;Recursive+SFTP+Automation+%F0%9F%94%84;Secure+by+Default+%E2%9A%99%EF%B8%8F" alt="Typing SVG" />

<br/>

[![CI Status](https://img.shields.io/github/actions/workflow/status/Di3Z1E/spindlex/ci.yml?branch=main&style=for-the-badge&logo=github&labelColor=1a1a1a)](https://github.com/Di3Z1E/spindlex/actions)
[![Coverage](https://img.shields.io/codecov/c/github/Di3Z1E/spindlex?style=for-the-badge&logo=codecov&labelColor=1a1a1a)](https://codecov.io/gh/Di3Z1E/spindlex)
[![PyPI Version](https://img.shields.io/pypi/v/spindlex?style=for-the-badge&logo=pypi&logoColor=white&labelColor=1a1a1a)](https://pypi.org/project/spindlex/)
[![License](https://img.shields.io/pypi/l/spindlex?style=for-the-badge&color=bb86fc&labelColor=1a1a1a)](https://github.com/Di3Z1E/spindlex/blob/main/LICENSE)

<br />

<a href="#-quick-start"><b><font color="#bb86fc">Quick Start</font></b></a> • <a href="https://spindlex.readthedocs.io/"><b><font color="#bb86fc">Documentation</font></b></a> • <a href="meta/SECURITY.md"><b><font color="#bb86fc">Security</font></b></a> • <a href="meta/CONTRIBUTING.md"><b><font color="#bb86fc">Contributing</font></b></a>

</div>

---

## ⚡ Overview

**SpindleX** is a modern SSH protocol implementation for Python 3.8+. It is designed for high-performance automation and secure file transfers, providing a clean alternative to legacy SSH libraries.

### 🔥 Key Features

- 🚀 **High Performance**: Optimized internal buffering (32KB chunks) for high-throughput SFTP and command execution.
- 🔄 **Native Async**: First-class `asyncio` support via `AsyncSSHClient` and `AsyncSFTPClient`.
- 🛡️ **Security**: Prioritizes modern primitives (Ed25519, AES-256-CTR) and disables legacy/weak ciphers.
- 🔗 **Advanced Tunneling**: Support for **ProxyJump** (bastion hosts) and TCP port forwarding.
- 📂 **Recursive SFTP**: Native support for recursive directory uploads and downloads.
- 🏷️ **Fully Typed**: Comprehensive type hints for IDE integration and static analysis.

---

## 💎 Why SpindleX?

- 💼 **Business Friendly**: MIT Licensed. Permissive use for commercial and proprietary projects.
- 📖 **Maintainable Code**: Modular architecture designed for clarity and easier security auditing.
- 🛠️ **Modern API**: Clean, intuitive interface with consistent error handling and minimal dependencies.
- 🧊 **Focused Scope**: No support for insecure legacy protocols, resulting in a leaner and more secure codebase.

---

## 🛠️ Tech Stack

<div align="left">

**Core Logic** ![Python](https://img.shields.io/badge/Python-3776AB?style=flat-square&logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Cryptography-FFD43B?style=flat-square&logo=python&logoColor=3776AB)

**Protocol** ![SSH](https://img.shields.io/badge/SSH-000000?style=flat-square&logo=ssh&logoColor=white)
![SFTP](https://img.shields.io/badge/SFTP-444444?style=flat-square&logo=files&logoColor=white)

**Concurrency** ![Asyncio](https://img.shields.io/badge/Asyncio-3776AB?style=flat-square&logo=python&logoColor=white)

</div>

---

## 🚀 Quick Start

### Installation

```bash
# Using pip
pip install spindlex

# Using uv
uv pip install spindlex
```

### 💻 Usage Preview

<details>
<summary><b>Synchronous Example</b></summary>

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.get_host_keys().load()
    client.connect('example.com', username='admin')

    stdin, stdout, stderr = client.exec_command('uptime')
    print(f"Server Status: {stdout.read().decode().strip()}")
```
</details>

<details>
<summary><b>Asynchronous Example</b></summary>

```python
import asyncio
from spindlex import AsyncSSHClient

async def main():
    async with AsyncSSHClient() as client:
        await client.connect('example.com', username='admin')
        stdin, stdout, stderr = await client.exec_command('df -h')
        print(await stdout.read())

asyncio.run(main())
```
</details>

---

## 📊 Performance Benchmarks

SpindleX is optimized for high-throughput environments, significantly reducing protocol overhead compared to standard implementations.

| Operation | SpindleX | Legacy Libraries | Improvement |
|:---|:---:|:---:|:---:|
| **Handshake** | 0.32s | 0.85s | **~2.6x** |
| **Bulk SFTP** | 45 MB/s | 18 MB/s | **~2.5x** |
| **Overhead** | Low | High | 🔥 |

> [!TIP]
> Run the benchmark suite on your own hardware:  
> `python scripts/benchmark_compare.py`

---

## 🛡️ Security

- **Verification Enforced**: Host key verification is mandatory by default.
- **Log Sanitization**: Credentials and sensitive data are automatically filtered from logs.
- **Modern Defaults**: Ed25519 and ECDSA preferred for key exchange.
- **Full Policy**: See [meta/SECURITY.md](meta/SECURITY.md) for vulnerability reporting and security standards.

---

## 🤝 Contributing

Contributions are welcome. See `meta/CONTRIBUTING.md` for guidelines.

Distributed under the **MIT License**. See `LICENSE` for more information.

<div align="center">

---

*SpindleX Project © 2026*

</div>
