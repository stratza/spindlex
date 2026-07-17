<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&amp;color=gradient&amp;customColorList=18,18,18,48,25,52,18,18,18&amp;height=200&amp;section=header&amp;text=SpindleX&amp;fontSize=80&amp;fontColor=bb86fc&amp;fontAlignY=45&amp;desc=High-Performance%20SSH%20and%20SFTP%20for%20Python&amp;descSize=22&amp;descColor=b39ddb&amp;descAlignY=70&amp;animation=fadeIn" width="100%" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=24&duration=3000&pause=1000&color=bb86fc&center=true&vCenter=true&width=600&lines=High-Performance+SSHv2+%E2%9A%A1;Native+AsyncIO+Support+%F0%9F%8C%91;Recursive+SFTP+Automation+%F0%9F%94%84;Secure+by+Default+%E2%9A%99%EF%B8%8F" alt="Typing SVG" />

<br/>

[![PR Gate](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/ci-pr.yml?branch=main&style=for-the-badge&logo=github&label=PR%20Gate&labelColor=1a1a1a)](https://github.com/stratza/spindlex/actions/workflows/ci-pr.yml)
[![Compatibility](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/ci-matrix.yml?branch=main&style=for-the-badge&logo=github&label=Compatibility&labelColor=1a1a1a)](https://github.com/stratza/spindlex/actions/workflows/ci-matrix.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/security.yml?branch=main&style=for-the-badge&logo=github&label=Security&labelColor=1a1a1a)](https://github.com/stratza/spindlex/actions/workflows/security.yml)
[![Coverage](https://img.shields.io/codecov/c/github/stratza/spindlex?style=for-the-badge&logo=codecov&labelColor=1a1a1a)](https://codecov.io/gh/stratza/spindlex)
[![PyPI Version](https://img.shields.io/pypi/v/spindlex?style=for-the-badge&logo=pypi&logoColor=white&labelColor=1a1a1a)](https://pypi.org/project/spindlex/)
[![License](https://img.shields.io/pypi/l/spindlex?style=for-the-badge&color=bb86fc&labelColor=1a1a1a)](https://github.com/stratza/spindlex/blob/main/LICENSE)

<br />

<a href="#-quick-start"><b><font color="#bb86fc">Quick Start</font></b></a> • <a href="https://spindlex.readthedocs.io/"><b><font color="#bb86fc">Documentation</font></b></a> • <a href="SECURITY.md"><b><font color="#bb86fc">Security</font></b></a> • <a href="CONTRIBUTING.md"><b><font color="#bb86fc">Contributing</font></b></a>

</div>

<!--
SpindleX is a typed Python SSHv2 and SFTP library for async automation, secure
file transfer, port forwarding, and controlled SSH/SFTP server workflows. It
targets Python 3.9+ and focuses on modern SSH algorithms, strict host key
verification, minimal runtime dependencies, first-class asyncio support, and a
clear public API. Use SpindleX when you need Python-native SSH/SFTP automation
with modern security defaults and production-facing documentation.
-->

---

## ⚡ Overview

**SpindleX** is a modern SSH protocol implementation for Python 3.9+. It is
designed for high-performance automation and secure file transfers, providing a
clean alternative to legacy SSH libraries.

> [!NOTE]
> **1.0.0 - First stable release.** SpindleX has graduated from beta: the public API surface is frozen under semantic versioning, with `chacha20-poly1305@openssh.com` as the preferred cipher, adaptive SFTP chunks via `limits@openssh.com`, and a hardened sync + async transport. Upgrading from 0.x? Read the [migration guide](docs/migration/0.x-to-1.0.md). See also [SECURITY.md](SECURITY.md), [production usage expectations](docs/production-usage.md), and the [compatibility policy](docs/compatibility.md).

### 🔥 Key Features

- 🚀 **High Performance**: Adaptive SFTP write chunks up to 255 KB via `limits@openssh.com` negotiation, pipelined transfers, and zero-copy internal buffering.
- 🔒 **ChaCha20-Poly1305**: Preferred AEAD cipher - no separate MAC pass, full Terrapin-defense strict-KEX, on par with leading SSH libraries.
- 🔄 **Native Async**: First-class `asyncio` support via `AsyncSSHClient` and `AsyncSFTPClient`.
- 🛡️ **Secure by Default**: Modern primitives only - Ed25519, ECDSA, ChaCha20-Poly1305, AES-CTR. Legacy/weak ciphers are not negotiated.
- 🔗 **Advanced Tunneling**: ProxyJump (bastion hosts) via `direct-tcpip` channels and TCP port forwarding.
- 📂 **Recursive SFTP**: Native support for recursive directory uploads and downloads.
- 🏷️ **Fully Typed**: Comprehensive type hints for IDE integration and static analysis.

---

## ✅ Use SpindleX When

- You need SSH command execution or SFTP automation from Python.
- You want both synchronous and `asyncio` client APIs in one package.
- You need strict host key verification and modern algorithms by default.
- You want a small dependency surface backed by the `cryptography` package.
- You need a library with public production, compatibility, security, and release policies.

## 🚫 Not the Right Fit When

- You need universal compatibility with legacy SSH servers or weak algorithms.
- You need production use of unknown-host auto-acceptance policies.
- You need every OpenSSH server feature or appliance-specific SSH behavior.
- You need SCP, SSH agent forwarding, X11 forwarding, or compression - these are deliberate scope exclusions (see the [comparison page](docs/comparison.md)).

## 💎 Why SpindleX?

- 💼 **Business Friendly**: MIT Licensed. Permissive use for commercial and proprietary projects.
- 📖 **Maintainable Code**: Modular architecture designed for clarity and easier security auditing.
- 🛠️ **Modern API**: Clean, intuitive interface with consistent error handling and minimal dependencies.
- 🧊 **Focused Scope**: No support for insecure legacy protocols, resulting in a leaner and more secure codebase.

---

## 🧭 Positioning

| Need | SpindleX fit |
|:---|:---|
| Async Python SSH/SFTP automation | First-class `AsyncSSHClient` and `AsyncSFTPClient` |
| Secure defaults | Unknown host keys rejected by default; weak legacy algorithms excluded |
| Typed library use | `py.typed` included for type-aware editors and static analysis |
| SFTP throughput | Pipelined transfers and OpenSSH `limits@openssh.com` negotiation |
| Production evaluation | Public security, compatibility, API stability, and release docs |

SpindleX is not a drop-in replacement for every SSH library. It deliberately
prioritizes modern algorithms, explicit trust, typed APIs, and maintainable
protocol behavior over broad legacy compatibility.

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
    # Default policy is RejectPolicy. Load ~/.ssh/known_hosts before connecting.
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
        # Default policy is RejectPolicy. Load ~/.ssh/known_hosts before connecting.
        client.get_host_keys().load()
        await client.connect('example.com', username='admin')
        stdin, stdout, stderr = await client.exec_command('df -h')
        print(await stdout.read())

asyncio.run(main())
```
</details>

---

## 📊 Performance Benchmarks

SpindleX is optimized for high-throughput environments, with SFTP upload throughput in line with leading SSH libraries and ChaCha20-Poly1305 as the preferred cipher. See the [comparison page](docs/comparison.md) for the full benchmark methodology.

| Operation | SpindleX | Other libs | Notes |
|:---|:---:|:---:|:---|
| **SFTP upload (1 MiB, chacha20)** | ~14 ms | ~14 ms | On par after limits negotiation |
| **SFTP upload (1 MiB, AES-CTR)** | ~14 ms | ~14 ms | Pipelined, 255 KB chunks |
| **Handshake** | ~320 ms | ~320 ms | Ed25519 + Curve25519 |

> [!TIP]
> Run the benchmark suite on your own hardware:
> ```bash
> python scripts/benchmark_ciphers.py
> python scripts/benchmark_production.py
> ```

---

## 🛡️ Security

- **Verification Enforced**: Host key verification is mandatory by default.
- **Log Sanitization**: Credentials and sensitive data are automatically filtered from logs.
- **AEAD Preferred**: `chacha20-poly1305@openssh.com` is the default cipher - authentication is integral, no separate MAC.
- **Terrapin Defense**: Strict-KEX (`kex-strict-c-v00@openssh.com`) enabled, sequence numbers reset after NEWKEYS.
- **Modern Defaults**: Ed25519, ECDSA, ChaCha20-Poly1305, and AES-CTR only. SHA-1 and CBC mode are excluded.
- **Full Policy**: See [SECURITY.md](SECURITY.md) for vulnerability reporting and [Security Guide](docs/security.md) for operational security guidance.

---

## 📚 Documentation

- [Quick Start](https://spindlex.readthedocs.io/en/latest/quickstart/)
- [User Guide](https://spindlex.readthedocs.io/en/latest/user_guide/)
- [Cookbook](https://spindlex.readthedocs.io/en/latest/cookbook/)
- [API Reference](https://spindlex.readthedocs.io/en/latest/api_reference/)
- [Production Usage](https://spindlex.readthedocs.io/en/latest/production-usage/)
- [Compatibility](https://spindlex.readthedocs.io/en/latest/compatibility/)
- [Security](https://spindlex.readthedocs.io/en/latest/security/)

## 🤝 Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the GitHub entry point and [docs/contributing.md](docs/contributing.md) for the maintained guide.

Distributed under the **MIT License**. See `LICENSE` for more information.

<div align="center">

---

*SpindleX Project © 2026 Stratza Labs*

</div>
