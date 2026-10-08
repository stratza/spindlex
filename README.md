<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=18,18,18,48,25,52,18,18,18&height=200&section=header&text=SpindleX&fontSize=80&fontColor=bb86fc&fontAlignY=45&desc=High-Performance%20SSH%20and%20SFTP%20for%20Python&descSize=22&descColor=b39ddb&descAlignY=70&animation=fadeIn" width="100%" />

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&size=24&duration=3000&pause=1000&color=bb86fc&center=true&vCenter=true&width=600&lines=High-Performance+SSHv2+%E2%9A%A1;Native+AsyncIO+Support+%F0%9F%8C%91;Recursive+SFTP+Automation+%F0%9F%94%84;Secure+by+Default+%E2%9A%99%EF%B8%8F" alt="Typing SVG" />

<br/>

[![PR Gate](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/ci-pr.yml?branch=main&style=for-the-badge&logo=github&label=PR%20Gate&labelColor=1a1a1a)](https://github.com/stratza/spindlex/actions/workflows/ci-pr.yml)
[![Compatibility](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/ci-matrix.yml?branch=main&style=for-the-badge&logo=github&label=Compatibility&labelColor=1a1a1a)](https://github.com/stratza/spindlex/actions/workflows/ci-matrix.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/security.yml?branch=main&style=for-the-badge&logo=github&label=Security&labelColor=1a1a1a)](https://github.com/stratza/spindlex/actions/workflows/security.yml)
[![Coverage](https://img.shields.io/codecov/c/github/stratza/spindlex?style=for-the-badge&logo=codecov&labelColor=1a1a1a)](https://codecov.io/gh/stratza/spindlex)
[![PyPI Version](https://img.shields.io/pypi/v/spindlex?style=for-the-badge&logo=pypi&logoColor=white&labelColor=1a1a1a)](https://pypi.org/project/spindlex/)
[![Python Versions](https://img.shields.io/pypi/pyversions/spindlex?style=for-the-badge&logo=python&logoColor=white&labelColor=1a1a1a)](https://pypi.org/project/spindlex/)
[![License](https://img.shields.io/pypi/l/spindlex?style=for-the-badge&color=bb86fc&labelColor=1a1a1a)](https://github.com/stratza/spindlex/blob/main/LICENSE)

<br />

<a href="#-quick-start"><b><font color="#bb86fc">Quick Start</font></b></a> • <a href="https://spindlex.readthedocs.io/"><b><font color="#bb86fc">Documentation</font></b></a> • <a href="SECURITY.md"><b><font color="#bb86fc">Security</font></b></a> • <a href="CONTRIBUTING.md"><b><font color="#bb86fc">Contributing</font></b></a>

</div>

---

## ⚡ Overview

**SpindleX** is a modern SSH and SFTP implementation for Python 3.9 - 3.14 - client *and* server, sync *and* async. It is designed for high-performance automation and secure file transfers, providing a clean alternative to legacy SSH libraries.

> [!NOTE]
> **Stable 1.x.** The public API is frozen under semantic versioning since 1.0.0. The 1.0.x releases have hardened interoperability with OpenSSH and Dropbear, the SpindleX SSH and SFTP servers, and the sync and async transports - see the [changelog](docs/changelog.md). Upgrading from 0.x? Read the [migration guide](docs/migration/0.x-to-1.0.md). See also [SECURITY.md](SECURITY.md) and the [compatibility & API stability policy](docs/compatibility.md).

### 🔥 Key Features

- 🚀 **High Performance**: Pipelined SFTP transfers with read/write sizes negotiated via `limits@openssh.com` (up to 255 KB), and the fastest handshake and command execution in our [benchmarks](#-performance-benchmarks).
- 🔒 **Modern Cryptography**: ChaCha20-Poly1305 (preferred) and AES-CTR, Curve25519/ECDH/DH-group14 key exchange, Ed25519, ECDSA and RSA (SHA-2) keys, Terrapin-defense strict KEX.
- 🔄 **Native Async**: First-class `asyncio` support via `AsyncSSHClient` and `AsyncSFTPClient`.
- 🖥️ **SSH & SFTP Server**: Build servers with `SSHServer`, `SSHServerManager` and `SFTPServer` - they work with the OpenSSH `ssh` and `sftp` clients.
- 🔑 **Authentication**: Password, public key, keyboard-interactive, GSSAPI/Kerberos and multi-factor (partial success).
- 🔗 **Tunneling**: Local and remote port forwarding, and ProxyJump (bastion hosts) via `direct-tcpip` channels.
- 📂 **Recursive SFTP**: `get_recursive()` / `put_recursive()` for whole directory trees.
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
        client.get_host_keys().load()
        await client.connect('example.com', username='admin')
        stdin, stdout, stderr = await client.exec_command('df -h')
        print(await stdout.read())

asyncio.run(main())
```
</details>

<details>
<summary><b>SFTP Example</b></summary>

```python
from spindlex import SSHClient

with SSHClient() as client:
    client.get_host_keys().load()
    client.connect('example.com', username='admin')

    with client.open_sftp() as sftp:
        sftp.put('report.csv', '/srv/data/report.csv')
        sftp.get_recursive('/var/log/app', './app-logs')
        print(sftp.listdir('/srv/data'))
```
</details>

More examples - servers, port forwarding, ProxyJump, multi-factor login - are in the [documentation](https://spindlex.readthedocs.io/) and the [cookbook](docs/cookbook/index.md).

---

## 📊 Performance Benchmarks

Median of 5 runs against a live OpenSSH 9.2 server on a local network (SpindleX 1.0.4, AsyncSSH 2.24, Paramiko 5.0, Python 3.12). Lower is better.

| Operation | SpindleX | AsyncSSH | Paramiko |
|:---|:---:|:---:|:---:|
| **Handshake** (connect + auth + close) | **41 ms** | 50 ms | 84 ms |
| **Command** (`echo hello`, warm connection) | **5.5 ms** | 5.7 ms | 49 ms |
| **Command with 1.4 MB output** | **20 ms** | 21 ms | 67 ms |
| **SFTP upload** (1 MiB) | **14 ms** | 20 ms | 45 ms |
| **SFTP download** (1 MiB) | 16 ms | **14 ms** | 360 ms |

Network latency dominates in practice, so measure in your own environment. See the [comparison page](docs/comparison.md) for methodology and feature differences.

> [!TIP]
> Run the benchmark suite on your own hardware:
> ```bash
> python scripts/benchmark_compare.py     # SpindleX vs AsyncSSH vs Paramiko
> python scripts/benchmark_ciphers.py     # per cipher / key exchange / host key
> python scripts/benchmark_production.py  # protocol correctness + stability
> ```

---

## 🛡️ Security

- **Verification Enforced**: Host key verification is mandatory by default.
- **Log Sanitization**: Credentials and sensitive data are automatically filtered from logs.
- **AEAD Preferred**: `chacha20-poly1305@openssh.com` is the default cipher - authentication is integral, no separate MAC.
- **Terrapin Defense**: Strict-KEX (`kex-strict-c-v00@openssh.com`) enabled, sequence numbers reset after NEWKEYS.
- **Modern Defaults**: Ed25519, ECDSA, RSA with SHA-2 signatures, ChaCha20-Poly1305 and AES-CTR. CBC mode and SHA-1 (key exchange, MACs, `ssh-rsa` signatures) are off by default.
- **known_hosts Aware**: Hashed entries, non-standard ports and `@revoked` markers are honoured; private keys are written owner-only (`0600`).
- **Hardened Server**: Authentication only after key exchange, a login grace deadline, failed-attempt limits, and an SFTP server confined to its root.
- **Full Policy**: See [SECURITY.md](SECURITY.md) for vulnerability reporting and [Security Guide](docs/security.md) for operational security guidance.

---

## 🤝 Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for the GitHub entry point and [docs/contributing.md](docs/contributing.md) for the maintained guide.

Distributed under the **MIT License**. See `LICENSE` for more information.

<div align="center">

---

*SpindleX Project © 2026 Stratza Labs*

</div>
