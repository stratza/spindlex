# SpindleX

Welcome to SpindleX's documentation! SpindleX is a modern, high-performance, pure-Python SSHv2 and SFTP client/server library.

[![CI Status](https://img.shields.io/github/actions/workflow/status/daveops-world/spindlex/ci.yml?branch=main&style=flat-square)](https://gitlab.com/daveops.world/development/python/spindle/-/pipelines)
[![Coverage](https://img.shields.io/codecov/c/github/daveops-world/spindlex?style=flat-square)](https://codecov.io/gh/daveops-world/spindlex)
[![PyPI Version](https://img.shields.io/pypi/v/spindlex?style=flat-square)](https://pypi.org/project/spindlex/)
[![Python Support](https://img.shields.io/pypi/pyversions/spindlex?style=flat-square)](https://pypi.org/project/spindlex/)
[![License](https://img.shields.io/pypi/l/spindlex?style=flat-square)](https://github.com/daveops-world/spindlex/blob/main/LICENSE)

## Features

*   **:zap: High Performance**: Optimized with Adaptive Buffering and TCP Fast-Path for minimal latency.
*   **:shield: Modern Security**: Supports Ed25519, ECDSA, ChaCha20-Poly1305, and other modern algorithms.
*   **:package: Pure Python**: Zero-dependency core (except `cryptography`) - no GCC or system headers required.
*   **:link: Full SSH & SFTP**: Both client and server implementations for SSHv2 and SFTP.
*   **:asyncio: Native Async**: First-class support for `asyncio` with `AsyncSSHClient` and `AsyncSFTPClient`.
*   **:test_tube: Well Tested**: Extensive test suite with >95% code coverage.
*   **:type: Fully Typed**: Complete type hints for a better developer experience.

## Quick Start

Install SpindleX:

```bash
pip install spindlex
```

### Basic SSH Client

=== "Sync"

    ```python
    from spindlex import SSHClient
    from spindlex.hostkeys.policy import AutoAddPolicy

    with SSHClient() as client:
        client.set_missing_host_key_policy(AutoAddPolicy())
        client.connect('example.com', username='user', password='password')

        stdin, stdout, stderr = client.exec_command('ls -la')
        print(stdout.read().decode())
    ```

=== "Async"

    ```python
    import asyncio
    from spindlex import AsyncSSHClient

    async def run():
        async with AsyncSSHClient() as client:
            await client.connect('example.com', username='user')
            stdin, stdout, stderr = await client.exec_command('ls -la')
            print(await stdout.read())

    asyncio.run(run())
```

## Navigation

*   [**Quick Start**](quickstart.md) - Get up and running in minutes.
*   [**User Guide**](user_guide/index.md) - Deep dive into SpindleX features.
*   [**Migration Guide**](migration/paramiko.md) - Switching from Paramiko? Start here.
*   [**Cookbook**](cookbook/index.md) - Real-world recipes for common tasks.
*   [**API Reference**](api_reference/index.md) - Detailed technical documentation.
*   [**Performance**](performance.md) - Benchmarks and optimization tips.
*   [**Security**](security.md) - Our security model and best practices.
