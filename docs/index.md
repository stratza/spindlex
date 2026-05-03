# SpindleX

Welcome to SpindleX's documentation! SpindleX is a modern, high-performance SSHv2 and SFTP client/server library.

[![PR Gate](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/ci-pr.yml?branch=main&style=flat-square&label=PR%20Gate)](https://github.com/stratza/spindlex/actions/workflows/ci-pr.yml)
[![Compatibility](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/ci-matrix.yml?branch=main&style=flat-square&label=Compatibility)](https://github.com/stratza/spindlex/actions/workflows/ci-matrix.yml)
[![Security](https://img.shields.io/github/actions/workflow/status/stratza/spindlex/security.yml?branch=main&style=flat-square&label=Security)](https://github.com/stratza/spindlex/actions/workflows/security.yml)
[![Coverage](https://img.shields.io/codecov/c/github/stratza/spindlex?style=flat-square)](https://codecov.io/gh/stratza/spindlex)
[![PyPI Version](https://img.shields.io/pypi/v/spindlex?style=flat-square)](https://pypi.org/project/spindlex/)
[![Python Support](https://img.shields.io/pypi/pyversions/spindlex?style=flat-square)](https://pypi.org/project/spindlex/)
[![License](https://img.shields.io/pypi/l/spindlex?style=flat-square)](https://github.com/stratza/spindlex/blob/main/LICENSE)

## Features

*   **:zap: High Performance**: Optimized protocol implementation with internal read buffering.
*   **:shield: Modern Security**: Supports Ed25519, ECDSA, AES-256-CTR, and other modern algorithms.
*   **:package: Lean Design**: Minimal dependencies, leveraging the industry-standard `cryptography` library.
*   **:link: Full SSH & SFTP**: Both client and server implementations for SSHv2 and SFTP.
*   **:cyclone: Native Async**: First-class support for `asyncio` with `AsyncSSHClient` and `AsyncSFTPClient`.
*   **:test_tube: Well Tested**: Robust test suite with focus on protocol correctness and reliability.
*   **:label: Fully Typed**: Complete type hints for a better developer experience.
*   **:sparkles: Unified API**: Consistent synchronous and asynchronous client interfaces.

## Quick Start

Install SpindleX:

```bash
pip install spindlex
```

### Basic SSH Client

=== "Sync"

    ```python
    from spindlex import SSHClient

    # Default policy is RejectPolicy — load ~/.ssh/known_hosts first.
    with SSHClient() as client:
        client.get_host_keys().load()
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
*   [**Cookbook**](cookbook/index.md) - Real-world recipes for common tasks.
*   [**API Reference**](api_reference/index.md) - Detailed technical documentation.
*   [**Performance**](performance.md) - Benchmarks and optimization tips.
*   [**Security**](security.md) - Our security model and best practices.
