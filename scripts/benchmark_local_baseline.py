#!/usr/bin/env python3
"""Run a repeatable local SSH/SFTP benchmark baseline and write JSON results."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import platform
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

import spindlex  # noqa: E402
from spindlex import AsyncSSHClient, SSHClient  # noqa: E402
from spindlex.hostkeys.policy import AutoAddPolicy  # noqa: E402


@dataclass(frozen=True)
class Target:
    name: str
    host: str
    port: int
    username: str = "testuser"
    password: str = "password123"  # noqa: S105 - Docker test fixture password.


def run(command: list[str], *, cwd: Path = REPO_ROOT) -> str:
    completed = subprocess.run(  # noqa: S603 - command list is fixed by callers.
        command,
        cwd=cwd,
        text=True,
        capture_output=True,
    )
    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(f"Command failed ({' '.join(command)}): {detail}")
    return completed.stdout.strip()


def docker_compose_command() -> list[str]:
    try:
        run(["docker", "compose", "version"])
        return ["docker", "compose"]
    except Exception:
        run(["docker-compose", "--version"])
        return ["docker-compose"]


def wait_for_port(host: str, port: int, timeout: float = 120.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2.0):
                return
        except OSError:
            time.sleep(2.0)
    raise TimeoutError(f"Timed out waiting for {host}:{port}")


def compose_port(compose: list[str], service: str, internal_port: int) -> int:
    output = run(
        compose
        + [
            "-f",
            "tests/integration/docker-compose.yml",
            "port",
            service,
            str(internal_port),
        ]
    )
    return int(output.rsplit(":", 1)[1])


def start_targets(skip_docker: bool) -> list[Target]:
    if skip_docker:
        return [
            Target(
                name="external",
                host=os.environ.get("SSH_HOST", "127.0.0.1"),
                port=int(os.environ.get("SSH_PORT", "22")),
                username=os.environ.get("SSH_USER", "testuser"),
                password=os.environ.get("SSH_PASSWORD", "password123"),
            )
        ]

    compose = docker_compose_command()
    run(compose + ["-f", "tests/integration/docker-compose.yml", "up", "-d"])
    openssh_port = compose_port(compose, "openssh-server", 2222)
    dropbear_port = compose_port(compose, "dropbear-server", 22)
    targets = [
        Target("openssh", "127.0.0.1", openssh_port),
        Target("dropbear", "127.0.0.1", dropbear_port),
    ]
    for target in targets:
        wait_for_port(target.host, target.port)
    time.sleep(10)
    return targets


def timed(label: str, iterations: int, operation: Callable[[], Any]) -> dict[str, Any]:
    times: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        operation()
        times.append(time.perf_counter() - start)
    return {
        "operation": label,
        "iterations": iterations,
        "times_seconds": times,
        "median_seconds": statistics.median(times),
        "mean_seconds": statistics.mean(times),
        "min_seconds": min(times),
        "max_seconds": max(times),
        "stdev_seconds": statistics.stdev(times) if len(times) > 1 else 0.0,
    }


def connect(target: Target) -> SSHClient:
    client = SSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    client.connect(
        target.host,
        port=target.port,
        username=target.username,
        password=target.password,
        timeout=30,
    )
    return client


async def async_connect_exec(target: Target) -> None:
    client = AsyncSSHClient()
    client.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    try:
        await client.connect(
            target.host,
            port=target.port,
            username=target.username,
            password=target.password,
            timeout=30,
        )
        _stdin, stdout, stderr = await client.exec_command("printf async-ok")
        await stdout.read()
        await stderr.read()
    finally:
        await client.close()


def benchmark_target(target: Target, iterations: int, file_size: int) -> dict[str, Any]:
    payload = b"x" * file_size
    results: list[dict[str, Any]] = []

    def handshake() -> None:
        client = connect(target)
        client.close()

    results.append(timed("sync_handshake", iterations, handshake))

    client = connect(target)
    try:
        results.append(
            timed(
                "sync_exec",
                iterations,
                lambda: client.exec_command("printf spindlex-baseline")[1].read(),
            )
        )

        with tempfile.TemporaryDirectory() as tmp:
            local_upload = Path(tmp) / "upload.bin"
            local_download = Path(tmp) / "download.bin"
            local_upload.write_bytes(payload)
            remote_path = f"/tmp/spindlex-baseline-{int(time.time())}.bin"
            sftp = client.open_sftp()
            try:
                results.append(
                    timed(
                        "sync_sftp_upload",
                        iterations,
                        lambda: sftp.put(str(local_upload), remote_path),
                    )
                )
                results.append(
                    timed(
                        "sync_sftp_download",
                        iterations,
                        lambda: sftp.get(remote_path, str(local_download)),
                    )
                )
            finally:
                try:
                    sftp.remove(remote_path)
                except Exception:
                    pass
                sftp.close()
    finally:
        client.close()

    results.append(
        timed(
            "async_connect_exec",
            iterations,
            lambda: asyncio.run(async_connect_exec(target)),
        )
    )

    return {
        "target": target.name,
        "host": target.host,
        "port": target.port,
        "file_size_bytes": file_size,
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--iterations", type=int, default=3)
    parser.add_argument("--file-size", type=int, default=1024 * 1024)
    parser.add_argument("--skip-docker", action="store_true")
    args = parser.parse_args(argv)

    targets = start_targets(args.skip_docker)
    report = {
        "schema_version": 1,
        "generated_at_unix": int(time.time()),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "spindlex": spindlex.__version__,
        },
        "iterations": args.iterations,
        "targets": [
            benchmark_target(target, args.iterations, args.file_size)
            for target in targets
        ],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
    )
    print(f"Wrote benchmark baseline to {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
