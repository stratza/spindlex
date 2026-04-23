"""
Cross-library SSH/SFTP benchmark: spindlex vs paramiko vs asyncssh.

Loads connection details from .env (SSH_HOST, SSH_PORT, SSH_USER,
SSH_PASSWORD) and runs five workloads against the same target,
reporting median / mean / stddev for each library/workload pair.

Workloads:
  1. handshake        — full connect + auth + close cycle
  2. exec-small       — exec_command("echo hello") on a warm connection
  3. exec-large       — ~1 MiB stdout (base64 of /dev/zero)
  4. sftp-upload      — write a 1 MiB temp file to the server
  5. sftp-download    — read a 1 MiB temp file back
  6. parallel-connect — 10 concurrent handshakes

Methodology: 1 warm-up iteration (discarded) + N timed iterations
per workload (default 5). Times are wall-clock, monotonic clock.
"""

from __future__ import annotations

import asyncio
import os
import statistics
import sys
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterable

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import asyncssh  # noqa: E402
import paramiko  # noqa: E402

import spindlex  # noqa: E402
from spindlex import AsyncSSHClient, SSHClient  # noqa: E402
from spindlex.hostkeys.policy import AutoAddPolicy  # noqa: E402

ITERATIONS = 5
WARMUP = 1
PARALLEL_N = 10
PAYLOAD_SIZE = 1024 * 1024  # 1 MiB
SFTP_CHUNK = 16 * 1024  # Reduced from 32KB to avoid exceeding server packet limits


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    env_path = REPO_ROOT / ".env"
    if env_path.exists():
        for raw in env_path.read_text().splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            env[k.strip()] = v.strip().strip('"').strip("'")
    return {
        "host": env.get("SSH_HOST", os.environ.get("SSH_HOST", "")),
        "port": int(env.get("SSH_PORT", os.environ.get("SSH_PORT", "22"))),
        "user": env.get("SSH_USER", os.environ.get("SSH_USER", "")),
        "password": env.get("SSH_PASSWORD", os.environ.get("SSH_PASSWORD", "")),
    }


@contextmanager
def timed() -> Iterable[Callable[[], float]]:
    start = time.perf_counter()
    finished: dict[str, float] = {}

    def get() -> float:
        return finished.get("d", time.perf_counter() - start)

    try:
        yield get
    finally:
        finished["d"] = time.perf_counter() - start


def stats(samples: list[float]) -> dict[str, float]:
    if not samples:
        return {"median": float("nan"), "mean": float("nan"), "stdev": float("nan")}
    return {
        "median": statistics.median(samples),
        "mean": statistics.fmean(samples),
        "stdev": statistics.pstdev(samples) if len(samples) > 1 else 0.0,
    }


def safe(label: str, sampler: Callable[[], list[float]]) -> dict[str, Any]:
    """Run `sampler()` and return its stats; on exception, return an error entry.

    Keeps one library's failure from aborting the whole benchmark.
    """
    try:
        return stats(sampler())
    except BaseException as e:  # noqa: BLE001 — keep going past KeyboardInterrupt subclasses too
        if isinstance(e, KeyboardInterrupt):
            raise
        tb = traceback.format_exception_only(type(e), e)[-1].strip()
        return {"error": tb, "label": label}


# ---------- spindlex (sync) ----------

def spindlex_handshake(cfg: dict[str, Any]) -> None:
    c = SSHClient()
    c.set_missing_host_key_policy(AutoAddPolicy())
    c.connect(
        hostname=cfg["host"], port=cfg["port"],
        username=cfg["user"], password=cfg["password"],
    )
    c.close()


def spindlex_exec(client: SSHClient, cmd: str) -> bytes:
    _, stdout, _ = client.exec_command(cmd)
    return stdout.read()


def spindlex_open(cfg: dict[str, Any]) -> SSHClient:
    c = SSHClient()
    c.set_missing_host_key_policy(AutoAddPolicy())
    c.connect(
        hostname=cfg["host"], port=cfg["port"],
        username=cfg["user"], password=cfg["password"],
    )
    return c


# ---------- paramiko ----------

def paramiko_handshake(cfg: dict[str, Any]) -> None:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        hostname=cfg["host"], port=cfg["port"],
        username=cfg["user"], password=cfg["password"],
        allow_agent=False, look_for_keys=False,
    )
    c.close()


def paramiko_exec(client: paramiko.SSHClient, cmd: str) -> bytes:
    _, stdout, _ = client.exec_command(cmd)
    return stdout.read()


def paramiko_open(cfg: dict[str, Any]) -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        hostname=cfg["host"], port=cfg["port"],
        username=cfg["user"], password=cfg["password"],
        allow_agent=False, look_for_keys=False,
    )
    return c


# ---------- asyncssh ----------

async def asyncssh_handshake(cfg: dict[str, Any]) -> None:
    async with asyncssh.connect(
        host=cfg["host"], port=cfg["port"],
        username=cfg["user"], password=cfg["password"],
        known_hosts=None,
    ):
        pass


async def asyncssh_exec(conn: asyncssh.SSHClientConnection, cmd: str) -> bytes:
    res = await conn.run(cmd, check=False)
    out = res.stdout
    return out.encode() if isinstance(out, str) else out or b""


async def asyncssh_open(cfg: dict[str, Any]) -> asyncssh.SSHClientConnection:
    return await asyncssh.connect(
        host=cfg["host"], port=cfg["port"],
        username=cfg["user"], password=cfg["password"],
        known_hosts=None,
    )


# ---------- spindlex (async) ----------

async def spindlex_async_handshake(cfg: dict[str, Any]) -> None:
    async with AsyncSSHClient() as c:
        c.set_missing_host_key_policy(AutoAddPolicy())
        await c.connect(
            hostname=cfg["host"], port=cfg["port"],
            username=cfg["user"], password=cfg["password"],
        )


async def spindlex_async_open(cfg: dict[str, Any]) -> AsyncSSHClient:
    c = AsyncSSHClient()
    c.set_missing_host_key_policy(AutoAddPolicy())
    await c.connect(
        hostname=cfg["host"], port=cfg["port"],
        username=cfg["user"], password=cfg["password"],
    )
    return c


async def spindlex_async_exec(client: AsyncSSHClient, cmd: str) -> bytes:
    _, stdout, _ = await client.exec_command(cmd)
    return await stdout.read()


# ---------- benchmark drivers ----------

def time_sync(fn: Callable[[], None], iters: int) -> list[float]:
    samples: list[float] = []
    for _ in range(WARMUP):
        try:
            fn()
        except Exception:
            pass
    for _ in range(iters):
        with timed() as t:
            fn()
        samples.append(t())
    return samples


def time_async(coro_factory: Callable[[], Any], iters: int) -> list[float]:
    async def runner() -> list[float]:
        samples: list[float] = []
        for _ in range(WARMUP):
            try:
                await coro_factory()
            except Exception:
                pass
        for _ in range(iters):
            with timed() as t:
                await coro_factory()
            samples.append(t())
        return samples
    return asyncio.run(runner())


def bench_handshake(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        "spindlex (sync)": safe("spindlex (sync)", lambda: time_sync(lambda: spindlex_handshake(cfg), ITERATIONS)),
        "paramiko": safe("paramiko", lambda: time_sync(lambda: paramiko_handshake(cfg), ITERATIONS)),
        "asyncssh": safe("asyncssh", lambda: time_async(lambda: asyncssh_handshake(cfg), ITERATIONS)),
        "spindlex (async)": safe("spindlex (async)", lambda: time_async(lambda: spindlex_async_handshake(cfg), ITERATIONS)),
    }


def bench_exec_on_warm(cfg: dict[str, Any], cmd: str) -> dict[str, dict[str, Any]]:
    """Open one connection per library, time exec_command on the warm conn."""
    out: dict[str, dict[str, Any]] = {}

    def _spx_sync() -> list[float]:
        c = spindlex_open(cfg)
        try:
            return time_sync(lambda: spindlex_exec(c, cmd), ITERATIONS)
        finally:
            c.close()
    out["spindlex (sync)"] = safe("spindlex (sync)", _spx_sync)

    def _pmk() -> list[float]:
        p = paramiko_open(cfg)
        try:
            return time_sync(lambda: paramiko_exec(p, cmd), ITERATIONS)
        finally:
            p.close()
    out["paramiko"] = safe("paramiko", _pmk)

    async def _asyncssh() -> list[float]:
        conn = await asyncssh_open(cfg)
        try:
            samples: list[float] = []
            for _ in range(WARMUP):
                await asyncssh_exec(conn, cmd)
            for _ in range(ITERATIONS):
                with timed() as t:
                    await asyncssh_exec(conn, cmd)
                samples.append(t())
            return samples
        finally:
            conn.close()
            await conn.wait_closed()
    out["asyncssh"] = safe("asyncssh", lambda: asyncio.run(_asyncssh()))

    async def _spx_async() -> list[float]:
        conn = await spindlex_async_open(cfg)
        try:
            samples: list[float] = []
            for _ in range(WARMUP):
                await spindlex_async_exec(conn, cmd)
            for _ in range(ITERATIONS):
                with timed() as t:
                    await spindlex_async_exec(conn, cmd)
                samples.append(t())
            return samples
        finally:
            await conn.close()
    out["spindlex (async)"] = safe("spindlex (async)", lambda: asyncio.run(_spx_async()))

    return out


def bench_sftp_upload(cfg: dict[str, Any], payload: bytes, remote_path: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}

    # spindlex — needs explicit chunking; the protocol layer rejects strings
    # larger than the SFTP write limit, unlike paramiko/asyncssh which chunk.
    def _spx() -> list[float]:
        c = spindlex_open(cfg)
        try:
            sftp = c.open_sftp()
            try:
                def _do() -> None:
                    with sftp.open(remote_path, "wb") as fh:
                        for off in range(0, len(payload), SFTP_CHUNK):
                            fh.write(payload[off:off + SFTP_CHUNK])
                return time_sync(_do, ITERATIONS)
            finally:
                sftp.close()
        finally:
            c.close()
    out["spindlex (sync)"] = safe("spindlex (sync)", _spx)

    def _pmk() -> list[float]:
        p = paramiko_open(cfg)
        try:
            sftp_p = p.open_sftp()
            try:
                def _do_p() -> None:
                    with sftp_p.open(remote_path, "wb") as fh:
                        fh.write(payload)
                return time_sync(_do_p, ITERATIONS)
            finally:
                sftp_p.close()
        finally:
            p.close()
    out["paramiko"] = safe("paramiko", _pmk)

    async def _asyncssh() -> list[float]:
        conn = await asyncssh_open(cfg)
        try:
            sftp_a = await conn.start_sftp_client()
            try:
                samples: list[float] = []
                async def _wr() -> None:
                    async with sftp_a.open(remote_path, "wb") as fh:
                        await fh.write(payload)
                for _ in range(WARMUP):
                    await _wr()
                for _ in range(ITERATIONS):
                    with timed() as t:
                        await _wr()
                    samples.append(t())
                return samples
            finally:
                sftp_a.exit()
        finally:
            conn.close()
            await conn.wait_closed()
    out["asyncssh"] = safe("asyncssh", lambda: asyncio.run(_asyncssh()))

    return out


def bench_sftp_download(cfg: dict[str, Any], remote_path: str) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}

    def _spx() -> list[float]:
        c = spindlex_open(cfg)
        try:
            sftp = c.open_sftp()
            try:
                def _do() -> None:
                    with sftp.open(remote_path, "rb") as fh:
                        fh.read()
                return time_sync(_do, ITERATIONS)
            finally:
                sftp.close()
        finally:
            c.close()
    out["spindlex (sync)"] = safe("spindlex (sync)", _spx)

    def _pmk() -> list[float]:
        p = paramiko_open(cfg)
        try:
            sftp_p = p.open_sftp()
            try:
                def _do_p() -> None:
                    with sftp_p.open(remote_path, "rb") as fh:
                        fh.read()
                return time_sync(_do_p, ITERATIONS)
            finally:
                sftp_p.close()
        finally:
            p.close()
    out["paramiko"] = safe("paramiko", _pmk)

    async def _asyncssh() -> list[float]:
        conn = await asyncssh_open(cfg)
        try:
            sftp_a = await conn.start_sftp_client()
            try:
                samples: list[float] = []
                async def _rd() -> None:
                    async with sftp_a.open(remote_path, "rb") as fh:
                        await fh.read()
                for _ in range(WARMUP):
                    await _rd()
                for _ in range(ITERATIONS):
                    with timed() as t:
                        await _rd()
                    samples.append(t())
                return samples
            finally:
                sftp_a.exit()
        finally:
            conn.close()
            await conn.wait_closed()
    out["asyncssh"] = safe("asyncssh", lambda: asyncio.run(_asyncssh()))

    return out


def bench_parallel_connect(cfg: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}

    def _spx() -> None:
        with ThreadPoolExecutor(max_workers=PARALLEL_N) as ex:
            list(ex.map(lambda _: spindlex_handshake(cfg), range(PARALLEL_N)))
    out["spindlex (sync)"] = safe("spindlex (sync)", lambda: time_sync(_spx, ITERATIONS))

    def _pmk() -> None:
        with ThreadPoolExecutor(max_workers=PARALLEL_N) as ex:
            list(ex.map(lambda _: paramiko_handshake(cfg), range(PARALLEL_N)))
    out["paramiko"] = safe("paramiko", lambda: time_sync(_pmk, ITERATIONS))

    async def _asyncssh() -> None:
        await asyncio.gather(*(asyncssh_handshake(cfg) for _ in range(PARALLEL_N)))
    out["asyncssh"] = safe("asyncssh", lambda: time_async(lambda: _asyncssh(), ITERATIONS))

    async def _spx_async() -> None:
        await asyncio.gather(*(spindlex_async_handshake(cfg) for _ in range(PARALLEL_N)))
    out["spindlex (async)"] = safe("spindlex (async)", lambda: time_async(lambda: _spx_async(), ITERATIONS))

    return out


def print_table(title: str, results: dict[str, dict[str, Any]], unit: str = "ms") -> None:
    print(f"\n=== {title} ===")
    ok = {k: v for k, v in results.items() if "error" not in v}
    failed = {k: v for k, v in results.items() if "error" in v}

    rows = sorted(ok.items(), key=lambda kv: kv[1]["median"])
    fastest = rows[0][1]["median"] if rows else 0
    print(f"  {'Library':<22} {'median':>10} {'mean':>10} {'stdev':>10}   relative")
    for lib, s in rows:
        rel = s["median"] / fastest if fastest else float("inf")
        print(
            f"  {lib:<22} "
            f"{s['median']*1000:>8.2f} {unit} "
            f"{s['mean']*1000:>8.2f} {unit} "
            f"{s['stdev']*1000:>8.2f} {unit}   "
            f"{rel:>5.2f}x"
        )
    for lib, s in failed.items():
        print(f"  {lib:<22} FAILED -- {s['error']}")


def main() -> None:
    cfg = load_env()
    if not cfg["host"] or not cfg["user"] or not cfg["password"]:
        print("ERROR: SSH_HOST / SSH_USER / SSH_PASSWORD not set in .env")
        sys.exit(1)

    print(f"Target: {cfg['user']}@{cfg['host']}:{cfg['port']}")
    print(f"spindlex={spindlex.__version__}  paramiko={paramiko.__version__}  asyncssh={asyncssh.__version__}")
    print(f"Iterations per measurement: {ITERATIONS} (after {WARMUP} warmup)")

    def stage(label: str, title: str, fn: Callable[[], dict[str, dict[str, Any]]]) -> None:
        print(f"\n{label}")
        try:
            print_table(title, fn())
        except Exception as e:
            print(f"  STAGE FAILED --{type(e).__name__}: {e}")

    stage("[1/6] handshake (connect+auth+close)", "Handshake",
          lambda: bench_handshake(cfg))

    stage("[2/6] exec_command('echo hello') on warm connection", "Small exec",
          lambda: bench_exec_on_warm(cfg, "echo hello"))

    LARGE_CMD = "dd if=/dev/zero bs=1024 count=1024 2>/dev/null | base64"
    stage(f"[3/6] exec_command large output (~1.4 MB): {LARGE_CMD}", "Large exec",
          lambda: bench_exec_on_warm(cfg, LARGE_CMD))

    payload = os.urandom(PAYLOAD_SIZE)
    remote_path = f"/tmp/spindlex_bench_{os.getpid()}.bin"
    stage(f"[4/6] SFTP upload {PAYLOAD_SIZE} bytes -> {remote_path}", "SFTP upload",
          lambda: bench_sftp_upload(cfg, payload, remote_path))

    stage(f"[5/6] SFTP download {PAYLOAD_SIZE} bytes <- {remote_path}", "SFTP download",
          lambda: bench_sftp_download(cfg, remote_path))

    try:
        c = spindlex_open(cfg)
        sftp = c.open_sftp()
        try:
            sftp.remove(remote_path)
        finally:
            sftp.close()
            c.close()
    except Exception as e:
        print(f"  (cleanup failed: {e})")

    stage(f"[6/6] {PARALLEL_N} parallel handshakes", f"{PARALLEL_N} parallel handshakes",
          lambda: bench_parallel_connect(cfg))


if __name__ == "__main__":
    main()
