"""
SpindleX Production Readiness Benchmark.

Validates library-level correctness and stability — not raw performance.

Sections:
  1. SSH Protocol Correctness     — KEX, cipher, host-key algorithm coverage
                                    + silent-fallback detection
  2. Session Lifecycle            — sequential stability, async task leak check,
                                    reconnect consistency
  3. Exec Reliability             — small / medium / large output integrity,
                                    stdout/stderr separation, sync==async
  4. SFTP Integrity               — SHA-256 round-trip per chunk size,
                                    large-file stability, repeated-transfer consistency
  5. Concurrency Correctness      — per-session output identity (no cross-session
                                    data leakage), async and sync thread-pool
  6. Failure Classification       — deterministic typed exceptions per error class,
                                    sync/async exception-type consistency
  7. Negotiation Determinism      — same config → same outcome across N runs,
                                    no flapping
  8. Performance Stability        — jitter (p99/median), cumulative slowdown,
                                    error rate

Usage:
  python scripts/benchmark_production.py [--quick]
  Set SSH_HOST / SSH_PORT / SSH_USER / SSH_PASSWORD in .env or environment.

  --quick  Reduces iteration counts for fast feedback.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import os
import statistics
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import spindlex  # noqa: E402
from spindlex import AsyncSSHClient, SSHClient  # noqa: E402
from spindlex.crypto.ciphers import CipherSuite  # noqa: E402
from spindlex.exceptions import (  # noqa: E402
    AuthenticationException,
    SSHException,
)
from spindlex.hostkeys.policy import AutoAddPolicy  # noqa: E402

# ── Algorithm lists ────────────────────────────────────────────────────────────

KEX_ALGORITHMS = [
    "curve25519-sha256",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
]

HOST_KEY_ALGORITHMS = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-256",
    "rsa-sha2-512",
]

CIPHER_ALGORITHMS = [
    "aes256-ctr",
    "aes192-ctr",
    "aes128-ctr",
]

SFTP_CHUNK = 16 * 1024  # 16 KiB — stays under server packet limits


# ── Run config ─────────────────────────────────────────────────────────────────


@dataclass
class RunConfig:
    sequential_sessions: int = 50
    stability_runs: int = 100
    concurrent_levels: list[int] = field(default_factory=lambda: [10, 25, 50])
    negotiation_repeats: int = 5
    large_output_kb: int = 5120


def quick_config() -> RunConfig:
    return RunConfig(
        sequential_sessions=10,
        stability_runs=30,
        concurrent_levels=[10, 25],
        negotiation_repeats=3,
        large_output_kb=1024,
    )


# ── Result tracking ────────────────────────────────────────────────────────────


@dataclass
class Result:
    label: str
    status: str  # PASS | FAIL | SKIP | WARN
    detail: str = ""


_results: list[Result] = []


def _emit(label: str, status: str, detail: str = "") -> Result:
    r = Result(label, status, detail)
    _results.append(r)
    det = f"  ({detail})" if detail else ""
    print(f"  [{status:<4}]  {label:<58}{det}")
    return r


def passed(label: str, detail: str = "") -> Result:
    return _emit(label, "PASS", detail)


def failed(label: str, detail: str = "") -> Result:
    return _emit(label, "FAIL", detail)


def skipped(label: str, detail: str = "") -> Result:
    return _emit(label, "SKIP", detail)


def warned(label: str, detail: str = "") -> Result:
    return _emit(label, "WARN", detail)


# ── .env loader ────────────────────────────────────────────────────────────────


def load_env() -> dict[str, Any]:
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


# ── Connection helpers ─────────────────────────────────────────────────────────


def spx_open(cfg: dict[str, Any]) -> SSHClient:
    c = SSHClient()
    c.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    c.connect(
        hostname=cfg["host"],
        port=cfg["port"],
        username=cfg["user"],
        password=cfg["password"],
    )
    return c


async def spx_async_open(cfg: dict[str, Any]) -> AsyncSSHClient:
    c = AsyncSSHClient()
    c.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
    await c.connect(
        hostname=cfg["host"],
        port=cfg["port"],
        username=cfg["user"],
        password=cfg["password"],
    )
    return c


@contextmanager
def _force_algos(
    cipher: str | None = None,
    kex: str | None = None,
    hostkey: str | None = None,
) -> Iterator[None]:
    """Temporarily constrain CipherSuite to a single algorithm per category."""
    saved: dict[str, list[str]] = {}
    try:
        if cipher is not None:
            saved["ENCRYPTION_ALGORITHMS"] = CipherSuite.ENCRYPTION_ALGORITHMS[:]
            CipherSuite.ENCRYPTION_ALGORITHMS = [cipher]
        if kex is not None:
            saved["KEX_ALGORITHMS"] = CipherSuite.KEX_ALGORITHMS[:]
            CipherSuite.KEX_ALGORITHMS = [kex]
        if hostkey is not None:
            saved["HOST_KEY_ALGORITHMS"] = CipherSuite.HOST_KEY_ALGORITHMS[:]
            CipherSuite.HOST_KEY_ALGORITHMS = [hostkey]
        yield
    finally:
        for attr, val in saved.items():
            setattr(CipherSuite, attr, val)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def section(n: int, title: str) -> None:
    print(f"\n[{n}/8] {title}")
    print("  " + "-" * 72)


# ═══════════════════════════════════════════════════════════════════════════════
# 1. SSH Protocol Correctness
# ═══════════════════════════════════════════════════════════════════════════════


def check_protocol_correctness(cfg: dict[str, Any]) -> None:
    section(1, "SSH Protocol Correctness")

    print("  KEX algorithms:")
    for kex in KEX_ALGORITHMS:
        try:
            with _force_algos(kex=kex):
                spx_open(cfg).close()
            passed(f"    kex  {kex}")
        except SSHException as e:
            # Server may not advertise this KEX — mark SKIP, not FAIL
            skipped(f"    kex  {kex}", f"{type(e).__name__}: server may not offer this")
        except Exception as e:
            failed(f"    kex  {kex}", f"non-SSH exception: {type(e).__name__}: {e}")

    print("  Host-key types:")
    for hk in HOST_KEY_ALGORITHMS:
        try:
            with _force_algos(hostkey=hk):
                spx_open(cfg).close()
            passed(f"    hostkey  {hk}")
        except SSHException as e:
            skipped(
                f"    hostkey  {hk}",
                f"{type(e).__name__}: server may not have this key type",
            )
        except Exception as e:
            failed(f"    hostkey  {hk}", f"non-SSH exception: {type(e).__name__}: {e}")

    print("  Cipher algorithms:")
    for ciph in CIPHER_ALGORITHMS:
        try:
            with _force_algos(cipher=ciph):
                c = spx_open(cfg)
                _, stdout, _ = c.exec_command("echo cipher_ok")
                out = stdout.read().strip()
                c.close()
            if out == b"cipher_ok":
                passed(f"    cipher  {ciph}")
            else:
                failed(f"    cipher  {ciph}", f"unexpected output: {out!r}")
        except SSHException as e:
            failed(f"    cipher  {ciph}", type(e).__name__)
        except Exception as e:
            failed(f"    cipher  {ciph}", f"non-SSH exception: {type(e).__name__}: {e}")

    print("  Silent-fallback detection (fake algorithms must be rejected):")
    for kind, fake in [
        ("kex", "nonexistent-kex-00"),
        ("hostkey", "nonexistent-hk-00"),
        ("cipher", "nonexistent-ciph-00"),
    ]:
        kwargs: dict[str, str] = {kind: fake}
        try:
            with _force_algos(**kwargs):
                spx_open(cfg).close()
            failed(
                f"    no-fallback  {kind}",
                "connection succeeded — silent fallback occurred",
            )
        except SSHException:
            passed(f"    no-fallback  {kind}", "correctly rejected with SSHException")
        except Exception as e:
            warned(
                f"    no-fallback  {kind}",
                f"rejected but with non-SSH exception: {type(e).__name__}",
            )


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Session Lifecycle
# ═══════════════════════════════════════════════════════════════════════════════


def check_session_lifecycle(cfg: dict[str, Any], run_cfg: RunConfig) -> None:
    section(2, f"Session Lifecycle  ({run_cfg.sequential_sessions} sequential cycles)")

    # Sequential stability
    ok = 0
    first_fail: int | None = None
    for i in range(run_cfg.sequential_sessions):
        try:
            c = spx_open(cfg)
            _, stdout, _ = c.exec_command("echo ok")
            stdout.read()
            c.close()
            ok += 1
        except Exception:
            if first_fail is None:
                first_fail = i

    n = run_cfg.sequential_sessions
    if ok == n:
        passed("Sequential stability", f"{ok}/{n} sessions succeeded")
    else:
        failed(
            "Sequential stability",
            f"{ok}/{n} succeeded; first failure at iteration {first_fail}",
        )

    # Reconnect consistency: compare success rate in first half vs second half
    half = max(5, run_cfg.sequential_sessions // 2)
    counts = [0, 0]
    for batch in range(2):
        for _ in range(half):
            try:
                spx_open(cfg).close()
                counts[batch] += 1
            except Exception:
                pass
    rate0 = counts[0] / half
    rate1 = counts[1] / half
    drift = abs(rate1 - rate0)
    if drift < 0.05:
        passed(
            "Reconnect consistency (no drift)",
            f"batch1={rate0:.0%}  batch2={rate1:.0%}",
        )
    elif drift < 0.15:
        warned(
            "Reconnect consistency",
            f"rate drifted {drift:.0%}: batch1={rate0:.0%} batch2={rate1:.0%}",
        )
    else:
        failed(
            "Reconnect consistency",
            f"rate drifted {drift:.0%}: batch1={rate0:.0%} batch2={rate1:.0%}",
        )

    # Async task leak check
    async def _async_leak_check() -> int:
        baseline = len(asyncio.all_tasks())
        for _ in range(10):
            c = await spx_async_open(cfg)
            _, stdout, _ = await c.exec_command("echo ok")
            await stdout.read()
            await c.close()
        await asyncio.sleep(0.2)
        return max(0, len(asyncio.all_tasks()) - baseline)

    try:
        leaked = asyncio.run(_async_leak_check())
        if leaked == 0:
            passed("Async task leak (10 cycles)", "0 orphaned tasks")
        else:
            failed("Async task leak (10 cycles)", f"{leaked} orphaned tasks detected")
    except Exception as e:
        failed("Async task leak (10 cycles)", f"{type(e).__name__}: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Exec Reliability
# ═══════════════════════════════════════════════════════════════════════════════


def check_exec_reliability(cfg: dict[str, Any], run_cfg: RunConfig) -> None:
    section(3, "Exec Reliability")

    c = spx_open(cfg)
    try:
        # Small output
        _, stdout, _ = c.exec_command("echo hello")
        out = stdout.read().strip()
        if out == b"hello":
            passed("Small exec (echo hello) — output correctness")
        else:
            failed("Small exec (echo hello) — output correctness", f"got {out!r}")

        # Medium output (~100 KB)
        med_cmd = "dd if=/dev/zero bs=1024 count=100 2>/dev/null | base64"
        _, stdout, _ = c.exec_command(med_cmd)
        med_data = stdout.read()
        expected_min = 130_000  # base64 of 100 KiB ~= 136 KB
        if len(med_data) >= expected_min:
            passed(
                "Medium exec (~100 KB output) — no truncation",
                f"{len(med_data):,} bytes",
            )
        else:
            failed(
                "Medium exec (~100 KB output) — no truncation",
                f"only {len(med_data):,} bytes (expected >= {expected_min:,})",
            )

        # Large output
        large_cmd = f"dd if=/dev/zero bs=1024 count={run_cfg.large_output_kb} 2>/dev/null | base64"
        _, stdout, _ = c.exec_command(large_cmd)
        large_data = stdout.read()
        expected_large = int(run_cfg.large_output_kb * 1024 * 1.33)
        if len(large_data) >= expected_large:
            passed(
                f"Large exec (~{run_cfg.large_output_kb} KB output) — no truncation",
                f"{len(large_data):,} bytes",
            )
        else:
            failed(
                f"Large exec (~{run_cfg.large_output_kb} KB output) — no truncation",
                f"only {len(large_data):,} bytes (expected >= {expected_large:,})",
            )

        # Stdout/stderr separation — no deadlock
        _, stdout, stderr = c.exec_command(
            "sh -c 'printf stdout_ok; printf stderr_ok >&2'"
        )
        out_s = stdout.read()
        err_s = stderr.read()
        if b"stdout_ok" in out_s and b"stderr_ok" in err_s:
            passed("Stdout/stderr separation — no deadlock")
        elif b"stdout_ok" in out_s:
            warned("Stdout/stderr separation", "stderr empty or not captured")
        else:
            failed("Stdout/stderr separation", f"stdout={out_s!r} stderr={err_s!r}")
    finally:
        c.close()

    # Sync vs async output consistency
    consistency_cmd = "echo spindlex_consistency_token"
    c2 = spx_open(cfg)
    try:
        _, stdout, _ = c2.exec_command(consistency_cmd)
        sync_out = stdout.read().strip()
    finally:
        c2.close()

    async def _async_exec() -> bytes:
        ac = await spx_async_open(cfg)
        try:
            _, stdout, _ = await ac.exec_command(consistency_cmd)
            return (await stdout.read()).strip()
        finally:
            await ac.close()

    try:
        async_out = asyncio.run(_async_exec())
        if sync_out == async_out:
            passed("Sync vs async output consistency", repr(sync_out.decode()))
        else:
            failed(
                "Sync vs async output consistency",
                f"sync={sync_out!r} async={async_out!r}",
            )
    except Exception as e:
        failed("Sync vs async output consistency", f"{type(e).__name__}: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# 4. SFTP Integrity
# ═══════════════════════════════════════════════════════════════════════════════


def check_sftp_integrity(cfg: dict[str, Any]) -> None:
    section(4, "SFTP Integrity")

    remote_base = f"/tmp/spx_prod_{os.getpid()}"
    c = spx_open(cfg)
    sftp = c.open_sftp()
    cleanup: list[str] = []

    try:
        payload = os.urandom(512 * 1024)  # 512 KiB
        payload_hash = _sha256(payload)

        # SHA-256 round-trip across chunk sizes
        for chunk_kb in [4, 16, 64, 256]:
            chunk = chunk_kb * 1024
            remote = f"{remote_base}_c{chunk_kb}k.bin"
            cleanup.append(remote)
            try:
                with sftp.open(remote, "wb") as fh:
                    for off in range(0, len(payload), chunk):
                        fh.write(payload[off : off + chunk])
                with sftp.open(remote, "rb") as fh:
                    dl = fh.read()
                ok = _sha256(dl) == payload_hash and len(dl) == len(payload)
                if ok:
                    passed(f"SFTP chunk={chunk_kb}KB SHA-256 round-trip")
                else:
                    failed(
                        f"SFTP chunk={chunk_kb}KB SHA-256 round-trip",
                        f"size {len(dl)} vs {len(payload)}, hash_match={_sha256(dl) == payload_hash}",
                    )
            except Exception as e:
                failed(
                    f"SFTP chunk={chunk_kb}KB SHA-256 round-trip",
                    f"{type(e).__name__}: {e}",
                )

        # Large file (10 MB)
        large_payload = os.urandom(10 * 1024 * 1024)
        large_hash = _sha256(large_payload)
        large_remote = f"{remote_base}_10mb.bin"
        cleanup.append(large_remote)
        try:
            with sftp.open(large_remote, "wb") as fh:
                for off in range(0, len(large_payload), SFTP_CHUNK):
                    fh.write(large_payload[off : off + SFTP_CHUNK])
            with sftp.open(large_remote, "rb") as fh:
                dl = fh.read()
            if _sha256(dl) == large_hash:
                passed("SFTP large file (10 MB) — integrity")
            else:
                failed(
                    "SFTP large file (10 MB) — integrity",
                    "hash mismatch after download",
                )
        except Exception as e:
            failed("SFTP large file (10 MB) — integrity", f"{type(e).__name__}: {e}")

        # Repeated transfer consistency (5 rounds, same payload)
        rpt_payload = os.urandom(256 * 1024)
        rpt_hash = _sha256(rpt_payload)
        rpt_remote = f"{remote_base}_rpt.bin"
        cleanup.append(rpt_remote)
        rpt_ok = 0
        try:
            for _ in range(5):
                with sftp.open(rpt_remote, "wb") as fh:
                    for off in range(0, len(rpt_payload), SFTP_CHUNK):
                        fh.write(rpt_payload[off : off + SFTP_CHUNK])
                with sftp.open(rpt_remote, "rb") as fh:
                    dl = fh.read()
                if _sha256(dl) == rpt_hash:
                    rpt_ok += 1
            if rpt_ok == 5:
                passed("SFTP repeated transfer consistency (5x)", "5/5 hashes match")
            else:
                failed(
                    "SFTP repeated transfer consistency (5x)",
                    f"only {rpt_ok}/5 hashes matched",
                )
        except Exception as e:
            failed(
                "SFTP repeated transfer consistency (5x)", f"{type(e).__name__}: {e}"
            )

    finally:
        for path in cleanup:
            try:
                sftp.remove(path)
            except Exception:
                pass
        sftp.close()
        c.close()


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Concurrency Correctness
# ═══════════════════════════════════════════════════════════════════════════════


def check_concurrency_correctness(cfg: dict[str, Any], run_cfg: RunConfig) -> None:
    section(5, "Concurrency Correctness")

    # Async: each session echoes its own unique marker and verifies it
    for n in run_cfg.concurrent_levels:

        async def _run(n: int = n) -> tuple[int, list[str]]:
            errors: list[str] = []

            async def session(idx: int) -> bool:
                marker = f"spx_{idx:05d}"
                try:
                    ac = await spx_async_open(cfg)
                    _, stdout, _ = await ac.exec_command(f"echo {marker}")
                    out = (await stdout.read()).decode().strip()
                    await ac.close()
                    if out != marker:
                        errors.append(f"idx={idx} expected={marker!r} got={out!r}")
                        return False
                    return True
                except Exception as e:
                    errors.append(f"idx={idx} {type(e).__name__}: {e}")
                    return False

            results = await asyncio.gather(*[session(i) for i in range(n)])
            return sum(results), errors

        try:
            correct, errs = asyncio.run(_run())
            label = f"Async N={n} — per-session output identity"
            if correct == n:
                passed(label, f"{n}/{n} sessions correct")
            else:
                first_err = errs[0] if errs else "unknown"
                failed(label, f"{correct}/{n} correct — {first_err}")
        except Exception as e:
            failed(
                f"Async N={n} — per-session output identity",
                f"stage error: {type(e).__name__}: {e}",
            )

    # Sync thread-pool: same per-thread identity test
    n_threads = run_cfg.concurrent_levels[0]
    thread_errors: list[str] = []

    def _thread(idx: int) -> bool:
        marker = f"thr_{idx:05d}"
        try:
            c = spx_open(cfg)
            _, stdout, _ = c.exec_command(f"echo {marker}")
            out = stdout.read().decode().strip()
            c.close()
            return out == marker
        except Exception as e:
            thread_errors.append(f"idx={idx} {type(e).__name__}: {e}")
            return False

    with ThreadPoolExecutor(max_workers=n_threads) as pool:
        thread_results = list(pool.map(_thread, range(n_threads)))

    correct = sum(thread_results)
    label = f"Sync thread-pool N={n_threads} — per-thread output identity"
    if correct == n_threads:
        passed(label, f"{n_threads}/{n_threads} threads correct")
    else:
        first_err = thread_errors[0] if thread_errors else "wrong output"
        failed(label, f"{correct}/{n_threads} correct — {first_err}")

    # Mixed async workload: exec + sftp sessions concurrently
    remote_base = f"/tmp/spx_mixed_{os.getpid()}"
    mix_payload = os.urandom(64 * 1024)
    mix_hash = _sha256(mix_payload)
    n_each = 5

    async def _mixed() -> tuple[int, int]:
        exec_ok = 0
        sftp_ok = 0

        async def exec_task(idx: int) -> bool:
            marker = f"mx_{idx:04d}"
            ac = await spx_async_open(cfg)
            _, stdout, _ = await ac.exec_command(f"echo {marker}")
            out = (await stdout.read()).decode().strip()
            await ac.close()
            return out == marker

        async def sftp_task(idx: int) -> bool:
            remote = f"{remote_base}_{idx}.bin"
            ac = await spx_async_open(cfg)
            sftp = await ac.open_sftp()
            try:
                async with await sftp.open(remote, "wb") as fh:
                    await fh.write(mix_payload)
                async with await sftp.open(remote, "rb") as fh:
                    dl = await fh.read()
                await sftp.remove(remote)
                return _sha256(dl) == mix_hash
            finally:
                await sftp.close()
                await ac.close()

        tasks = [exec_task(i) for i in range(n_each)] + [
            sftp_task(i) for i in range(n_each)
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        exec_ok = sum(1 for r in results[:n_each] if r is True)
        sftp_ok = sum(1 for r in results[n_each:] if r is True)
        return exec_ok, sftp_ok

    try:
        exec_ok, sftp_ok = asyncio.run(_mixed())
        label = f"Mixed async workload ({n_each} exec + {n_each} sftp concurrent)"
        if exec_ok == n_each and sftp_ok == n_each:
            passed(label)
        else:
            failed(label, f"exec={exec_ok}/{n_each} sftp={sftp_ok}/{n_each}")
    except Exception as e:
        failed(
            f"Mixed async workload ({n_each} exec + {n_each} sftp concurrent)",
            f"{type(e).__name__}: {e}",
        )


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Failure Classification
# ═══════════════════════════════════════════════════════════════════════════════


def _catch(fn: Callable[[], None]) -> Exception | None:
    try:
        fn()
        return None
    except Exception as e:
        return e


async def _async_catch(coro: Any) -> Exception | None:
    try:
        await coro
        return None
    except Exception as e:
        return e


def _exc_label(exc: Exception | None) -> str:
    if exc is None:
        return "no exception"
    return type(exc).__name__


def check_failure_classification(cfg: dict[str, Any]) -> None:
    section(6, "Failure Classification")

    bad_cfg = {**cfg, "password": "spindlex_bench_deliberately_wrong_xyz999"}

    def _sync_bad_auth() -> None:
        c = SSHClient()
        c.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        c.connect(
            hostname=bad_cfg["host"],
            port=bad_cfg["port"],
            username=bad_cfg["user"],
            password=bad_cfg["password"],
        )
        c.close()

    async def _async_bad_auth() -> None:
        ac = AsyncSSHClient()
        ac.set_missing_host_key_policy(AutoAddPolicy(accept_risk=True))
        await ac.connect(
            hostname=bad_cfg["host"],
            port=bad_cfg["port"],
            username=bad_cfg["user"],
            password=bad_cfg["password"],
        )
        await ac.close()

    sync_auth_exc = _catch(_sync_bad_auth)
    async_auth_exc = asyncio.run(_async_catch(_async_bad_auth()))

    for mode, exc in [("sync", sync_auth_exc), ("async", async_auth_exc)]:
        label = f"Auth failure ({mode}) — raises AuthenticationException"
        if exc is None:
            failed(label, "no exception for wrong password")
        elif isinstance(exc, AuthenticationException):
            passed(label)
        elif isinstance(exc, SSHException):
            warned(
                label, f"got {type(exc).__name__} (expected AuthenticationException)"
            )
        else:
            failed(label, f"non-SSH exception: {type(exc).__name__}")

    label_cons = "Auth failure — sync/async exception type consistent"
    if sync_auth_exc is not None and async_auth_exc is not None:
        if type(sync_auth_exc) is type(async_auth_exc):
            passed(label_cons, type(sync_auth_exc).__name__)
        else:
            failed(
                label_cons,
                f"sync={_exc_label(sync_auth_exc)} async={_exc_label(async_auth_exc)}",
            )
    else:
        skipped(label_cons, "one or both modes had no exception")

    # Bad KEX — must raise SSHException (not raw/internal exception)
    def _sync_bad_kex() -> None:
        with _force_algos(kex="nonexistent-kex-prod-bench"):
            spx_open(cfg).close()

    async def _async_bad_kex() -> None:
        with _force_algos(kex="nonexistent-kex-prod-bench"):
            ac = await spx_async_open(cfg)
            await ac.close()

    sync_kex_exc = _catch(_sync_bad_kex)
    async_kex_exc = asyncio.run(_async_catch(_async_bad_kex()))

    for mode, exc in [("sync", sync_kex_exc), ("async", async_kex_exc)]:
        label = f"KEX mismatch ({mode}) — raises SSHException subclass"
        if exc is None:
            failed(label, "no exception for nonexistent KEX")
        elif isinstance(exc, SSHException):
            passed(label, type(exc).__name__)
        else:
            failed(label, f"raw non-SSH exception: {type(exc).__name__}: {exc}")

    label_kex_cons = "KEX mismatch — sync/async exception type consistent"
    if sync_kex_exc is not None and async_kex_exc is not None:
        if type(sync_kex_exc) is type(async_kex_exc):
            passed(label_kex_cons, type(sync_kex_exc).__name__)
        else:
            failed(
                label_kex_cons,
                f"sync={_exc_label(sync_kex_exc)} async={_exc_label(async_kex_exc)}",
            )
    else:
        skipped(label_kex_cons, "one or both modes had no exception")

    # Bad cipher — must raise SSHException
    def _sync_bad_cipher() -> None:
        with _force_algos(cipher="nonexistent-cipher-prod-bench"):
            spx_open(cfg).close()

    ciph_exc = _catch(_sync_bad_cipher)
    label = "Cipher mismatch (sync) — raises SSHException subclass"
    if ciph_exc is None:
        failed(label, "no exception for nonexistent cipher")
    elif isinstance(ciph_exc, SSHException):
        passed(label, type(ciph_exc).__name__)
    else:
        failed(label, f"raw non-SSH exception: {type(ciph_exc).__name__}: {ciph_exc}")


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Negotiation Determinism
# ═══════════════════════════════════════════════════════════════════════════════


def check_negotiation_determinism(cfg: dict[str, Any], run_cfg: RunConfig) -> None:
    section(7, f"Negotiation Determinism  ({run_cfg.negotiation_repeats} runs each)")

    profiles: list[tuple[str, dict[str, str]]] = [
        ("kex=curve25519-sha256", {"kex": "curve25519-sha256"}),
        ("kex=ecdh-sha2-nistp256", {"kex": "ecdh-sha2-nistp256"}),
        ("cipher=aes256-ctr", {"cipher": "aes256-ctr"}),
        ("cipher=aes128-ctr", {"cipher": "aes128-ctr"}),
    ]

    for label, kwargs in profiles:
        outcomes: list[str] = []
        for _ in range(run_cfg.negotiation_repeats):
            try:
                with _force_algos(**kwargs):
                    spx_open(cfg).close()
                outcomes.append("OK")
            except SSHException as e:
                outcomes.append(type(e).__name__)
            except Exception as e:
                outcomes.append(f"RAW:{type(e).__name__}")

        unique = set(outcomes)
        check_label = f"Determinism  {label}"
        if len(unique) == 1:
            result = outcomes[0]
            if result == "OK":
                passed(
                    check_label, f"{run_cfg.negotiation_repeats}x consistent success"
                )
            else:
                # Consistently fails — deterministic, just unsupported
                skipped(
                    check_label,
                    f"{run_cfg.negotiation_repeats}x consistently: {result}",
                )
        else:
            failed(
                check_label,
                f"flapping outcomes across {run_cfg.negotiation_repeats} runs: {outcomes}",
            )


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Performance Stability
# ═══════════════════════════════════════════════════════════════════════════════


def check_performance_stability(cfg: dict[str, Any], run_cfg: RunConfig) -> None:
    section(
        8, f"Performance Stability  ({run_cfg.stability_runs} sequential handshakes)"
    )

    samples: list[float] = []
    errors = 0

    for _ in range(run_cfg.stability_runs):
        t0 = time.perf_counter()
        try:
            spx_open(cfg).close()
            samples.append(time.perf_counter() - t0)
        except Exception:
            errors += 1

    if len(samples) < 5:
        failed(
            "Performance stability",
            f"too few valid samples ({len(samples)}) to analyze",
        )
        return

    ms = [s * 1000 for s in samples]
    med = statistics.median(ms)
    mean = statistics.fmean(ms)
    stdev = statistics.pstdev(ms)
    srt = sorted(ms)
    p95 = srt[int(len(srt) * 0.95)]
    p99 = srt[min(int(len(srt) * 0.99), len(srt) - 1)]

    print(f"    median={med:.1f}ms  mean={mean:.1f}ms  stdev={stdev:.1f}ms")
    print(
        f"    p95={p95:.1f}ms  p99={p99:.1f}ms  errors={errors}/{run_cfg.stability_runs}"
    )

    # Jitter: p99 should be < 5x median
    jitter = p99 / med if med > 0 else float("inf")
    if jitter < 5:
        passed("Jitter  (p99 / median)", f"{jitter:.2f}x  (threshold: <5x)")
    elif jitter < 10:
        warned("Jitter  (p99 / median)", f"{jitter:.2f}x  (warning: >5x)")
    else:
        failed("Jitter  (p99 / median)", f"{jitter:.2f}x  (critical: >10x)")

    # Slowdown: last 10% avg vs first 10%
    q = max(1, len(ms) // 10)
    first_avg = statistics.fmean(ms[:q])
    last_avg = statistics.fmean(ms[-q:])
    slowdown = last_avg / first_avg if first_avg > 0 else float("inf")
    if slowdown < 2.0:
        passed(
            "Cumulative slowdown  (last/first 10%)",
            f"{slowdown:.2f}x  (threshold: <2x)",
        )
    elif slowdown < 3.0:
        warned(
            "Cumulative slowdown  (last/first 10%)", f"{slowdown:.2f}x  (warning: >2x)"
        )
    else:
        failed(
            "Cumulative slowdown  (last/first 10%)", f"{slowdown:.2f}x  (critical: >3x)"
        )

    # Error rate
    error_rate = errors / run_cfg.stability_runs
    if error_rate == 0:
        passed("Error rate", f"0/{run_cfg.stability_runs}")
    elif error_rate < 0.05:
        warned("Error rate", f"{errors}/{run_cfg.stability_runs} ({error_rate:.1%})")
    else:
        failed("Error rate", f"{errors}/{run_cfg.stability_runs} ({error_rate:.1%})")


# ═══════════════════════════════════════════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════════════════════════════════════════


def print_summary() -> None:
    counts: dict[str, int] = {"PASS": 0, "FAIL": 0, "WARN": 0, "SKIP": 0}
    for r in _results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print("\n" + "=" * 74)
    print("  PRODUCTION READINESS SUMMARY")
    print("=" * 74)
    print(f"  Total checks : {len(_results)}")
    print(f"  PASS         : {counts['PASS']}")
    print(f"  WARN         : {counts['WARN']}")
    print(f"  FAIL         : {counts['FAIL']}")
    print(
        f"  SKIP         : {counts['SKIP']}  (server may not support those algorithms)"
    )

    if counts["FAIL"]:
        print("\n  Failed checks:")
        for r in _results:
            if r.status == "FAIL":
                print(f"    - {r.label}: {r.detail}")

    if counts["WARN"]:
        print("\n  Warnings:")
        for r in _results:
            if r.status == "WARN":
                print(f"    - {r.label}: {r.detail}")

    if counts["FAIL"] == 0 and counts["WARN"] == 0:
        verdict = "PRODUCTION READY"
    elif counts["FAIL"] == 0:
        verdict = "PRODUCTION READY  (review warnings)"
    elif counts["FAIL"] <= 3:
        verdict = "NEEDS ATTENTION"
    else:
        verdict = "NOT PRODUCTION READY"

    print(f"\n  Verdict: {verdict}")
    print("=" * 74)


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════


def main() -> None:
    parser = argparse.ArgumentParser(
        description="SpindleX Production Readiness Benchmark"
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Reduced iteration counts for fast feedback",
    )
    args = parser.parse_args()

    cfg = load_env()
    if not cfg["host"] or not cfg["user"] or not cfg["password"]:
        print(
            "ERROR: SSH_HOST / SSH_USER / SSH_PASSWORD not set in .env or environment"
        )
        sys.exit(1)

    run_cfg = quick_config() if args.quick else RunConfig()

    print("=" * 74)
    print("  SpindleX Production Readiness Benchmark")
    print("=" * 74)
    print(f"  Target  : {cfg['user']}@{cfg['host']}:{cfg['port']}")
    print(f"  Version : spindlex {spindlex.__version__}")
    print(f"  Mode    : {'quick' if args.quick else 'full'}")
    print(
        f"  Config  : {run_cfg.sequential_sessions} sequential sessions, "
        f"{run_cfg.stability_runs} stability runs, "
        f"concurrent levels {run_cfg.concurrent_levels}"
    )

    check_protocol_correctness(cfg)
    check_session_lifecycle(cfg, run_cfg)
    check_exec_reliability(cfg, run_cfg)
    check_sftp_integrity(cfg)
    check_concurrency_correctness(cfg, run_cfg)
    check_failure_classification(cfg)
    check_negotiation_determinism(cfg, run_cfg)
    check_performance_stability(cfg, run_cfg)

    print_summary()


if __name__ == "__main__":
    main()
