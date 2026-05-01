"""
Per-algorithm SSH/SFTP benchmark: cipher suites, KEX methods, host-key types.

Compares spindlex, paramiko, and asyncssh with forced algorithm configurations
to measure the performance impact of each security choice.

Sections:
  A. Cipher comparison    — fixed KEX=curve25519, hostkey negotiated from defaults
  B. KEX comparison       — fixed cipher=aes256-ctr
  C. Host-key comparison  — fixed cipher=aes256-ctr, KEX=curve25519

Workloads per section:
  handshake  — full connect+auth+close  (reflects KEX / hostkey cost)
  sftp-up    — 1 MiB upload             (reflects cipher throughput)
  sftp-down  — 1 MiB download           (reflects cipher throughput)
"""

from __future__ import annotations

import asyncio
import os
import statistics
import sys
import time
import traceback
import warnings
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import asyncssh  # noqa: E402
import paramiko  # noqa: E402

import spindlex  # noqa: E402
from spindlex import SSHClient  # noqa: E402
from spindlex.crypto.ciphers import CipherSuite  # noqa: E402
from spindlex.hostkeys.policy import AutoAddPolicy  # noqa: E402

warnings.filterwarnings("ignore", category=UserWarning)

ITERATIONS = 3
WARMUP = 1
PAYLOAD_SIZE = 1024 * 1024  # 1 MiB
SFTP_CHUNK = 16 * 1024

# ── Algorithm profiles ────────────────────────────────────────────────────────

CIPHER_PROFILES: list[dict[str, Any]] = [
    {"label": "aes256-ctr",        "cipher": "aes256-ctr"},
    {"label": "aes192-ctr",        "cipher": "aes192-ctr"},
    {"label": "aes128-ctr",        "cipher": "aes128-ctr"},
]

KEX_PROFILES: list[dict[str, Any]] = [
    {"label": "curve25519-sha256",   "kex": "curve25519-sha256",             "cipher": "aes256-ctr"},
    {"label": "ecdh-nistp256",       "kex": "ecdh-sha2-nistp256",            "cipher": "aes256-ctr"},
    {"label": "dh-group14-sha256",   "kex": "diffie-hellman-group14-sha256", "cipher": "aes256-ctr"},
]

HOSTKEY_PROFILES: list[dict[str, Any]] = [
    {"label": "ed25519",      "hostkey": "ssh-ed25519",         "cipher": "aes256-ctr", "kex": "curve25519-sha256"},
    {"label": "ecdsa-p256",   "hostkey": "ecdsa-sha2-nistp256", "cipher": "aes256-ctr", "kex": "curve25519-sha256"},
    {"label": "rsa-sha2-256", "hostkey": "rsa-sha2-256",        "cipher": "aes256-ctr", "kex": "curve25519-sha256"},
]

# ── Algorithm-forcing helpers ─────────────────────────────────────────────────

# Complete known lists for paramiko disabled_algorithms computation.
_ALL_PMK_CIPHERS = [
    "aes128-ctr", "aes192-ctr", "aes256-ctr",
    "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc",
]
_ALL_PMK_KEX = [
    "curve25519-sha256", "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521",
    "diffie-hellman-group14-sha256", "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1",
]
_ALL_PMK_HOSTKEYS = [
    "ssh-ed25519",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "rsa-sha2-256", "rsa-sha2-512", "ssh-rsa",
]


@contextmanager
def spindlex_profile(
    cipher: str | None = None,
    kex: str | None = None,
    hostkey: str | None = None,
) -> Iterator[None]:
    """Temporarily override CipherSuite class-level algorithm lists."""
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


def pmk_disabled(
    cipher: str | None = None,
    kex: str | None = None,
    hostkey: str | None = None,
) -> dict[str, list[str]]:
    """Build paramiko disabled_algorithms dict to force a specific algorithm."""
    d: dict[str, list[str]] = {}
    if cipher:
        d["ciphers"] = [c for c in _ALL_PMK_CIPHERS if c != cipher]
    if kex:
        # curve25519 has two name aliases in paramiko's preference list
        keep = {"curve25519-sha256", "curve25519-sha256@libssh.org"} if "curve25519" in kex else {kex}
        d["kex"] = [k for k in _ALL_PMK_KEX if k not in keep]
    if hostkey:
        d["keys"] = [k for k in _ALL_PMK_HOSTKEYS if k != hostkey]
    return d


def asyncssh_kw(
    cipher: str | None = None,
    kex: str | None = None,
    hostkey: str | None = None,
) -> dict[str, Any]:
    """Build asyncssh.connect() kwargs to force a specific algorithm."""
    kw: dict[str, Any] = {"known_hosts": None}
    if cipher:
        kw["encryption_algs"] = [cipher]
    if kex:
        kw["kex_algs"] = [kex]
    if hostkey:
        kw["server_host_key_algs"] = [hostkey]
    return kw


# ── Timing utilities ──────────────────────────────────────────────────────────


def stats(samples: list[float]) -> dict[str, float]:
    if not samples:
        return {"median": float("nan"), "mean": float("nan"), "stdev": float("nan")}
    return {
        "median": statistics.median(samples),
        "mean": statistics.fmean(samples),
        "stdev": statistics.pstdev(samples) if len(samples) > 1 else 0.0,
    }


def safe(label: str, fn: Callable[[], list[float]]) -> dict[str, Any]:
    try:
        return stats(fn())
    except BaseException as e:
        if isinstance(e, KeyboardInterrupt):
            raise
        tb = traceback.format_exception_only(type(e), e)[-1].strip()
        return {"error": tb, "label": label}


def time_sync(fn: Callable[[], None], iters: int) -> list[float]:
    for _ in range(WARMUP):
        try:
            fn()
        except Exception:
            pass
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        fn()
        samples.append(time.perf_counter() - t0)
    return samples


def time_async(coro_fn: Callable[[], Any], iters: int) -> list[float]:
    async def _run() -> list[float]:
        for _ in range(WARMUP):
            try:
                await coro_fn()
            except Exception:
                pass
        samples = []
        for _ in range(iters):
            t0 = time.perf_counter()
            await coro_fn()
            samples.append(time.perf_counter() - t0)
        return samples

    return asyncio.run(_run())


# ── Load .env ─────────────────────────────────────────────────────────────────


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


# ── Connection helpers ────────────────────────────────────────────────────────


def spindlex_open(cfg: dict[str, Any]) -> SSHClient:
    c = SSHClient()
    c.set_missing_host_key_policy(AutoAddPolicy())
    c.connect(
        hostname=cfg["host"],
        port=cfg["port"],
        username=cfg["user"],
        password=cfg["password"],
    )
    return c


def paramiko_open(
    cfg: dict[str, Any], disabled: dict[str, list[str]] | None = None
) -> paramiko.SSHClient:
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(
        hostname=cfg["host"],
        port=cfg["port"],
        username=cfg["user"],
        password=cfg["password"],
        allow_agent=False,
        look_for_keys=False,
        disabled_algorithms=disabled or {},
    )
    return c


async def asyncssh_open(
    cfg: dict[str, Any], **kw: Any
) -> asyncssh.SSHClientConnection:
    return await asyncssh.connect(
        host=cfg["host"],
        port=cfg["port"],
        username=cfg["user"],
        password=cfg["password"],
        **kw,
    )


# ── Benchmark workloads ───────────────────────────────────────────────────────


def bench_handshake(cfg: dict[str, Any], profile: dict[str, Any]) -> dict[str, dict[str, Any]]:
    cipher  = profile.get("cipher")
    kex     = profile.get("kex")
    hostkey = profile.get("hostkey")
    disabled = pmk_disabled(cipher=cipher, kex=kex, hostkey=hostkey)
    akw      = asyncssh_kw(cipher=cipher, kex=kex, hostkey=hostkey)

    def _spx() -> list[float]:
        with spindlex_profile(cipher=cipher, kex=kex, hostkey=hostkey):
            return time_sync(lambda: spindlex_open(cfg).close(), ITERATIONS)

    def _pmk() -> list[float]:
        return time_sync(lambda: paramiko_open(cfg, disabled).close(), ITERATIONS)

    def _assh() -> list[float]:
        async def _hs() -> None:
            conn = await asyncssh_open(cfg, **akw)
            conn.close()
            await conn.wait_closed()

        return time_async(_hs, ITERATIONS)

    return {
        "spindlex": safe("spindlex", _spx),
        "paramiko":  safe("paramiko", _pmk),
        "asyncssh":  safe("asyncssh", _assh),
    }


def bench_sftp_upload(
    cfg: dict[str, Any],
    payload: bytes,
    remote: str,
    profile: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    cipher  = profile.get("cipher")
    kex     = profile.get("kex")
    hostkey = profile.get("hostkey")
    disabled = pmk_disabled(cipher=cipher, kex=kex, hostkey=hostkey)
    akw      = asyncssh_kw(cipher=cipher, kex=kex, hostkey=hostkey)

    def _spx() -> list[float]:
        with spindlex_profile(cipher=cipher, kex=kex, hostkey=hostkey):
            c = spindlex_open(cfg)
            sftp = c.open_sftp()
            try:
                def _do() -> None:
                    with sftp.open(remote, "wb") as fh:
                        for off in range(0, len(payload), SFTP_CHUNK):
                            fh.write(payload[off : off + SFTP_CHUNK])

                return time_sync(_do, ITERATIONS)
            finally:
                sftp.close()
                c.close()

    def _pmk() -> list[float]:
        p = paramiko_open(cfg, disabled)
        sftp_p = p.open_sftp()
        try:
            def _do_p() -> None:
                with sftp_p.open(remote, "wb") as fh:
                    fh.write(payload)

            return time_sync(_do_p, ITERATIONS)
        finally:
            sftp_p.close()
            p.close()

    async def _assh_run() -> list[float]:
        conn = await asyncssh_open(cfg, **akw)
        sftp_a = await conn.start_sftp_client()
        try:
            samples: list[float] = []

            async def _wr() -> None:
                async with sftp_a.open(remote, "wb") as fh:
                    await fh.write(payload)

            for _ in range(WARMUP):
                await _wr()
            for _ in range(ITERATIONS):
                t0 = time.perf_counter()
                await _wr()
                samples.append(time.perf_counter() - t0)
            return samples
        finally:
            sftp_a.exit()
            conn.close()
            await conn.wait_closed()

    return {
        "spindlex": safe("spindlex", _spx),
        "paramiko":  safe("paramiko", _pmk),
        "asyncssh":  safe("asyncssh", lambda: asyncio.run(_assh_run())),
    }


def bench_sftp_download(
    cfg: dict[str, Any],
    remote: str,
    profile: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    cipher  = profile.get("cipher")
    kex     = profile.get("kex")
    hostkey = profile.get("hostkey")
    disabled = pmk_disabled(cipher=cipher, kex=kex, hostkey=hostkey)
    akw      = asyncssh_kw(cipher=cipher, kex=kex, hostkey=hostkey)

    def _spx() -> list[float]:
        with spindlex_profile(cipher=cipher, kex=kex, hostkey=hostkey):
            c = spindlex_open(cfg)
            sftp = c.open_sftp()
            try:
                def _do() -> None:
                    with sftp.open(remote, "rb") as fh:
                        fh.read()

                return time_sync(_do, ITERATIONS)
            finally:
                sftp.close()
                c.close()

    def _pmk() -> list[float]:
        p = paramiko_open(cfg, disabled)
        sftp_p = p.open_sftp()
        try:
            def _do_p() -> None:
                with sftp_p.open(remote, "rb") as fh:
                    fh.read()

            return time_sync(_do_p, ITERATIONS)
        finally:
            sftp_p.close()
            p.close()

    async def _assh_run() -> list[float]:
        conn = await asyncssh_open(cfg, **akw)
        sftp_a = await conn.start_sftp_client()
        try:
            samples: list[float] = []

            async def _rd() -> None:
                async with sftp_a.open(remote, "rb") as fh:
                    await fh.read()

            for _ in range(WARMUP):
                await _rd()
            for _ in range(ITERATIONS):
                t0 = time.perf_counter()
                await _rd()
                samples.append(time.perf_counter() - t0)
            return samples
        finally:
            sftp_a.exit()
            conn.close()
            await conn.wait_closed()

    return {
        "spindlex": safe("spindlex", _spx),
        "paramiko":  safe("paramiko", _pmk),
        "asyncssh":  safe("asyncssh", lambda: asyncio.run(_assh_run())),
    }


# ── Display ───────────────────────────────────────────────────────────────────

LIBS = ["spindlex", "paramiko", "asyncssh"]


def _cell(s: dict[str, Any]) -> str:
    if "error" in s:
        short = s["error"]
        return f"FAIL({short[:200]})"
    return f"{s['median'] * 1000:7.1f} ±{s['stdev'] * 1000:5.1f} ms"


def print_table(
    title: str,
    profiles: list[dict[str, Any]],
    workload_fn: Callable[[dict[str, Any]], dict[str, dict[str, Any]]],
    *,
    show_progress: bool = True,
) -> None:
    print(f"\n  {title}")
    print(f"  {'Profile':<22}" + "".join(f"  {lib:<26}" for lib in LIBS))
    print("  " + "-" * (22 + len(LIBS) * 28))
    for p in profiles:
        if show_progress:
            print(f"    running {p['label']} ...", end="\r", flush=True)
        results = workload_fn(p)
        row = f"  {p['label']:<22}"
        for lib in LIBS:
            row += f"  {_cell(results.get(lib, {'error': 'n/a'})):<26}"
        print(row + " " * 30)  # overwrite progress


def section(label: str) -> None:
    print(f"\n{'='*72}")
    print(f"  {label}")
    print(f"{'='*72}")


# ── Main ──────────────────────────────────────────────────────────────────────


def main() -> None:
    cfg = load_env()
    if not cfg["host"] or not cfg["user"] or not cfg["password"]:
        print("ERROR: SSH_HOST / SSH_USER / SSH_PASSWORD not set in .env")
        sys.exit(1)

    print(f"\nTarget : {cfg['user']}@{cfg['host']}:{cfg['port']}")
    print(f"Libs   : spindlex={spindlex.__version__}  paramiko={paramiko.__version__}  asyncssh={asyncssh.__version__}")
    print(f"Config : {ITERATIONS} iterations (after {WARMUP} warmup)  |  payload={PAYLOAD_SIZE // 1024} KiB  |  chunk={SFTP_CHUNK // 1024} KiB")

    payload = os.urandom(PAYLOAD_SIZE)
    remote  = f"/tmp/spx_algobench_{os.getpid()}.bin"

    # ── A. Cipher comparison ──────────────────────────────────────────────────
    section("A  CIPHER COMPARISON  (KEX=curve25519 default, hostkey=ed25519 default)")

    print_table(
        "Handshake (connect+auth+close)",
        CIPHER_PROFILES,
        lambda p: bench_handshake(cfg, p),
    )
    print_table(
        "SFTP Upload 1 MiB",
        CIPHER_PROFILES,
        lambda p: bench_sftp_upload(cfg, payload, remote, p),
    )
    print_table(
        "SFTP Download 1 MiB",
        CIPHER_PROFILES,
        lambda p: bench_sftp_download(cfg, remote, p),
    )

    # ── B. KEX comparison ─────────────────────────────────────────────────────
    section("B  KEX COMPARISON  (cipher=aes256-ctr, hostkey=ed25519 default)")
    print("  Note: KEX only affects handshake cost; bulk-data tables omitted.")

    print_table(
        "Handshake (connect+auth+close)",
        KEX_PROFILES,
        lambda p: bench_handshake(cfg, p),
    )

    # ── C. Host-key comparison ────────────────────────────────────────────────
    section("C  HOST-KEY COMPARISON  (cipher=aes256-ctr, KEX=curve25519)")
    print("  Note: host-key type only affects signature verify during handshake.")

    print_table(
        "Handshake (connect+auth+close)",
        HOSTKEY_PROFILES,
        lambda p: bench_handshake(cfg, p),
    )

    # cleanup
    try:
        with spindlex_profile():
            c = spindlex_open(cfg)
            sftp = c.open_sftp()
            try:
                sftp.remove(remote)
            finally:
                sftp.close()
                c.close()
    except Exception as e:
        print(f"\n  (cleanup failed: {e})")

    print("\nDone.")


if __name__ == "__main__":
    main()
