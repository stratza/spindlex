# Comparison

This page compares SpindleX to other Python SSH libraries. The goal is to help
you choose the right library for your use case, not to claim universal
superiority. Every library has trade-offs.

!!! info "Benchmark environment"
    Numbers below are from the SpindleX v0.7.3 production readiness benchmark
    (`scripts/benchmark_production.py`) run against a Docker-backed OpenSSH
    server on the same host. They reflect loopback conditions - real-network
    results will differ. See [Performance](performance.md) for methodology.

---

## Libraries Compared

| | SpindleX | Paramiko | AsyncSSH |
|---|---|---|---|
| **License** | MIT | LGPL-2.1 | Eclipse Public License 2.0 |
| **Python support** | 3.9–3.13 | 3.8+ | 3.6+ |
| **Async-first** | Yes | No (add-on) | Yes |
| **Dependencies** | `cryptography` only | `cryptography`, `bcrypt`, `pynacl` | `cryptography` |
| **Type hints** | Full, strict mypy | Partial | Partial |
| **ChaCha20-Poly1305** | Yes (preferred) | Yes | Yes |
| **Compression** | No | Yes (zlib) | Yes (zlib) |
| **GSSAPI** | Optional (Unix) | Yes | Yes |
| **SSH server** | Yes (controlled environments) | Yes | Yes |
| **SFTP server** | Yes (controlled environments) | Yes | Yes |
| **SCP** | No | Yes | No |
| **Agent forwarding** | No | Yes | Yes |
| **X11 forwarding** | No | Yes | No |

---

## Performance

The numbers below are median timings over 10 iterations (loopback, same host).

### SSH handshake latency

| Library | Median |
|---------|--------|
| SpindleX | 53–65 ms |
| AsyncSSH | 60–67 ms |
| Paramiko | 87–90 ms |

### SFTP upload (1 MB file)

| Library | Median |
|---------|--------|
| SpindleX | 14–15 ms |
| AsyncSSH | 19–23 ms |
| Paramiko | 54–58 ms |

### SFTP download (1 MB file)

| Library | Median |
|---------|--------|
| SpindleX | 15–18 ms |
| AsyncSSH | 15–17 ms |
| Paramiko | 356–368 ms |

These numbers are loopback only. Network latency dominates in practice. Run
`scripts/benchmark_production.py` in your own environment to get numbers
relevant to your servers and network conditions.

---

## SpindleX vs Paramiko

**Choose SpindleX if:**

- You want a modern async-first API with `asyncio` support built in.
- You want ChaCha20-Poly1305 as the preferred cipher with Terrapin defense.
- You want strict type hints across the entire public API.
- You want minimal dependencies (only `cryptography`).
- You prefer MIT licensing for commercial or proprietary projects.
- SFTP throughput matters - SpindleX adaptive write chunks (up to 255 KB via
  `limits@openssh.com`) reduce round trips significantly.

**Choose Paramiko if:**

- You need SCP transfers.
- You need SSH agent forwarding.
- You need X11 forwarding.
- You need GSSAPI key exchange (not just auth).
- You are deploying on a large existing codebase already built on Paramiko.
- You need support for legacy algorithms that SpindleX deliberately excludes
  (SHA-1 MACs, CBC ciphers, Group 1 DH).
- Long-term library stability matters more than modern API design - Paramiko
  has a longer track record in production.

**Feature gaps to know about:**

SpindleX does not implement: SCP, agent forwarding, X11 forwarding, GSSAPI key
exchange, or compression. These are deliberate scope decisions. If your use case
requires any of these features, SpindleX is not the right choice today.

---

## SpindleX vs AsyncSSH

**Choose SpindleX if:**

- You want MIT licensing (AsyncSSH uses Eclipse Public License 2.0).
- You want a library that explicitly refuses to negotiate weak algorithms at
  the protocol level (SHA-1 KEX, CBC ciphers, MD5 MACs).
- You want a single `cryptography` dependency with no optional native extensions
  required for the core feature set.

**Choose AsyncSSH if:**

- You need X11 forwarding.
- You need SSH agent forwarding.
- You need `zlib` compression.
- You need GSSAPI key exchange.
- You are already in an `asyncio` codebase and value a more mature async library
  with a longer track record.
- You need broader OpenSSH and legacy server compatibility.

AsyncSSH has a significantly larger feature set than SpindleX. If your use case
goes beyond SSH command execution and SFTP file transfer, AsyncSSH is likely the
better choice today.

---

## What SpindleX Does Not Support

These features are intentionally out of scope for SpindleX 1.0:

- **SCP** - SFTP is the modern replacement and is fully supported.
- **Compression** - Not implemented; `none` is the only advertised method.
- **SSH agent forwarding** - Not implemented.
- **X11 forwarding** - Not implemented.
- **GSSAPI key exchange** - GSSAPI authentication (not KEX) is available as an
  optional extra on Unix.
- **Legacy algorithms** - SHA-1 KEX/MACs, CBC ciphers, DH Group 1, MD5 MACs are
  explicitly excluded. SpindleX will never negotiate these.
- **Universal SSH server compatibility** - Tested against OpenSSH and Dropbear.
  Appliance-specific or legacy SSH server behavior may not be compatible.

---

## Honest Limitations

SpindleX `1.0.0` is the project's first stable release. Paramiko has been in
production for over 15 years. AsyncSSH has been production-used for over 10
years. SpindleX does not have that track record yet.

Before adopting SpindleX in a production system:

- Run your own integration tests against your actual SSH servers.
- Review the [Compatibility](compatibility.md) page for known incompatibilities.
- Review the [Security Guide](security.md) for security expectations.
- Pin an exact version and treat upgrades as deliberate changes.
