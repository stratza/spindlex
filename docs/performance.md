# Performance Guide

This guide covers performance optimization techniques, benchmarking, and the internal architecture that makes SpindleX a highly efficient SSH library.

## Performance Overview

SpindleX is engineered for speed, security, and protocol efficiency. Key performance features include:

*   **:zap: Internal Read Buffering**: Configurable read buffering architecture (via `SPINDLEX_BUFFER_SIZE`) that minimizes syscall overhead by chunking protocol data.
*   **:rocket: Low Latency I/O**: Native management of `TCP_NODELAY` to bypass Nagle's algorithm, reducing latency for small packets.
*   **:package: Lean Design**: Optimized protocol layer leveraging the industry-standard `cryptography` library.
*   **:link: Streamlined Handshake**: Efficient version exchange and key negotiation logic.
*   **:shield: Modern Cryptography**: ChaCha20-Poly1305 (preferred AEAD cipher), Ed25519, Curve25519, and AES-CTR with HMAC-SHA2.

## Benchmarking and Profiling

### Benchmark Scripts

SpindleX ships repeatable benchmark scripts in `scripts/`:

- **`benchmark_ciphers.py`** - compares upload throughput across all supported ciphers (ChaCha20-Poly1305, AES-256/192/128-CTR) against other SSH libraries on a live server configured in `.env`.
- **`benchmark_production.py`** - full protocol correctness and performance sweep: verifies every cipher, MAC, KEX, and host-key algorithm negotiates and transfers data correctly, then reports timing.
- **`benchmark_local_baseline.py`** - zero-cost Docker-backed baseline against local OpenSSH and Dropbear services. It writes JSON artifacts for handshake, command execution, SFTP upload/download, and sync/async paths.

```bash
python scripts/benchmark_ciphers.py
python scripts/benchmark_production.py
python scripts/benchmark_local_baseline.py --output benchmark-results/local.json
```

The local baseline records environment metadata and should be used for comparing
project changes over time, not for universal performance claims.

### Packet-Level Profiler

Set `SPINDLEX_PROFILE=1` to enable the built-in `PacketProfiler`, which records per-packet build / encrypt / socket-write latencies for every packet sent through the transport:

```bash
SPINDLEX_PROFILE=1 python your_script.py
```

The profiler is a zero-overhead no-op when the env var is absent. When active, call `transport._profiler.summary()` to get median and P95 timings broken down by stage:

```
PacketProfiler (500 packets) - median / P95 in µs:
  build:     9.4 /  14.1
  encrypt:  53.7 /  71.2
  write:    20.5 /  38.9
  total:    83.6 / 124.2
```

### Performance Metrics

When benchmarking SpindleX, focus on these metrics:

1.  **Handshake & Connect Time**: Time from socket creation to authentication success.
2.  **SFTP Transfer Rate**: Throughput for file transfers over encrypted channels.
3.  **Command Execution Latency**: Round-trip time for command execution and output retrieval.

## Data Transfer Optimization

### Read Buffering

SpindleX uses an internal buffering strategy for I/O operations. By reading data in larger chunks (default 32KB), it reduces the number of `socket.recv()` calls, which is often a bottleneck in high-throughput network applications.

You can tune this buffer size using the `SPINDLEX_BUFFER_SIZE` environment variable (e.g., `export SPINDLEX_BUFFER_SIZE=65536` for high-latency connections).

### TCP_NODELAY

By default, SpindleX enables `TCP_NODELAY` on the underlying transport socket. This ensures that packets are sent immediately without waiting for the buffer to fill up, which is critical for interactive shells and low-latency command execution.

## Performance Monitoring Tools

SpindleX provides advanced monitoring tools to profile your SSH operations in real-time. These tools are available in the `spindlex.logging.monitoring` module.

### Performance Monitor

The `PerformanceMonitor` tracks operation timings, throughput, and error rates.

```python
from spindlex.logging.monitoring import get_performance_monitor

monitor = get_performance_monitor()

# You can also manually track custom operations:
with monitor.time_operation("my_bulk_transfer"):
    # Perform operations
    pass

# Print a summary of performance metrics
monitor.print_summary()
```

### Protocol Analyzer

The `ProtocolAnalyzer` provides insights into the SSH protocol exchange, including packet types, sizes, and frequencies.

```python
from spindlex.logging.monitoring import get_protocol_analyzer

analyzer = get_protocol_analyzer()

# Get statistics about packet distribution
stats = analyzer.get_message_stats()
for msg_type, data in stats.items():
    print(f"Message {msg_type}: {data['count']} packets, {data['total_bytes']} bytes")
```

## Best Practices Summary

1.  **Use Connection Pooling**: Reuse SSH connections for multiple operations to avoid the overhead of repeated handshakes.
2.  **Choose Modern Algorithms**: ChaCha20-Poly1305 is the default and preferred cipher - it is AEAD (no separate MAC pass) and matches other leading SSH libraries on typical hardware.
3.  **Stream Large Files**: Use the SFTP streaming methods to minimize memory usage for large file transfers. SpindleX automatically negotiates `limits@openssh.com` with OpenSSH servers to use write chunks up to 255 KB, reducing round trips by ~8× compared to the 32 KB default.
4.  **Monitor Network Latency**: Use the built-in monitoring tools to track performance across different network environments.
