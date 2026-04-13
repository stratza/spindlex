# Performance Guide

This guide covers performance optimization techniques, benchmarking, and the internal architecture that makes SpindleX a highly efficient SSH library.

## Performance Overview

SpindleX is engineered for speed, security, and protocol efficiency. Key performance features include:

*   **:zap: Internal Read Buffering**: 32KB read buffering architecture that minimizes syscall overhead by chunking protocol data.
*   **:rocket: Low Latency I/O**: Native management of `TCP_NODELAY` to bypass Nagle's algorithm, reducing latency for small packets.
*   **:package: Lean Design**: Optimized protocol layer leveraging the industry-standard `cryptography` library.
*   **:link: Streamlined Handshake**: Efficient version exchange and key negotiation logic.
*   **:shield: Modern Cryptography**: Optimized support for Ed25519, Curve25519, and AES-256-CTR with HMAC-SHA2.

## Benchmarking and Profiling

### Built-in Benchmark Tool

SpindleX includes a `spindlex-benchmark` CLI tool to help you evaluate performance in your specific environment.

### Performance Metrics

When benchmarking SpindleX, focus on these metrics:

1.  **Handshake & Connect Time**: Time from socket creation to authentication success.
2.  **SFTP Transfer Rate**: Throughput for file transfers over encrypted channels.
3.  **Command Execution Latency**: Round-trip time for command execution and output retrieval.

## Data Transfer Optimization

### Read Buffering

SpindleX uses an internal buffering strategy for I/O operations. By reading data in larger chunks (default 32KB), it reduces the number of `socket.recv()` calls, which is often a bottleneck in high-throughput network applications.

### TCP_NODELAY

By default, SpindleX enables `TCP_NODELAY` on the underlying transport socket. This ensures that packets are sent immediately without waiting for the buffer to fill up, which is critical for interactive shells and low-latency command execution.

## Best Practices Summary

1.  **Use Connection Pooling**: Reuse SSH connections for multiple operations to avoid the overhead of repeated handshakes.
2.  **Choose Modern Algorithms**: Prefer Ed25519 and AES-256-CTR for the best balance of security and speed.
3.  **Stream Large Files**: Use the SFTP streaming methods to minimize memory usage for large file transfers.
4.  **Monitor Network Latency**: Use the built-in monitoring tools to track performance across different network environments.
