Performance Guide
=================

This guide covers performance optimization techniques, benchmarking, and the internal architecture that makes SpindleX one of the fastest pure-Python SSH libraries.

Performance Overview
--------------------

SpindleX is engineered for speed, security, and protocol efficiency. Key performance features include:

- **Adaptive Buffering**: Intelligent 32KB read buffering architecture that minimizes syscall overhead by chunking protocol data.
- **TCP Fast-Path**: Automatic management of `TCP_NODELAY` to bypass Nagle's algorithm, reducing latency for small packets.
- **Zero Dependencies**: Pure-Python core with zero dependencies (except `cryptography`), ensuring minimal overhead and broad compatibility.
- **Optimized KEX**: Streamlined Version Exchange and Key (Re-)Exchange logic.
- **Modern Cryptography**: Native support for Ed25519, Curve25519, and ChaCha20-Poly1305.

Benchmarking and Profiling
--------------------------

Built-in Performance Monitoring
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

SpindleX includes built-in performance monitoring tools to help you identify bottlenecks in your application.

Custom Benchmarking
~~~~~~~~~~~~~~~~~~~

When benchmarking SpindleX, focus on these metrics:

1. **Handshake & Connect Time**: Time from socket creation to authentication success.
2. **SFTP Transfer Rate**: Throughput for file transfers over encrypted channels.
3. **Command Execution Latency**: Round-trip time for command execution and output retrieval.

Data Transfer Optimization
--------------------------

Adaptive Buffering
~~~~~~~~~~~~~~~~~~

SpindleX uses an adaptive buffering strategy for I/O operations. This reduces the number of `socket.recv()` calls, which is often a bottleneck in high-throughput network applications.

TCP Fast-Path
~~~~~~~~~~~~~

By default, SpindleX enables `TCP_NODELAY` on the underlying transport socket. This ensures that packets are sent immediately without waiting for the buffer to fill up, which is critical for interactive shells and low-latency command execution.

Best Practices Summary
---------------------

1. **Use Connection Pooling**: Reuse SSH connections for multiple operations to avoid the overhead of repeated handshakes.
2. **Choose Modern Algorithms**: Prefer Ed25519 and ChaCha20-Poly1305 for the best balance of security and speed.
3. **Stream Large Files**: Use the SFTP streaming methods to minimize memory usage for large file transfers.
4. **Monitor Network Latency**: Use the built-in monitoring tools to track performance across different network environments.
