# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.2] - 2026-04-16

### Added
*   **Unified Client API**: Standardized the interface between `SSHClient` and `AsyncSSHClient` for better consistency and easier migration between sync and async code.
*   **Improved SSH Key Management**: Enhanced Ed25519 and RSA key generation/loading with broader compatibility for OpenSSH-formatted keys.
*   **Enhanced Demos**: Added a suite of comprehensive, high-fidelity demo scripts (`complex_setup_demo.py`, etc.) to showcase real-world performance.
*   **Verified Demo Results**: Integrated a new [demo_results.md](demo_results.md) tracking actual execution metrics.

### Changed
*   **Performance**: Optimized internal buffering in `AsyncTransport` for high-throughput scenarios. Connection establishment is ~2.6x faster than legacy libraries.

### Fixed
*   **Protocol Stability**: Resolved several race conditions in `AsyncTransport` during high-concurrency SFTP transfers.
*   **Security Hardening**: Tightened standard compliance for cryptographic primitives and handshake sequences.
*   **Context Manager Cleanup**: Fixed resource leaks in `async with` blocks where sessions were not properly closed on exception.

## [0.5.0] - 2026-04-11

### Added
*   **Rekeying Support**: Implemented RFC 4253 compliant rekeying triggered by data volume (1GB), time (1 hour), or sequence number limits (2^31 packets).
*   **Peer-Initiated Rekeying**: Added support for handling server-initiated key exchanges seamlessly.
*   **Keyboard-Interactive Authentication**: Fully implemented client-side support for interactive authentication prompts (RFC 4256), enabling MFA and complex PAM configurations.
*   **Request Delegation**: Implemented structured channel and global request delegation to the `SSHServer` interface, replacing the previous "accept all" policy.

### Fixed
*   **Message Dispatching**: Resolved critical protocol message ambiguity where multiple messages shared type code 60 (e.g., `MSG_USERAUTH_PK_OK` vs `MSG_USERAUTH_INFO_REQUEST`).
*   **Port Forwarding Stability**: Improved error handling and logging in data relays to distinguish between expected closures and unexpected errors.
*   **Transport Threading**: Fixed potential race conditions during simultaneous rekeying attempts.

## [0.4.2] - 2026-04-10

### Changed
*   **Security**: Purged legacy SHA-1 based MACs and weak ciphers from default negotiation list.
*   **Performance**: Improved `AsyncSFTPClient` concurrency by optimizing message pumping in the underlying transport.

### Fixed
*   **Documentation**: Clarified dependencies and qualified performance claims in README.
*   **CI/CD**: Fixed invalid `.codecov.yml` structure and improved coverage path mapping.

## [0.4.1] - 2026-04-10

### Fixed
*   Fixed critical "Receive timeout" in `AsyncSSHClient` and `AsyncSFTPClient` by implementing transport pumping in `AsyncChannel`.
*   Corrected attribute naming in `AsyncChannel` (e.g., `_eof_received`, `_closed`).
*   Fixed `AsyncChannel.send` to correctly return total bytes sent and handle window adjustments robustly.
*   Fixed `AsyncTransport` to properly initialize channel window and packet sizes from server confirmation.
*   Corrected message argument naming in `AsyncTransport` (e.g., `bytes_to_add` in window adjust).
*   Fixed message loss bug in `AsyncTransport` by ensuring all pumped messages are queued.
*   Fixed `AsyncSFTPClient._recv_message` to robustly read length-prefixed messages using new `recv_exactly` method.

### Added
*   Added `recv_exactly` method to `AsyncChannel` for reliable protocol-level data retrieval.
*   Added `remove` method to `AsyncSFTPClient`.
*   Added asynchronous context manager support (`async with`) to `AsyncSFTPClient` and `AsyncSFTPFile`.
*   Added `makefile_stderr` support to `AsyncChannel`.

## [0.4.0] - 2026-04-07

### Fixed
*   **Transport Layer**: Resolved a critical hang in SSH command execution caused by an infinite loop in `Transport._expect_message` where unhandled messages were repeatedly re-queued and re-read.
*   **Message Dispatching**: Improved `Transport._handle_channel_message` to correctly extract recipient channel IDs for all message types, ensuring proper dispatch to channel instances.
*   **Concurrency**: Added `_read_lock` to `Transport` to prevent concurrent socket access and potential data corruption during simultaneous read operations.
*   **SSH Client**: Ensured `SSHClient` permanently sets the connection timeout on the underlying transport after a successful handshake.
*   **Channel Stability**: Updated `Channel.exec_command` to automatically send EOF after the command, improving compatibility with various SSH server implementations.

### Added
*   **SFTP Client**: Implemented context manager support (`__enter__`/`__exit__`) for `SFTPClient` for easier resource management.
*   **SFTP Operations**: Implemented `SFTPClient.open()` and the `SFTPFile` class to support synchronous file-like operations (read/write).
*   **Channel Timeouts**: Enhanced `Channel.recv` to respect per-channel timeouts, preventing indefinite blocking.

## [0.3.0] - 2026-04-04

### Fixed
*   **Protocol Utilities**: Fixed `write_mpint` to use the minimum number of bytes for negative integers (e.g., -128 now correctly serializes to `0x80` instead of `0xff80`).
*   **Version Parsing**: Improved error handling in `parse_version_string` to provide clearer messages for invalid SSH version strings.
*   **SSH Connection Stability**: Resolved numerous issues preventing reliable SSH connections, including corrected KEX initialization, `bytearray` vs `bytes` type issues, and more.
*   **Authentication**: Fixed `PasswordAuth.authenticate` to use the correct service name (`ssh-connection`).
*   **Channel**: Fixed `ChannelFile.read()` to correctly read until EOF.

### Added
*   **Unit Tests**: Created a comprehensive test suite in `tests/` covering protocol utilities and constants.
*   **Configuration Consolidation**: Unified project configuration into `pyproject.toml`.

## [0.2.0] - 2026-03-31

### Added
*   Basic logging structure and sanitization for test files.

## [0.1.0] - 2026-03-20

### Added
*   Initial project setup and basic SSH client/server structure.
*   Core protocol messages and transport layer implementation.
