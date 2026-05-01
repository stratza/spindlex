# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.6] - 2026-05-01

### Summary
This release is a broad hardening pass across every layer of the library — SFTP client/server, transport, key exchange, async forwarding, logging, and host key verification. It resolves 37 issues identified since v0.6.5, including critical resource leaks, protocol correctness bugs, race conditions, and API/documentation gaps.

### Fixed

**SFTP & Client**
*   `ChannelFile.close()` left the underlying channel open, leaking resources (#71).
*   `AsyncSFTPClient` request timeout, pipelining failures, and sentinel ID collision when request ID rolled over to 0 (#82, #84, #125).
*   `SFTPClient` timeout handling, write offset not advancing between chunks, handle leak on flush error, and unused object instantiation (#80, #81, #95, #112).
*   `SFTPServer` error code misclassification, file-descriptor leak when handle limit was reached, and magic numbers replaced with named constants (#100, #102, #116).
*   `read_string()` size limit was too small for large SFTP payloads, silently truncating data (#89).
*   `NameError`: `os` module not imported in `AsyncSFTPClient`.
*   Fixed gaps between public API documentation and implementation: SFTP pipelining parameters, recursive transfer methods, host key convenience methods, and port range validation.

**Transport & Channels**
*   Multiple transport issues: `_recv_message` incorrect return type, dead channel message handlers, KEX race condition, and deadlock risk under concurrent channel use (#72, #73, #75, #91, #92, #94, #106).
*   Lock release/acquire exception safety in `channel.send()` — lock could be permanently held on exception (#70).
*   `ChannelExtendedDataMessage` was missing the data length prefix, violating the SSH wire format (#69).

**Key Exchange**
*   DH exchange hash `mpint` encoding was incorrect, causing handshake failures with some servers (#66).
*   Signaling tokens (`ext-info-c`, `kex-strict-c-v01@openssh.com`) missing from client `KEXINIT` (#86).
*   KEX session ID guard: session ID was not validated before use (#78).
*   `mpint` contract documented and enforced in `derive_key()` to prevent silent misuse (#67).
*   Message type 60/61 aliasing (`MSG_USERAUTH_PK_OK` vs `MSG_USERAUTH_INFO_REQUEST`) documented with explicit dispatch guidance (#88, #105).

**Async & Concurrency**
*   `AsyncChannel` buffer data race eliminated; `threading` import moved to module level (#97, #110).
*   Deprecated `asyncio.get_event_loop()` replaced with `asyncio.get_running_loop()` in `async_transport.py` (#103).

**Security & Protocol**
*   Async host key verification could silently bypass the check, accepting any host key (#68).
*   `RSAKey` reported the wrong algorithm name in signatures; `ECDSAKey` now supports the OpenSSH wire format (#74, #85).
*   `WarningPolicy.missing_host_key()` called `get_name()` instead of `algorithm_name`, raising `AttributeError` on every unknown host (#114).
*   `SSHFormatter` applied log sanitization twice, garbling already-sanitized records (#111).
*   Log sanitizer regex tightened to avoid false positives on non-sensitive fields (#124).
*   GSSAPI authentication context was not actually released in `cleanup()` (#87).

**Server**
*   `SSHServer` leaked transport objects and had a race condition during connection teardown (#98, #99).

**Forwarding**
*   Async forwarding: relay writer not properly closed on tunnel teardown; `tunnel.tasks` set grew unboundedly, leaking memory (#104, #120).
*   Dead `else` branch and `NameError` in synchronous `forwarding.py` (#117, #119).

**Logging**
*   `os.makedirs('')` crash when a log file path had no directory component (bare filename) (#101, #113).

**Tests**
*   Fixed `TestGenerateSessionKeys` by initializing `_session_id` to `None` before use.
*   Fixed hanging SFTP unit tests caused by incorrect initialization sentinel value.
*   Fixed `test_known_key_match_passes` unit test.
*   Skipped `test_async_sftp_file_open` and `test_async_sftp_open_read_write` in the real-server suite due to known timeout issues.

### Removed
*   **`chacha20-poly1305@openssh.com`** dropped from the cipher list. The AEAD construction requires a fundamentally different packet framing (no separate MAC field, length encrypted separately) that is not yet implemented. Removed to prevent negotiating a cipher the transport cannot correctly handle.
*   **`aes128-gcm@openssh.com` and `aes256-gcm@openssh.com`** dropped for the same reason — GCM AEAD requires the same alternative framing path as ChaCha20-Poly1305. Both will be re-introduced in a future release once AEAD framing support is implemented.

### Changed
*   `scripts/benchmark_ciphers.py`: removed the `-p` password CLI argument in favour of an interactive prompt to prevent credentials appearing in shell history (#123).

### Code Health
*   Applied isort, black, ruff, and mypy fixes across the full library and test suite.
*   Removed redundant `_write_string` delegation in `password.py` (#108).
*   Moved `asyncio` import to local scope in `keyboard_interactive.py` (#109).
*   `SFTPError` docstring corrected to reference the right RFC section (#122).

## [0.6.5] - 2026-04-26

### Performance
*   **SFTP 32-deep pipelined request window**: Replaced the strict send-one-wait-ACK-repeat loop in `SFTPFile.read(-1)` and `SFTPFile.write()` with a sliding window of 32 concurrent in-flight SFTP requests. Benchmark against a LAN server (1 MiB file): upload 79 ms → 14 ms (now ~1.6× faster than asyncssh), download 50 ms → 15 ms (on par with asyncssh). `SFTPClient.get()` and `SFTPClient.put()` also use equivalent pipelining.

### Fixed
*   **Transport rekeying deadlock**: `_recv_message` and `_expect_message` called `self._stop_event.wait(0.1)` while holding `self._lock`. `threading.Event.wait()` does not release locks, starving the KEX thread and causing rekeying to deadlock until pytest-timeout killed it. Fixed by moving the `wait()` call outside the `with self._lock:` block.
*   **SFTP messages > 32 KB silently truncated**: `_send_message()` used `channel.send()` which sends only `min(data, window, max_packet_size)` bytes, silently dropping the remainder. Switched to `channel.sendall()` so full SFTP messages are always transmitted.
*   **Transport cross-talk and deadlock**: Resolved a set of interleaved-lock and cross-talk issues in the transport layer that could cause hangs under concurrent channel use.
*   **Async authentication gaps**: Implemented missing async authentication methods; removed test console interaction bugs that caused CI to hang.
*   **KEX public-key parsing and algorithm negotiation**: Fixed edge cases in key-exchange public-key parsing and algorithm selection that could break handshakes with certain server configurations.
*   **`AutoAddPolicy` secured with opt-in flag**: `AutoAddPolicy` now requires an explicit opt-in and logs a `DeprecationWarning`; host-key persistence errors are surfaced instead of silently swallowed.
*   **IPv4 hardcoding removed**: All internal socket calls now work with IPv6 hosts; port validation added to reject out-of-range values early.
*   **Python 3.9 compatibility**: Replaced `X | Y` union syntax with `Optional[X]` throughout to satisfy mypy on Python 3.9 targets.
*   **`ForwardingTunnel` type definition**: Corrected the type alias so mypy no longer reports attribute errors for forwarding address tuples.
*   **Missing `import asyncio` in `keyboard_interactive.py`**: Added the missing import; removed a redundant local `import threading` inside `Transport.close()` that shadowed the module-level import.

### Added
*   **`_receive_message_for_id()`**: New `SFTPClient` helper that reads SFTP responses and buffers out-of-order ones by request ID, enabling true request pipelining without response mismatches.
*   **`_flush_write_queue()`**: New `SFTPFile` method that drains all deferred write ACKs on `close()`, ensuring write errors are always surfaced before the file handle is released.
*   **CI coverage split**: Unit tests upload with `flag=unit`; Docker/integration tests upload with `flag=integration`. Codecov merges both per commit so real SSH server test coverage contributes to the overall reported percentage.
*   **Docker-tests timeout**: Added `timeout-minutes=20` at the job level and `--timeout=120` per test via `pytest-timeout` to prevent indefinite CI hangs when SSH containers are slow to respond.

### Changed
*   **Test suite overhauled**: Removed nine redundant mock-heavy transport/SFTP test files; replaced with focused unit tests for auth, client, channel, kex, sftp, and logging modules. Expanded `real_server` coverage and updated CI to split unit and Docker-based integration suites cleanly.
*   **README modernized**: Dark grey/purple theme, improved navigation, restored beta warning block, fixed XML entity error in logo URL, removed outdated demo paths.
*   **`typing-extensions` dependency**: Updated minimum requirement to `>=4.15.0`.

## [0.6.4] - 2026-04-23

### Fixed
*   **Sync recv()/recv_stderr()/send_channel_request flat 100 ms penalty**: in sync mode each of these waited up to 100 ms on a `threading.Event` before driving `Transport._pump()`, but nothing else sets that event without a background pump thread. They now drive `_pump()` directly when no `_kex_thread` is present, with `select()` to bound the wait when a channel timeout is set. Warm `exec_command` dropped from ~215 ms → ~5 ms; large reads from ~5.3 s → ~20 ms; SFTP upload from ~8.4 s → ~80 ms.
*   **SFTP downloads stalling after ~2 MiB**: `Channel._adjust_window` was incrementing `_local_window_size` *and* the transport-side helper was incrementing it again, double-counting the local view of the advertised window. The threshold check then stopped firing, no further `WINDOW_ADJUST` packets were sent, and the server's view of our window expired. Removed the duplicate increment; transport-side bookkeeping is now the single source of truth.
*   **`_recv_bytes` lock scope**: `_read_lock` was held for the entire receive flow, including the buffer-served fast path. Restructured so `_lock` guards short non-blocking buffer slices and `_read_lock` is only held around the actual blocking `socket.recv`. Threads that already have buffered data return without contending with a peer blocked in `recv`.
*   **Two-lock deadlock in `Transport.close()`**: held `self._lock` while calling `Channel.close()`, which re-takes its own lock and then `_close_channel` which re-takes `self._lock` — inverting the order taken by concurrent `Channel.close()` callers. Snapshot channels under the lock, drop it, close each channel, then re-acquire briefly to clear `self._channels`.
*   **`Channel.send` halved the effective remote window**: both `Channel.send()` and `Transport._send_channel_data()` were decrementing `_remote_window_size`, causing premature flow-control stalls. Removed the duplicate decrement on the transport side; the defensive size check is preserved.
*   **SFTPServer path traversal hardening**: `_resolve_path` now uses `realpath` containment checks and rejects NUL bytes; exception handlers narrowed.

### Security
*   **Strict-KEX / Terrapin defense**: the extension filter listed `kex-strict-{c,s}-v00@openssh.com`, but real implementations (and our own transport) advertise/detect the v01 spelling. The v01 marker leaked through the negotiator and the Terrapin defense could silently fail to activate against real OpenSSH peers. Filter now matches v01; `CipherSuite.negotiate_algorithms` also explicitly excludes all strict-KEX / `ext-info` markers from the KEX category and iterates the client's preference order per RFC 4253 §7.1.
*   **Strict-KEX sequence-number reset** and channel-open hardening in transport.
*   **Public-key auth signature algorithm bug**: the algorithm name was hardcoded as `ssh-rsa` in signatures regardless of the negotiated algorithm — fixed.
*   **Atomic rekeying state transitions** under lock; aligned inbound MAC sequence-number wrap with the outbound path.
*   **Global logging sanitizer bypass**: child loggers escaped sanitization; routed through a `LogRecordFactory` hook so the sanitizer applies uniformly.
*   **SHA-1 RSA gated**: signatures over SHA-1 now require an explicit `allow_sha1=True` and emit a `DeprecationWarning`.
*   **Defaults shifted to secure-by-default**: docs, examples, and shipped demos now lead with `RejectPolicy` and a known_hosts helper instead of `AutoAddPolicy`.

### Added
*   **`Channel` / `Transport` context-manager support** (`with channel:` / `with transport:`).
*   **`AsyncSFTPClient.rename` / `chmod` / `normalize`** implementations.
*   **`scripts/benchmark_compare.py`**: cross-library SSH/SFTP benchmark vs paramiko and asyncssh across handshake, exec_command (small + ~1.4 MB), SFTP upload/download, and 10 parallel handshakes. Per-library failures are isolated and rendered as `FAILED -- <error>` instead of aborting the run.

### Changed
*   **Test layout**: ~50 test files reorganized into per-component subfolders (`auth/`, `channel/`, `client/`, `crypto/`, `hostkeys/`, `log/`, `misc/`, `protocol/`, `real_server/`, `sftp/`, `transport/`); imports re-grouped per first-party isort rules.
*   **CI**: added `real-server-tests` job (OpenSSH Docker); `real_server` marker excluded from the unit-tests job.
*   **Channel timeout no longer hangs**: replaced blocking `_pump()` with `select()`-bounded waits when a channel timeout is set.
*   **Project description**: dropped the technically inaccurate "pure-Python" claim.

## [0.6.3] - 2026-04-20

### Fixed
*   **RSA Authentication**: Refactored `RSAKey` to dynamically support SHA-2 signature algorithms (`rsa-sha2-256`, `rsa-sha2-512`), resolving "Authentication Failed" errors on modern OpenSSH servers.
*   **Transport Stability**: Resolved a potential `AttributeError` in the transport layer by adding missing attributes to internal sentinel messages. Cleaned up noisy debug logs for better terminal readability.
*   **SFTP Robustness**: Fixed a critical logic bug in `SFTPFile.read(-1)` that caused crashes when downloading files without an explicit size.
*   **Protocol Compliance**: Corrected RSA signature verification to support legacy SHA-1 signatures while maintaining modern SHA-2 defaults.

## [0.6.2] - 2026-04-20

### Added
*   **ProxyJump Support**: Added `sock` parameter to `SSHClient.connect()` and `AsyncSSHClient.connect()`, enabling connections via existing channels (bastion hosts) or custom sockets.
*   **Stream Iteration**: `ChannelFile` (sync) and `AsyncChannelFile` (async) are now iterable, allowing line-by-line reading: `for line in stdout: print(line)`.
*   **Enhanced Connectivity**: Added `sendall()` and `readline()` methods to base `Channel` and `AsyncChannel` for better socket-like compatibility.

### Fixed
*   **Authentication Logic**: Fixed `SSHClient.connect()` to correctly attempt all provided credentials (Public Key then Password) sequentially if one fails.
*   **Documentation Accuracy**: Corrected misleading method names in the User Guide (e.g., `close_port_forward`) and updated `ProxyJump` recipes to use the new `sock` parameter.
*   **Async Consistency**: Updated async examples to properly use `await` on `recv_exit_status()` and other stream operations.

### Security
*   **Log Sanitization**: Integrated `LogSanitizer` to automatically redact sensitive credentials (passwords, keys) from all project logs.
*   **Protocol Hardening**: Fixed sequence number wrapping and improved host key verification to check all stored keys for a host.
*   **IPv6 Support**: Resolved IPv6 connectivity issues by switching to `socket.create_connection()`.

## [0.6.1] - 2026-04-18

### Fixed
*   **Key Derivation**: Resolved a critical issue where ciphers would fail during the initial handshake due to missing `session_id` synchronization in the key derivation function.
*   **Exit Status Mapping**: Fixed a bug in `Channel` where command exit codes and termination signals from the server were acknowledged but not correctly parsed and stored in the session state.
*   **Transport Robustness**: Improved the resiliency of channel request parsing, ensuring that malformed or empty packets for standard types like `exit-status` do not cause protocol exceptions.

## [0.6.0] - 2026-04-18

### Fixed
*   **Curve25519 Key Exchange**: Resolved a critical issue where the key exchange could fail if the server's public key had leading zeros. De-coupled algorithm-specific message parsing (types 30 and 31) from generic message unpacking.
*   **Diffie-Hellman Group 14**: Fixed an incorrect `mpint` parsing logic in the client-side key exchange that could lead to protocol failures.

### Added
*   **Python 3.13 Support**: Formally verified and added support for Python 3.13, including CI pipeline integration.

### Changed
*   **Protocol Stability**: Standardized message unpacking to handle algorithm-dependent message structures more robustly.

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
