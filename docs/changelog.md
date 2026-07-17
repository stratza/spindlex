# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
*   **`cryptography` minimum raised to 48.0.1** - versions below 48.0.1 ship wheels bundling a vulnerable OpenSSL ([GHSA-537c-gmf6-5ccf](https://github.com/advisories/GHSA-537c-gmf6-5ccf), high severity). SpindleX previously allowed `>=46.0.7`, so environments pinned inside the vulnerable range could resolve an affected build. This closes the open OpenSSF Scorecard vulnerability alert.

### Changed
*   **`requires-python` tightened to `>=3.9.2`** - `cryptography` excludes the 3.9.0 and 3.9.1 point releases, so declaring support for them made the dependency range unsatisfiable under universal resolvers such as uv. Python 3.9 remains supported from 3.9.2 onward; 3.9.0/3.9.1 (from 2020, with known CVEs) were never usable with SpindleX's dependency set in practice.

## [1.0.0] - 2026-07-17

This is the first stable release of SpindleX. It marks the graduation from beta to a production-ready library with a frozen public API surface, full security documentation, a migration guide from the 0.x line, and validated performance benchmarks. It also closes all findings from a full-project pre-release review, including data-integrity fixes in the SFTP transfer paths and port forwarding.

### Added
*   **Migration guide** (`docs/migration/0.x-to-1.0.md`) - covers all breaking changes, removed APIs, changed defaults, host key behavior changes, and sync/async differences between the 0.x beta line and 1.0.0. A beta user can upgrade without diffing source code.
*   **Comparison page** (`docs/comparison.md`) - honest feature matrix and loopback benchmark comparison against Paramiko and AsyncSSH, including unsupported features and known limitations.
*   **Canary runbook** (`meta/internal/lifecycle/canary-runbook.md`) - canary environment spec, test coverage checklist, failure classification, fallback policy, and explicit v1.0.0 fallback approval.

### Fixed
*   **Docs examples missing host key loading** - every `SSHClient` and `AsyncSSHClient` example in the user guide, cookbook, and quickstart now calls `client.get_host_keys().load()` before `connect()`. Previously, examples that used the default `RejectPolicy` would fail for any user whose server was not already trusted, and examples that omitted host key loading implicitly recommended connecting without verification. Affected files: `docs/quickstart.md`, `docs/user_guide/client.md`, `docs/user_guide/sftp.md`, `docs/cookbook/automation.md`, `docs/cookbook/sftp_recipes.md`.
*   **Broken code block in `docs/user_guide/server.md`** - the `SSHServerManager` setup example had a premature closing fence that left `interface = MySSHServer()` and the remainder of the setup outside the code block, rendering as raw Python mixed into prose. Fixed into a single continuous code block. Removed unused `import socket`.
*   **Closing a local port forwarding tunnel could leak the listening port** - `LocalPortForwarder.close_tunnel()` closed the server socket without waking the accept thread. On Linux, `close()` does not interrupt a thread blocked in `accept()`, so the blocked call kept a reference to the socket and the local port stayed bound until the process exited. The socket is now `shutdown()` before `close()`, which reliably releases the port. This was the root cause of the recurring `docker-protocol` integration flake (`[Errno 98] Address already in use` in `test_local_port_forwarding_comprehensive`).
*   **PR quality gate rejected Dependabot PRs** - `validate_pr_body.py` required the human PR template's Type of Change token, which Dependabot never provides, so every dependency-bump PR failed metadata validation before any real checks ran (and a merged Dependabot PR would have broken release planning on `main`). PRs from trusted bot authors with no explicit token are now classified as `dependencies` with no release.
*   **SFTP downloads could silently corrupt files on short reads** - the pipelined read loops in `SFTPClient.get()`, `SFTPFile.read(-1)`, `AsyncSFTPClient.get()`, and `AsyncSFTPFile.read(-1)` assumed every `SSH_FXP_READ` response returned exactly the requested length. The SFTP spec allows servers to return fewer bytes before EOF; a short response left a silent gap and misplaced every subsequent chunk. Short reads now drain the stale pipeline and restart at the true end of the received data. The client also honours the server's `max-read-length` from `limits@openssh.com` (previously read and discarded).
*   **`SFTPServer` could truncate large responses** - `_send_message()` used `Channel.send()`, which sends at most one chunk bounded by the peer's window and max packet size, silently dropping the remainder and desynchronising the SFTP stream. Now uses `sendall()`.
*   **Port forwarding relays could drop data** - `LocalPortForwarder._relay_data()` and `RemotePortForwarder._relay_data()` called `Channel.send()` and ignored the partial-send return value. Both now use `sendall()` (the async relays were already correct).
*   **`ChannelFile.write()` could silently truncate stdin data** - it returned `Channel.send()`'s partial byte count, which file-like callers never check. It now sends the full buffer via `sendall()`.
*   **`HostKeyStorage.remove()` was case-sensitive** - `add()`/`get()`/`get_all()` normalise hostnames to lowercase (since 0.7.3) but `remove()` did not, so removing a host key with different capitalisation silently failed.
*   **Timeouts used the wall clock** - channel send/recv/exit-status timeouts and the transport rekey timer used `time.time()`, so NTP clock steps could cause spurious timeouts or indefinitely deferred rekeys. Switched to `time.monotonic()`.
*   **Remote-forward routing matched by port only** - two remote forwards on the same port with different bind addresses could mis-route incoming connections; an exact (address, port) match is now preferred with port-only as fallback.
*   **Local forward bind used only the first resolved address** - `getaddrinfo()` may order an IPv6 entry first (e.g. for `localhost`) while clients connect over IPv4; each resolved address is now tried until one binds.
*   **Channel remote window could exceed the RFC 4254 limit** - `WINDOW_ADJUST` handling now caps the window at 2^32 − 1.
*   **Failed channel requests were silently swallowed** - `Channel._handle_channel_request()` caught all exceptions and returned `False` with no trace; failures are now logged.

### Security
*   **SFTP server caps client-supplied message length** - `_receive_message()` read a 32-bit length field and allocated it unconditionally, letting a hostile client demand up to 4 GiB; messages are now capped at 256 KiB (matching OpenSSH's sftp-server).
*   **Signature verification no longer swallows unexpected errors** - `Ed25519Key.verify()`, `ECDSAKey.verify()`, and `RSAKey.verify()` caught all exceptions and returned `False`; they now only treat `InvalidSignature` and malformed signature blobs as verification failure, letting programming errors propagate (consistent with the `PKey.__eq__` fix in 0.7.3).

### Changed
*   **Version bumped to 1.0.0** - `pyproject.toml` and `spindlex/_version.py` updated from `0.7.3`.
*   **PyPI project URLs** - added `Security` (`https://github.com/stratza/spindlex/security/policy`) and `Source` (`https://github.com/stratza/spindlex`) to `[project.urls]` in `pyproject.toml` so both links appear on the PyPI project page.
*   **`check-yaml` pre-commit hook** - added `--unsafe` flag so commits that touch `mkdocs.yml` are not blocked by the hook's inability to parse MkDocs Python YAML tags.
*   Updated GitHub Actions pins for Node 24-compatible action releases while keeping full commit-SHA hardening: `actions/checkout` 6.0.3, `actions/setup-python` 6.2.0, `actions/upload-artifact` 7.0.1, `actions/create-github-app-token` 3.2.0, and `github/codeql-action` 4.36.1.
*   Pinned compatibility smoke runners to `windows-2025-vs2026` and `macos-26`, and added `.python-version` so GitHub's Automatic Dependency Submission uses Python 3.11 instead of the ambient runner `PATH`.

### Documentation
*   `docs/migration/` section added to MkDocs navigation.
*   `docs/comparison.md` added to MkDocs navigation.

### Verification
*   Unit test suite: **1781 passed, 1 skipped, 0 failed**.
*   Static analysis: ruff - 0 violations; mypy strict - 0 errors.
*   Production readiness benchmark: **53/53 PASS** (carried from 0.7.3).
*   `python -m build && twine check dist/*` - passes (run as part of RC final validation).

## [0.7.3] - 2026-06-08

This release closes all remaining v1.0.0 blockers identified in the pre-release code review. It fixes six confirmed bugs in the async surface, hardens two security-sensitive code paths, completes the async/sync API parity gap, makes ProxyJump connections functional end-to-end, and corrects a broken documentation example that has been present since 0.5.0.

### Fixed

*   **`AsyncSFTPClient.mkdir()` silently ignored the `mode` argument** - `attrs.st_mode` (a local Python `os.stat` field) was assigned instead of `attrs.permissions` (the SFTP wire field). Remote directories were created with no permissions set regardless of the `mode` argument passed by the caller.
*   **Async host key policy errors swallowed** - when a custom host key policy raised an exception to signal rejection, `AsyncSSHClient._verify_host_key()` logged a warning and continued connecting. It now re-raises as `SSHException`, matching the behavior of the sync `SSHClient` and enforcing fail-closed semantics.
*   **`AsyncSSHClient.connect()` silently accepted `compress=True`** - the parameter was present in the signature but never validated. The sync client already raises `ConfigurationException`; the async path now does the same.
*   **RSA host key TOFU matching broken across algorithm name variants** - `ssh-rsa`, `rsa-sha2-256`, and `rsa-sha2-512` refer to the same underlying RSA key pair but were treated as distinct key types during known-host lookup. A key stored as `ssh-rsa` was not recognised when the server later negotiated `rsa-sha2-256`, causing `RejectPolicy` connections to fail for known hosts after a server upgrade.
*   **`Transport._remote_version` not initialised in `__init__`** - the attribute was only assigned inside `_recv_version()`, so any code path that accessed it before the handshake completed (e.g. exception handlers, logging) raised `AttributeError` instead of a clean `TransportException`.
*   **`PKey.__eq__` caught all exceptions and returned `False`** - a broad `except Exception: return False` masked programming errors such as key corruption that should propagate. Now only `CryptoException` (covering the expected "no key loaded" uninitialized state) is suppressed; all other exceptions propagate to the caller.
*   **Host key storage used case-sensitive hostname lookup** - DNS hostnames are case-insensitive, but `HostKeyStorage` stored and matched them exactly as received. `Server.example.com` and `server.example.com` resolved to different storage slots. All hostnames are now normalised to lowercase on `add()`, `get()`, and `get_all()`.
*   **SFTP limits negotiation caught too broadly** - `SFTPClient._query_limits()` used `except Exception: pass` to suppress failures from servers that do not support `limits@openssh.com`. This also silenced unexpected programming errors. Narrowed to `(SFTPError, SSHException, struct.error, OSError)`.
*   **`AsyncSSHClient.connect(sock=Channel)` silently misconfigured transport** - passing a `Channel` object as the `sock` argument set `reader, writer = None, None` and skipped the `connect_existing()` call, leaving the transport in a broken state with no error. Now raises `SSHException` immediately with a message directing users to the sync `SSHClient` for ProxyJump connections.
*   **Keyboard-interactive auth doc example was broken** - `automation.md` showed `client.connect(..., handler=interactive_handler)` but `handler` has never been a parameter of `connect()`. The example would raise `TypeError` at runtime.

### Security

*   **Host key comparison is now constant-time** - `SSHClient._verify_host_key()` and `AsyncSSHClient._verify_host_key()` switched from Python's `==` operator to `hmac.compare_digest()` for host key byte comparison, consistent with how MAC verification is already handled throughout the transport layer.

### Added

*   **`keyboard_interactive_handler` parameter on `connect()`** - both `SSHClient.connect()` and `AsyncSSHClient.connect()` now accept a `keyboard_interactive_handler` callable. When provided, keyboard-interactive authentication is attempted automatically after publickey/password if those methods fail or are absent. The handler receives `(title, instructions, prompts)` where `prompts` is a list of `(text, echo)` tuples and must return a list of answer strings.
*   **`AsyncSFTPClient.getcwd()`** - mirrors the existing `SFTPClient.getcwd()` for async/sync API parity.
*   **`SFTPClient.truncate(path, size)` and `AsyncSFTPClient.truncate(path, size)`** - resize or empty a remote file using `SSH_FXP_SETSTAT` with `SSH_FILEXFER_ATTR_SIZE`.
*   **`Channel.fileno()`, `Channel.getsockname()`, `Channel.getpeername()`** - socket-interface methods on `Channel` that enable a `direct-tcpip` channel to be passed as the `sock=` argument to `SSHClient.connect()` for ProxyJump / bastion-host connections. `fileno()` returns `-1` (no OS file descriptor), which causes the transport's `fileno() != -1` guards to skip cleanly.
*   **`PortForwardingManager` and `AsyncPortForwardingManager` exported from `spindlex.__init__`** - port forwarding has been a working feature since 0.6.x but the manager classes were not importable from the public package namespace.

### Removed

*   **`KeyExchange.generate_keys()`** - removed as announced in the v0.7.2 deprecation notice. Access session keys via the `Transport` object after key exchange completes.

### Changed

*   **`AsyncSSHClient.connect()` `pkey` type hint** - corrected from `Any | None` to `PKey | None`, matching the sync `SSHClient` and enabling correct IDE autocomplete and mypy checking for callers.
*   **Pre-commit mypy hook** - updated `mirrors-mypy` rev from `v1.3.0` to `v1.11.0` and replaced the broken `types-all` additional dependency (which pulled in the yanked `types-pkg-resources`) with `cryptography`, which is the only runtime dependency that requires stub resolution.

### Documentation

*   **Keyboard-interactive auth cookbook example** (`docs/cookbook/automation.md`) rewritten to use the new `keyboard_interactive_handler=` parameter on `connect()`. Added an async variant of the example. Both sync and async paths now work as written.
*   **README ProxyJump claim** updated from "Support for ProxyJump (bastion hosts)" (vague) to "ProxyJump (bastion hosts) via `direct-tcpip` channels and TCP port forwarding" (accurate and explains the mechanism).

### Verification

*   Production readiness benchmark: **53/53 PASS** - zero warnings, zero failures across all sections (protocol correctness, session lifecycle, exec reliability, SFTP integrity, concurrency correctness, failure classification, negotiation determinism, performance stability).
*   Cipher comparison benchmark: SpindleX handshakes 53–65 ms vs paramiko 87–90 ms vs asyncssh 60–67 ms; SFTP uploads 14–15 ms vs paramiko 54–58 ms vs asyncssh 19–23 ms; SFTP downloads 15–18 ms vs paramiko 356–368 ms vs asyncssh 15–17 ms.
*   Unit test suite: **1761 passed, 1 skipped, 0 failed**.
*   Static analysis: ruff - 0 violations; mypy strict - 0 errors (46 source files).

## [0.7.2] - 2026-05-30

### Fixed
*   Made the protected publish job idempotent after partial PyPI uploads, added a manual recovery mode for already-published versions, configured Git identity before annotated tag creation, and finalized changelog sections for both new and recovered release-version PR branches before release-note extraction.

### Changed
*   Removed SHA-1 from `CryptographyBackend.HASH_ALGORITHMS` - SHA-1 now raises `CryptoException` if requested, enforcing the no-SHA-1 security invariant at the backend layer.
*   Replaced all `default_backend()` calls (`kex.py`, `backend.py`, `pkey.py`) with the implicit default introduced in `cryptography>=36.0.0`, eliminating deprecation warnings.
*   Moved `_AEAD_CIPHERS` frozenset to module level in `transport.py` - was being re-allocated on every `_build_packet()` call.
*   Version-string silent fallbacks in `_compute_ecdh_exchange_hash`, `_compute_curve25519_exchange_hash`, and `_compute_exchange_hash` replaced with explicit `CryptoException` guards - a missing version string now fails loudly instead of producing a wrong exchange hash.
*   Dead `try: … except Exception: raise` wrapper removed from `_perform_dh_group14_sha256`.
*   `KeyExchange.generate_keys()` deprecated with `DeprecationWarning`; will be removed in v1.0.
*   `WarningPolicy` docstring corrected to accurately describe TOFU behaviour; `AutoAddPolicy` now emits a `logger.warning` alongside the existing `UserWarning`.
*   Hardcoded `"utf-8"` literals in `ssh_client.py` replaced with `SSH_STRING_ENCODING`.
*   Added `[tool.isort]` and `[tool.black]` configs to `pyproject.toml` so both tools align with ruff's formatting style.

### Fixed
*   `MSG_EXT_INFO = 7` added to `protocol/constants.py`; magic literals `7` and `60` in `transport.py` replaced with named constants (`MSG_EXT_INFO`, `MSG_USERAUTH_PK_OK`).
*   Dead KEX fallback in `KeyExchange.start_kex()` replaced with an explicit `CryptoException` - the old path would have sent a spurious second `KEXINIT` in server mode.
*   `assert` statements in crypto and KEX paths replaced with explicit `if … raise CryptoException` guards, which survive Python's `-O` optimisation flag.
*   `_kex_thread` and `_server_key` declared in `Transport.__init__` - previously only set via `getattr` fallbacks, causing undeclared-attribute mypy warnings.
*   Misleading `_recv_bytes` lock-ordering comment updated to accurately describe the fast-path vs slow-path locking behaviour.
*   `SSHClient.save_host_keys()` no longer accesses private `_filename` and `_keys` attributes of `HostKeyStorage`; new `HostKeyStorage.copy_from()` method provides the correct encapsulated API.
*   `SSHClient.connect()` now raises `ConfigurationException` immediately for `compress=True` and `gss_kex=True` rather than silently ignoring them.

### Added
*   Public project policy docs for production usage, compatibility, API stability, release policy, governance, dependency handling, repository settings, CI policy, release operations, release verification, vulnerability response, architecture/security boundaries, logging operations, and public roadmap tracking.
*   Architecture Decision Records for release policy, documentation layout, supported platforms, and API stability boundaries.
*   Root GitHub entry points for contributing and support so GitHub, Read the Docs, and repository visitors all route to the maintained documentation source.

### Changed
*   Restructured GitHub Actions so PR validation runs through one sequential orchestrator and expensive reusable workflows do not launch independently on PRs or `main` pushes.
*   Moved post-merge CodeQL and full security scanning into the sequential release orchestrator for `main` pushes, preserving security coverage while avoiding parallel free-tier runner contention.
*   Documented the protected release-version PR flow, artifact integrity expectations, and maintainer release runbook.
*   Replaced the oversized `meta/CONTRIBUTING.md` copy with a short pointer to the maintained public contributor guide.
*   Rebuilt the Docker integration stack around locally maintained OpenSSH and Dropbear services so real-server workflow tests can run without relying on a removed public Dropbear image.

### Fixed
*   Switched protected release-version PR creation to the release GitHub App token and made the step retry PR creation when the release branch already exists without an open PR.
*   Limited protected release-publish detection to the canonical first commit-message line so `[publish release]` text in a merge body cannot accidentally enter the release-publish path.
*   Restricted protected release-publish mode to merged PRs from the generated `release/vX.Y.Z` branch with source PR metadata, so regular PR titles cannot trigger the publish path.
*   Prevented Docker SSH integration tests and local benchmarks from sharing host-key files across OpenSSH, Dropbear, or the developer's real home directory.
*   Raised the documentation dependency floor to `pymdown-extensions>=10.21.3`, pinned the Alpine test image digest, and documented path-scoped Trivy ignores for intentional SSH test-fixture Dockerfile findings.
*   Folded the open Dependabot GitHub Actions pin updates into the release-scan fix: `actions/checkout` 6.0.2, `astral-sh/setup-uv` 8.1.0, `codecov/codecov-action` 6.0.1, `github/codeql-action` 4.36.0, and `ossf/scorecard-action` 2.4.3.

### Verification
*   Read the Docs continues to build from `.readthedocs.yaml` through `mkdocs.yml`; newly added public docs are explicitly surfaced in the MkDocs navigation rather than being included by the Read the Docs config directly.

## [0.7.1] - 2026-05-29

### Summary
This maintainer-facing readiness entry documents the repository lifecycle work
released in 0.7.1.

## [0.7.0] - 2026-05-16

### Added
*   **ChaCha20-Poly1305 cipher**: Full `chacha20-poly1305@openssh.com` implementation - encrypt, decrypt_length, and decrypt_body - added to `CryptographyBackend`. Registered as the preferred cipher in `CipherSuite` (first in `ENCRYPTION_ALGORITHMS`), with `AEAD_CIPHERS` sentinel set and `key_len: 64` entry in `CIPHER_INFO`.
*   **ChaCha20 sync transport path**: `_encrypt_packet` and `_recv_packet` in `Transport` handle ChaCha20-Poly1305 natively via the two-key AEAD construction (64-byte key split into body key + header key, Poly1305 tag over enc_length + enc_body).
*   **ChaCha20 async transport path**: `_recv_packet_async` in `AsyncTransport` implements the AEAD inbound path - reads enc_length (4 B), decrypts length, reads enc_body + Poly1305 tag (16 B), verifies and decrypts body.
*   **Strict-KEX sequence reset**: After sending `NEWKEYS` with strict-KEX active (`kex-strict-c-v00@openssh.com`), the outbound sequence number is reset to 0 in the async path (Terrapin defense, RFC 9142).
*   **SFTP `limits@openssh.com` negotiation**: `SFTPClient._query_limits()` sends `SSH_FXP_EXTENDED` after version negotiation and parses the 4×uint64 reply to obtain `max_write_len`. On OpenSSH servers this raises the write chunk from 64 KB to 255 KB, reducing round trips for a 1 MiB upload from ~16 to ~4.
*   **`PacketProfiler`**: Optional per-stage packet timing. Set `SPINDLEX_PROFILE=1` to record build / encrypt / socket-write latencies for every sent packet; call `transport._profiler.summary()` for median and P95 per stage.
*   **Algorithms reference page**: New `docs/algorithms.md` covering all supported KEX, host-key, cipher, and MAC algorithms with preference order, notes, and an explicit exclusion list.

### Changed
*   **Preferred cipher**: ChaCha20-Poly1305 is now the first cipher advertised in `CipherSuite.ENCRYPTION_ALGORITHMS`.
*   **KEX signal token**: Corrected from `kex-strict-c-v01@openssh.com` to the standard `kex-strict-c-v00@openssh.com`.
*   **`_packet_buffer`**: Changed from `bytes` to `bytearray` in `Transport`, eliminating O(n) copies on buffer advance.
*   **SFTP write chunk**: `SFTPFile.write()` and `SFTPClient.put()` now use the negotiated `_max_write_len` (default 64 KB, up to 255 KB on OpenSSH) instead of a hardcoded constant.
*   **`validate_packet_structure`**: Minimum packet body relaxed to 8 bytes for AEAD cipher compatibility.
*   **Writer presence check**: In `_send_message_async`, the `_writer` guard is now checked before packet build/encrypt.

### Fixed
*   mypy `Optional[bytes]` narrowing for `_chacha20_key_out` / `_chacha20_key_in` at all call sites.
*   Import order in `sftp_client.py` (transport imports moved above module-level constant).

## [0.6.11] - 2026-05-12

### Performance
*   **Async throughput overhaul**: SpindleX async SFTP now outperforms other leading SSH libraries on handshake, upload, and download benchmarks (LAN: ~42 ms handshake vs ~65 ms; ~14 ms/MiB upload vs ~15 ms/MiB; ~13 ms/MiB download vs ~14 ms/MiB).
*   **Native async packet receive**: Replaced `asyncio.to_thread(super()._read_message)` with `_recv_packet_async()`, which reads directly from the asyncio `StreamReader`. Eliminates two cross-thread context switches per received SSH packet.
*   **Threshold-based write drain**: `_send_message_async()` no longer calls `drain()` after every packet. Drain fires only when the asyncio write buffer exceeds 64 KB, eliminating ~32 event-loop yields per 1 MiB SFTP upload window.
*   **Doubled SFTP pipeline depth**: `_WINDOW` and `_PIPELINE_DEPTH` increased from 32 to 64, keeping up to 2 MiB of SFTP reads/writes in flight (was 1 MiB).
*   **Larger channel window**: `DEFAULT_WINDOW_SIZE` raised from 2 MiB to 4 MiB so the server can push larger bursts before needing a window adjustment.
*   **Socket tuning**: `TCP_NODELAY` enabled on async connections to suppress Nagle coalescing on control packets; `SO_SNDBUF`/`SO_RCVBUF` raised to 1 MiB each.
*   **Optimized SFTP message limits**: Raised `MAX_MESSAGE_SIZE` to 1 MiB and `SFTP_MAX_PACKET_SIZE` to 64 KB, providing a 2x throughput improvement for SFTP data payloads while maintaining standard compatibility.

### Fixed
*   **SFTP large write protocol crash**: Implemented automatic 64 KB chunking in `SFTPClient` and `AsyncSFTPClient` to prevent `ProtocolException: String too long` and connection resets when sending large data buffers.
*   **Async connection reliability**: Added a robust retry mechanism with exponential backoff and jitter to `AsyncSSHClient.connect()`, covering the entire handshake phase to mitigate transient server-side resets (`MaxStartups`).
*   **SFTP pipelining integrity**: Fixed a potential data corruption bug where unhandled short reads during pipelined transfers could lead to offset drift.
*   **Unified exception propagation**: Standardized `AsyncTransport` to preserve specific `SSHException` subclasses (like `CryptoException`) during initialization, ensuring parity with the synchronous transport's error reporting.
*   **Append mode in SFTP**: `SFTPClient._mode_to_flags()` now correctly sets `SSH_FXF_APPEND` for `"a"` open mode (previously the flag was defined but never used).
*   **`key_password` parameter**: `SSHClient.connect()` and `AsyncSSHClient.connect()` now accept a dedicated `key_password` argument for encrypted private keys, separate from the login `password`.
*   **`SSHClient.username` property**: Added a read-only `username` property that returns the authenticated username after `connect()`, or `None` if not connected.
*   **`ChannelFile.read()` exception handling**: Narrowed the exception catch from `Exception` to `ChannelException` so only genuine channel errors (timeout, closed) are handled; other errors propagate correctly.
*   **`put_recursive()` mkdir error handling**: `SFTPClient.put_recursive()` and `AsyncSFTPClient.put_recursive()` now only suppress `SSH_FX_FAILURE` (directory already exists); other SFTP error codes propagate as before.
*   **`_expect_message()` transport closed**: Changed a silent `return None` to `raise TransportException("Transport closed")` so callers are not handed a `None` message when the transport shuts down mid-wait.
*   **Rekey counter reset**: Removed premature `_bytes_since_rekey` and `_last_rekey_time` resets inside `_check_rekey()` that ran before the KEX thread completed, potentially skipping a required rekey cycle.
*   **`HostKeyStorage` load errors**: The constructor now silently ignores `FileNotFoundError` (normal on first use) but logs a warning for any other load error, rather than silently ignoring everything.
*   **`HostKeyStorage` marker**: The `save()` method now writes `spindlex` as the library name in the known-hosts comment instead of the generic `ssh_library`.
*   **`WarningPolicy` TOFU**: `WarningPolicy.missing_host_key()` now stores and persists the host key on first contact (trust-on-first-use), matching the documented behavior.
*   **Keyboard-interactive fallback removed**: `AsyncSSHClient._authenticate()` no longer silently attempts keyboard-interactive as a final fallback when no credentials are provided, preventing unexpected interactive prompts.

### Improved
*   **`configure_sanitizing_logging()` public API**: Added a convenience function to attach `SanitizingFilter` to any logger by name, making it easy to redact credentials from application logs.
*   **Async channel close safety**: `AsyncChannel._handle_close()` now schedules the EOF+CLOSE response as an `asyncio.ensure_future` task rather than calling `_send_message()` synchronously, preventing a potential event-loop deadlock in the native async receive path.
*   **Transport architecture**: Extracted `_dispatch_packet()` from `_read_message()` in the base `Transport` class so the async path can reuse the same packet dispatch logic without the thread bridge.
*   **Bandit/ruff noise reduction**: `AUTH_PASSWORD = "password"` now carries both `# noqa: S105` and `# nosec B105` markers with an explanatory comment; the four incorrect global ruff ignores (`S105`, `S106`, `S303`, `S324`) were removed from `pyproject.toml`.
*   **Code hygiene**: Removed all `# Bug #N Fixed:` inline comments, a dead `if TYPE_CHECKING: pass` block, and a misleading comment in `_recv_version()`.
*   **Benchmark scripts**: `AutoAddPolicy(accept_risk=True)` used in benchmark scripts to suppress the host-key warning during testing.

## [0.6.10] - 2026-05-08

### Added
*   **Modern NIST Curve Support**: Added full support for `ecdh-sha2-nistp384` and `ecdh-sha2-nistp521` key exchange algorithms, and `ecdsa-sha2-nistp384` and `ecdsa-sha2-nistp521` host key algorithms.
*   **RSA-SHA2-512 Support**: Added support for the `rsa-sha2-512` host key algorithm.
*   **SFTP API Parity**: Implemented `lstat`, `symlink`, and `readlink` in both `SFTPClient` (sync) and `AsyncSFTPClient` (async) to ensure interface consistency.
*   **Enhanced Configuration**: Integrated `SPINDLEX_LOG_LEVEL` and `SPINDLEX_BUFFER_SIZE` environment variables for better external control over library behavior.
*   **Benchmarking Suite**: Updated `scripts/benchmark_compare.py` and `scripts/benchmark_ciphers.py` to cover all newly added algorithms and modern cryptographic configurations.

### Fixed
*   **NIST Curve Key Derivation**: Fixed a critical bug in `KeyExchange` where the incorrect hash algorithm (SHA-256) was being used for NIST P-384 and P-521 curves, causing authentication failures.
*   **Beta Release Planning**: Updated release metadata parsing so `feature` PRs remain patch releases during beta stabilization, `feature-minor` explicitly advances the beta minor line, and breaking beta changes map to minor releases until the stable `1.0.0` policy is enabled.
*   **Release PR Detection**: Added retry and merge-message fallback behavior for push-triggered release planning so GitHub API association lag does not skip a release immediately after merge.
*   **Type Safety & Linting**: Resolved over 35 type errors and linting issues identified by `mypy` and `ruff`, particularly around `bytes`/`bytearray` buffer handling.
*   **Regression Repairs**: Fixed `KeyExchange` unit tests by implementing backward-compatibility aliases and normalizing error messages.

## [0.6.9] - 2026-05-05

### Fixed
*   Routed the intentionally gated legacy `ssh-rsa` SHA-1 compatibility path through a dedicated helper so Semgrep no longer reports the release-blocking direct `hashes.SHA1()` calls.

## [0.6.8] - 2026-05-05

### Summary
This patch release closes the remaining code-scanning items that can be fixed in source control after the v0.6.7 security pipeline rollout.

### Security
*   Raised the minimum supported `cryptography` version to `>=46.0.7` to avoid the vulnerable range reported by OSV/Scorecard for GHSA-p423-j2cm-9vmq.
*   Expanded the root `SECURITY.md` with reporting channels, expected report contents, disclosure timeline, practices, and threat model details so repository security policy scanners can evaluate the maintained policy directly.
*   Moved direct workflow `python -m pip install` verification steps to `uv pip install --python ...` so Scorecard no longer reports un-hashed pip commands for the isolated release and license-audit virtual environments.
*   Tightened Semgrep suppressions around the intentionally gated legacy `ssh-rsa` SHA-1 compatibility path.
*   Added a repository `CODEOWNERS` file so branch protection can require code owner review.

## [0.6.7] - 2026-05-05

### Summary
This release hardens the project lifecycle around release automation, PR gates, security scanning, and incident triage. It resolves the Scorecard/OSV dependency findings reported after v0.6.6, adds corporate-oriented runtime dependency license checks, and turns the CI/CD system into the main release safety surface for future patch releases.

### Security
*   Raised the minimum supported `cryptography` version to `>=46.0.6`, avoiding the vulnerable ranges reported by OSV/Scorecard for the runtime dependency.
*   Raised documentation dependency floors for `pymdown-extensions>=10.16.1` and `pygments>=2.20.0` to avoid known vulnerable documentation-build dependency ranges.
*   Added a runtime dependency license audit to the PR gate and scheduled security workflow. The audit fails on denied corporate-risk licenses such as GPL, LGPL, AGPL, SSPL, BUSL, and proprietary/commercial markers, and uploads a dependency license report from the full security workflow.
*   Added a full scheduled security workflow covering Semgrep, pip-audit, Gitleaks, Trivy, CodeQL SARIF upload, and OpenSSF Scorecard.
*   Documented project security policy and vulnerability reporting expectations in public and maintainer-facing security docs.
*   Kept legacy `ssh-rsa` SHA-1 handling explicitly gated behind `allow_sha1=True` while adding scanner suppressions that document the intentional compatibility path.

### CI/CD
*   Added a fast PR gate with stable PR type parsing, ruff, mypy, unit tests, docs build, workflow linting, security checks, and an aggregate quality gate.
*   Split compatibility and Docker-backed integration checks into reusable workflows used by both PR validation and release dry runs.
*   Added Linux Python 3.9-3.13 coverage plus Windows and macOS smoke coverage for the compatibility matrix.
*   Added full SHA pin dereferencing for GitHub Actions usage and tightened code-scanning-friendly workflow configuration.
*   Updated Trivy action usage and fixed Scorecard workflow permissions.
*   Removed legacy duplicated CI and release helper entry points in favor of the root `Makefile` and the dedicated reusable workflows.

### Release Automation
*   Added PR-driven release planning that maps PR type checkboxes to patch, minor, major, or no-release outcomes.
*   Added release dry-run validation for PRs so release planning, version sync, build, and publish checks are exercised before merge.
*   Added changelog enforcement for release-producing PRs so bug, feature, and breaking changes cannot merge without changelog updates.
*   Added changelog-section extraction for GitHub Release notes so automated releases keep the same detailed release-note shape as previous manual releases.
*   Added workflow failure tracking that opens or updates CI failure, flaky pipeline, and release-blocked incident issues with structured templates.
*   Added release publish and partial-publish triage hooks to preserve release failure context for maintainers.

### Documentation
*   Moved internal lifecycle planning docs out of the public documentation site and into `meta/internal/lifecycle`.
*   Added lifecycle epics, stage gates, release-process epics, quality/security epics, product-readiness epics, release-candidate planning, operations epics, failure-handling guidance, and implementation roadmap docs.
*   Updated contributing docs and PR guidance to match the new stable PR type tokens and release automation.
*   Refreshed badges and operational references after the workflow cleanup.

### Tests
*   Added tests for PR body validation, release planning/version sync, changelog enforcement, workflow failure tracking, and dependency license policy checks.
*   Added `pytest-timeout` to the test tooling used by the split CI workflows.

### Removed
*   Removed the legacy `.github/workflows/ci.yml` workflow after the PR gate, matrix, integration, release, and security workflows took over its responsibilities.
*   Removed obsolete `scripts/release.py`, `scripts/build.sh`, and `scripts/Makefile` helpers.

## [0.6.6] - 2026-05-01

### Summary
This release is a broad hardening pass across every layer of the library - SFTP client/server, transport, key exchange, async forwarding, logging, and host key verification. It resolves 37 issues identified since v0.6.5, including critical resource leaks, protocol correctness bugs, race conditions, and API/documentation gaps.

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
*   Lock release/acquire exception safety in `channel.send()` - lock could be permanently held on exception (#70).
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
*   **`aes128-gcm@openssh.com` and `aes256-gcm@openssh.com`** dropped for the same reason - GCM AEAD requires the same alternative framing path as ChaCha20-Poly1305. Both will be re-introduced in a future release once AEAD framing support is implemented.

### Changed
*   `scripts/benchmark_ciphers.py`: removed the `-p` password CLI argument in favour of an interactive prompt to prevent credentials appearing in shell history (#123).

### Code Health
*   Applied isort, black, ruff, and mypy fixes across the full library and test suite.
*   Removed redundant `_write_string` delegation in `password.py` (#108).
*   Moved `asyncio` import to local scope in `keyboard_interactive.py` (#109).
*   `SFTPError` docstring corrected to reference the right RFC section (#122).

## [0.6.5] - 2026-04-26

### Performance
*   **SFTP 32-deep pipelined request window**: Replaced the strict send-one-wait-ACK-repeat loop in `SFTPFile.read(-1)` and `SFTPFile.write()` with a sliding window of 32 concurrent in-flight SFTP requests. Benchmark against a LAN server (1 MiB file): upload 79 ms → 14 ms (now ~1.6× faster than other SSH libraries), download 50 ms → 15 ms (on par with other SSH libraries). `SFTPClient.get()` and `SFTPClient.put()` also use equivalent pipelining.

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
*   **Two-lock deadlock in `Transport.close()`**: held `self._lock` while calling `Channel.close()`, which re-takes its own lock and then `_close_channel` which re-takes `self._lock` - inverting the order taken by concurrent `Channel.close()` callers. Snapshot channels under the lock, drop it, close each channel, then re-acquire briefly to clear `self._channels`.
*   **`Channel.send` halved the effective remote window**: both `Channel.send()` and `Transport._send_channel_data()` were decrementing `_remote_window_size`, causing premature flow-control stalls. Removed the duplicate decrement on the transport side; the defensive size check is preserved.
*   **SFTPServer path traversal hardening**: `_resolve_path` now uses `realpath` containment checks and rejects NUL bytes; exception handlers narrowed.

### Security
*   **Strict-KEX / Terrapin defense**: the extension filter listed `kex-strict-{c,s}-v00@openssh.com`, but real implementations (and our own transport) advertise/detect the v01 spelling. The v01 marker leaked through the negotiator and the Terrapin defense could silently fail to activate against real OpenSSH peers. Filter now matches v01; `CipherSuite.negotiate_algorithms` also explicitly excludes all strict-KEX / `ext-info` markers from the KEX category and iterates the client's preference order per RFC 4253 §7.1.
*   **Strict-KEX sequence-number reset** and channel-open hardening in transport.
*   **Public-key auth signature algorithm bug**: the algorithm name was hardcoded as `ssh-rsa` in signatures regardless of the negotiated algorithm - fixed.
*   **Atomic rekeying state transitions** under lock; aligned inbound MAC sequence-number wrap with the outbound path.
*   **Global logging sanitizer bypass**: child loggers escaped sanitization; routed through a `LogRecordFactory` hook so the sanitizer applies uniformly.
*   **SHA-1 RSA gated**: signatures over SHA-1 now require an explicit `allow_sha1=True` and emit a `DeprecationWarning`.
*   **Defaults shifted to secure-by-default**: docs, examples, and shipped demos now lead with `RejectPolicy` and a known_hosts helper instead of `AutoAddPolicy`.

### Added
*   **`Channel` / `Transport` context-manager support** (`with channel:` / `with transport:`).
*   **`AsyncSFTPClient.rename` / `chmod` / `normalize`** implementations.
*   **`scripts/benchmark_compare.py`**: cross-library SSH/SFTP benchmark vs other SSH libraries across handshake, exec_command (small + ~1.4 MB), SFTP upload/download, and 10 parallel handshakes. Per-library failures are isolated and rendered as `FAILED -- <error>` instead of aborting the run.

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
*   **Verified Demo Results**: Integrated demo result tracking for actual execution metrics.

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
