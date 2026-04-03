# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-04-03

### Fixed

- **SSH Connection Stability:** Resolved numerous issues preventing reliable SSH connections, including:
    - Corrected KEX initialization to prevent protocol mismatches (`MSG_UNIMPLEMENTED` errors).
    - Addressed `bytearray` vs `bytes` type issues in cryptography operations.
    - Ensured correct service request (`ssh-connection`) for password authentication.
    - Fixed duplicate `KEXINIT` messages and added support for `ecdh-sha2-nistp256`.
    - Resolved host key storage and retrieval issues across all KEX methods, preventing "No host key received" warnings.
    - Handled `MSG_GLOBAL_REQUEST` and other internal messages in `_recv_message` to prevent unexpected connection closures.
    - Corrected sequence number incrementing in `_recv_message` for all received packets.
    - Implemented proper blocking behavior in `Channel.recv` to ensure all data is read until EOF.
    - Fixed `PasswordAuth.authenticate` to use the correct service name (`ssh-connection`).
    - Resolved `ChaCha20Poly1305` key length issue and adjusted cipher preference for better compatibility.
    - Addressed potential `MAC verification failed` errors by ensuring correct MAC length determination.
    - Fixed `ChannelFile.read()` to correctly read until EOF.
    - Ensured `Transport` initializes `_server_host_key_blob` correctly.
    - Improved `Transport._recv_message` to handle `MSG_GLOBAL_REQUEST` gracefully.

### Added

- Implemented robust password authentication in `spindlex/auth/password.py`.
- Enhanced `spindlex/transport/channel.py` to ensure `Channel.recv` blocks appropriately until data or EOF.

### Changed

- Prioritized modern KEX and cipher algorithms in `Transport._send_kexinit` for better compatibility.
- Standardized MAC algorithm names (e.g., `hmac-sha2-256`).

## [0.2.0] - 2026-03-31

### Fixed

- Improved logging and sanitization of sensitive data in test files.
- Addressed minor issues in host key parsing and handling.

### Added

- Basic logging structure and sanitization for test files.

## [0.1.0] - 2026-03-20

### Added

- Initial project setup and basic SSH client/server structure.
- Core protocol messages and transport layer implementation.
- Basic key exchange and cipher suite support.
- Rudimentary authentication methods.
