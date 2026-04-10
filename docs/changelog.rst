Changelog
=========

All notable changes to this project will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

0.4.1 (2026-04-10)
------------------

Fixed
~~~~~
* Fixed critical "Receive timeout" in ``AsyncSSHClient`` and ``AsyncSFTPClient`` by implementing transport pumping in ``AsyncChannel``.
* Corrected attribute naming in ``AsyncChannel`` (e.g., ``_eof_received``, ``_closed``).
* Fixed ``AsyncChannel.send`` to correctly return total bytes sent and handle window adjustments robustly.
* Fixed ``AsyncTransport`` to properly initialize channel window and packet sizes from server confirmation.
* Corrected message argument naming in ``AsyncTransport`` (e.g., ``bytes_to_add`` in window adjust).
* Fixed message loss bug in ``AsyncTransport`` by ensuring all pumped messages are queued.
* Fixed ``AsyncSFTPClient._recv_message`` to robustly read length-prefixed messages using new ``recv_exactly`` method.

Added
~~~~~
* Added ``recv_exactly`` method to ``AsyncChannel`` for reliable protocol-level data retrieval.
* Added ``remove`` method to ``AsyncSFTPClient``.
* Added asynchronous context manager support (``async with``) to ``AsyncSFTPClient`` and ``AsyncSFTPFile``.
* Added ``makefile_stderr`` support to ``AsyncChannel``.

0.4.0 (2026-04-07)
------------------


Fixed
~~~~~
- **Transport Layer:** Resolved a critical hang in SSH command execution caused by an infinite loop in ``Transport._expect_message`` where unhandled messages were repeatedly re-queued and re-read.
- **Message Dispatching:** Improved ``Transport._handle_channel_message`` to correctly extract recipient channel IDs for all message types, ensuring proper dispatch to channel instances.
- **Concurrency:** Added ``_read_lock`` to ``Transport`` to prevent concurrent socket access and potential data corruption during simultaneous read operations.
- **SSH Client:** Ensured ``SSHClient`` permanently sets the connection timeout on the underlying transport after a successful handshake.
- **Channel Stability:** Updated ``Channel.exec_command`` to automatically send EOF after the command, improving compatibility with various SSH server implementations.

Added
~~~~~
- **SFTP Client:** Implemented context manager support (``__enter__``/``__exit__``) for ``SFTPClient`` for easier resource management.
- **SFTP Operations:** Implemented ``SFTPClient.open()`` and the ``SFTPFile`` class to support synchronous file-like operations (read/write).
- **Channel Timeouts:** Enhanced ``Channel.recv`` to respect per-channel timeouts, preventing indefinite blocking.

0.3.0 (2026-04-04)
------------------

Fixed
~~~~~
- **Protocol Utilities:** Fixed ``write_mpint`` to use the minimum number of bytes for negative integers (e.g., -128 now correctly serializes to ``0x80`` instead of ``0xff80``).
- **Version Parsing:** Improved error handling in ``parse_version_string`` to provide clearer messages for invalid SSH version strings.
- **SSH Connection Stability:** Resolved numerous issues preventing reliable SSH connections, including:
    - Corrected KEX initialization to prevent protocol mismatches (``MSG_UNIMPLEMENTED`` errors).
    - Addressed ``bytearray`` vs ``bytes`` type issues in cryptography operations.
    - Ensured correct service request (``ssh-connection``) for password authentication.
    - Fixed duplicate ``KEXINIT`` messages and added support for ``ecdh-sha2-nistp256``.
    - Resolved host key storage and retrieval issues across all KEX methods, preventing "No host key received" warnings.
    - Handled ``MSG_GLOBAL_REQUEST`` and other internal messages in ``_recv_message`` to prevent unexpected connection closures.
    - Corrected sequence number incrementing in ``_recv_message`` for all received packets.
    - Implemented proper blocking behavior in ``Channel.recv`` to ensure all data is read until EOF.
    - Fixed ``PasswordAuth.authenticate`` to use the correct service name (``ssh-connection``).
    - Resolved ``ChaCha20Poly1305`` key length issue and adjusted cipher preference for better compatibility.
    - Addressed potential ``MAC verification failed`` errors by ensuring correct MAC length determination.
    - Fixed ``ChannelFile.read()`` to correctly read until EOF.
    - Ensured ``Transport`` initializes ``_server_host_key_blob`` correctly.
    - Improved ``Transport._recv_message`` to handle ``MSG_GLOBAL_REQUEST`` gracefully.

Added
~~~~~
- **Unit Tests:** Created a comprehensive test suite in ``tests/`` covering protocol utilities and constants.
- **Configuration Consolidation:** Unified project configuration into ``pyproject.toml``, removing redundant ``setup.cfg``, ``pytest.ini``, ``.flake8``, and ``tox.ini`` files.
- Implemented robust password authentication in ``spindlex/auth/password.py``.
- Enhanced ``spindlex/transport/channel.py`` to ensure ``Channel.recv`` blocks appropriately until data or EOF.

Changed
~~~~~~~
- Prioritized modern KEX and cipher algorithms in ``Transport._send_kexinit`` for better compatibility.
- Standardized MAC algorithm names (e.g., ``hmac-sha2-256``).

0.2.0 (2026-03-31)
------------------

Fixed
~~~~~
- Improved logging and sanitization of sensitive data in test files.
- Addressed minor issues in host key parsing and handling.

Added
~~~~~
- Basic logging structure and sanitization for test files.

0.1.0 (2026-03-20)
------------------

Added
~~~~~
- Initial project setup and basic SSH client/server structure.
- Core protocol messages and transport layer implementation.
- Basic key exchange and cipher suite support.
- Rudimentary authentication methods.
