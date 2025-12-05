Changelog
=========

All notable changes to SpindleX will be documented in this file.

The format is based on `Keep a Changelog <https://keepachangelog.com/en/1.0.0/>`_,
and this project adheres to `Semantic Versioning <https://semver.org/spec/v2.0.0.html>`_.

Unreleased
----------

Added
~~~~~
- Comprehensive API documentation with Sphinx
- Advanced usage examples and tutorials
- Performance optimization guide
- Security best practices documentation
- Async SSH client implementation
- Custom protocol subsystem support
- High-performance file transfer optimizations
- Connection pooling and management
- Built-in performance monitoring
- Extensive logging and debugging capabilities
- **Python 3.13 and 3.14 Support**: Added support for the latest Python versions

Changed
~~~~~~~
- Improved error handling and exception hierarchy
- Enhanced SFTP client with advanced features
- Optimized cryptographic operations
- Better memory management for large transfers
- Dropped Python 3.8 Support: Minimum Python version is now 3.9

Fixed
~~~~~
- Various bug fixes and stability improvements
- Memory leaks in long-running connections
- Race conditions in concurrent operations
- Test Suite Comprehensive Fixes: Fixed all 500 core functionality tests to pass
- Test suite imports updated from ssh_library to spindlex
- Test imports updated from spindle to spindlex throughout test files
- Protocol constants and message type definitions
- Missing timeout constants and default values
- Channel lifecycle management and proper cleanup
- SFTP error handling and status code management
- Port forwarding integration with Transport class
- Protocol message validation and error handling
- GSSAPI Authentication Tests: Fixed all GSSAPI tests to work without requiring actual GSSAPI library
- Async Client Tests: Fixed async mock setup to eliminate coroutine warnings
- Integration Tests: Fixed MockSFTPClient to properly track file sizes and handle concurrent operations
- Performance Tests: Fixed buffer type compatibility issues between deque and bytes operations
- Protocol Message Tests: Fixed SFTP message format issues with proper IgnoreMessage imports
- Comprehensive Benchmarks: Fixed syntax errors and memory usage assertions
- Key Exchange Compatibility: Added explicit support for ``diffie-hellman-group1-sha1`` KEX algorithm to improve compatibility with older SSH servers.

Improved
~~~~~~~~
- Test coverage with real SSH server integration testing
- Authentication flow with proper error handling
- File transfer operations with attribute handling
- Directory management with comprehensive error reporting
- Tunnel lifecycle management for port forwarding
- Protocol message parsing and validation
- Test Reliability: All core functionality tests now pass consistently without skips or warnings
- Debugging Capabilities: Enhanced transport layer with verbose logging for key exchange and packet handling, aiding in connection diagnosis.

Changed
~~~~~~~
- Improved error handling and exception hierarchy
- Enhanced SFTP client with advanced features
- Optimized cryptographic operations
- Better memory management for large transfers

Fixed
~~~~~
- Various bug fixes and stability improvements
- Memory leaks in long-running connections
- Race conditions in concurrent operations

Security
~~~~~~~~
- Enhanced host key verification
- Improved authentication security
- Secure random number generation
- Constant-time cryptographic comparisons

[1.0.0] - 2024-01-15
---------------------

Added
~~~~~
- Initial release of SpindleX
- Complete SSHv2 protocol implementation
- SSH client with all major authentication methods
- SFTP client for secure file transfers
- SSH server implementation
- SFTP server implementation
- Modern cryptographic algorithms (Ed25519, ChaCha20-Poly1305)
- Comprehensive test suite
- Documentation and examples

Features
~~~~~~~~
- **SSH Client**: Password, public key, keyboard-interactive, GSSAPI authentication
- **SFTP Client**: File upload/download, directory operations, attribute management
- **SSH Server**: Custom server implementation with authentication hooks
- **SFTP Server**: File system operations with access control
- **Port Forwarding**: Local and remote port forwarding
- **Cryptography**: Ed25519, ECDSA, RSA keys; ChaCha20-Poly1305, AES-GCM ciphers
- **Security**: Host key verification, secure defaults, audit logging
- **Performance**: Optimized for high throughput and low latency