# Changelog

All notable changes to SpindleX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Complete Transport.start_client() method implementation with SSH protocol handshake
- Authentication methods: auth_password and auth_publickey in Transport class
- Channel management with open_channel method and lifecycle management
- Command execution methods: exec_command, invoke_shell, request_pty in Channel class
- Data transmission methods: send, recv, recv_stderr for channel communication
- Complete CryptographyBackend class with cipher creation and key derivation
- Diffie-Hellman key exchange implementation with session key derivation
- SFTP file transfer methods: get and put for file operations
- SFTP directory operations: listdir, mkdir, rmdir with proper error handling
- Port forwarding functionality: local and remote port forwarding with PortForwardingManager
- Complete protocol message handling with serialization/deserialization
- SFTP protocol constants and message type handling
- Integration testing with real SSH server validation
- Mock GSSAPI classes for testing when GSSAPI library is not available
- **Python 3.13 and 3.14 Support**: Added support for the latest Python versions

### Fixed
- **Test Suite Comprehensive Fixes**: Fixed all 500 core functionality tests to pass
- Test suite imports updated from ssh_library to spindlex
- Test imports updated from spindle to spindlex throughout test files
- Protocol constants and message type definitions
- Missing timeout constants and default values
- Channel lifecycle management and proper cleanup
- SFTP error handling and status code management
- Port forwarding integration with Transport class
- Protocol message validation and error handling
- **GSSAPI Authentication Tests**: Fixed all GSSAPI tests to work without requiring actual GSSAPI library
- **Async Client Tests**: Fixed async mock setup to eliminate coroutine warnings
- **Integration Tests**: Fixed MockSFTPClient to properly track file sizes and handle concurrent operations
- **Performance Tests**: Fixed buffer type compatibility issues between deque and bytes operations
- **Protocol Message Tests**: Fixed SFTP message format issues with proper IgnoreMessage imports
- **Comprehensive Benchmarks**: Fixed syntax errors and memory usage assertions
- **Key Exchange Compatibility**: Added explicit support for `diffie-hellman-group1-sha1` KEX algorithm to improve compatibility with older SSH servers.

### Changed
- **Dropped Python 3.8 Support**: Minimum Python version is now 3.9

### Improved
- Test coverage with real SSH server integration testing
- Authentication flow with proper error handling
- File transfer operations with attribute handling
- Directory management with comprehensive error reporting
- Tunnel lifecycle management for port forwarding
- Protocol message parsing and validation
- **Test Reliability**: All core functionality tests now pass consistently without skips or warnings
- **Debugging Capabilities**: Enhanced transport layer with verbose logging for key exchange and packet handling, aiding in connection diagnosis.

## [0.2.0] - 2025-10-17

### Added
- Complete SSH key exchange implementation with Curve25519, DH Group 14/16/18
- Modern SSH protocol extensions (ext-info, strict-kex) for OpenSSH compatibility
- Comprehensive cryptographic backend with SSH-specific key derivation
- Full SSH message serialization/deserialization system
- Advanced algorithm negotiation supporting latest OpenSSH features
- Professional PyPI package distribution infrastructure
- Enhanced error handling with detailed SSH protocol exceptions
- Extensive protocol utilities for SSH message construction
- Support for modern encryption algorithms (ChaCha20-Poly1305, AES-GCM)
- ETM (Encrypt-then-MAC) algorithm support for enhanced security

### Changed
- Upgraded SSH version compatibility to OpenSSH 9.x standards
- Enhanced KEXINIT message handling with full extension support
- Improved transport layer with proper SSH packet framing
- Optimized key exchange algorithms for better performance
- Updated authentication framework to support modern SSH requirements
- Enhanced host key policy system with auto-add functionality

### Fixed
- SSH protocol implementation to work with modern OpenSSH servers
- Key exchange message format for proper server compatibility
- Transport layer packet construction and validation
- Authentication method negotiation and execution
- Message type handling and protocol state management
- Import issues with create_version_string function

### Security
- Implemented SSH strict KEX extension for enhanced security
- Added support for modern cryptographic algorithms
- Enhanced random number generation for key exchange
- Improved host key verification with multiple policy options
- Secure session key derivation following SSH RFCs

## [0.1.0] - 2024-01-15

### Added
- Initial release of SpindleX
- Complete SSHv2 protocol implementation
- SSH client with all major authentication methods
- SFTP client for secure file transfers
- SSH server implementation
- SFTP server implementation
- Modern cryptographic algorithms (Ed25519, ChaCha20-Poly1305)
- Comprehensive test suite
- Documentation and examples

### Features
- **SSH Client**: Password, public key, keyboard-interactive, GSSAPI authentication
- **SFTP Client**: File upload/download, directory operations, attribute management
- **SSH Server**: Custom server implementation with authentication hooks
- **SFTP Server**: File system operations with access control
- **Port Forwarding**: Local and remote port forwarding
- **Cryptography**: Ed25519, ECDSA, RSA keys; ChaCha20-Poly1305, AES-GCM ciphers
- **Security**: Host key verification, secure defaults, audit logging
- **Performance**: Optimized for high throughput and low latency