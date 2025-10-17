# Changelog

All notable changes to SpindleX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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