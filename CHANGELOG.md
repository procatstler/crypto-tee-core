# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2024-12-21

### Added

#### Core Features
- Initial release of CryptoTEE unified interface for hardware security modules
- Layer 1: Vendor implementations for Samsung Knox, Apple Secure Enclave, Qualcomm QSEE
- Layer 2: Platform abstraction with automatic vendor detection and fallback
- Layer 3: High-level API for key management and cryptographic operations
- Layer 4: RFC 9421 HTTP Message Signatures implementation

#### Security Features
- Hardware-backed key storage on supported platforms
- Biometric authentication support (Touch/Face ID, fingerprint)
- Constant-time cryptographic operations to prevent timing attacks
- Automatic memory zeroization for sensitive data
- Key attestation support

#### Platform Support
- macOS/iOS with Apple Secure Enclave
- Android with Samsung Knox and Qualcomm QSEE
- Software fallback for all platforms
- WebAssembly support (beta)

#### Developer Features
- Comprehensive async/await API
- Plugin system for extensibility
- Performance optimizations with caching
- Extensive documentation and examples
- Full test coverage with unit and integration tests

### Security
- All cryptographic operations use constant-time implementations
- Memory containing sensitive data is automatically zeroized
- Hardware isolation ensures private keys never leave the TEE

### Performance
- Optimized signature verification with caching
- Memory pool for reduced allocations
- Async operations for non-blocking I/O

### Documentation
- API documentation with rustdoc
- Comprehensive examples for all major use cases
- Platform-specific guides
- Security best practices

[0.1.0]: https://github.com/procatstler/crypto-tee-core/releases/tag/v0.1.0