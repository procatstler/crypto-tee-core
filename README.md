# CryptoTEE

[![Crates.io](https://img.shields.io/crates/v/crypto-tee.svg)](https://crates.io/crates/crypto-tee)
[![Documentation](https://docs.rs/crypto-tee/badge.svg)](https://docs.rs/crypto-tee)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Build Status](https://github.com/procatstler/crypto-tee-core/workflows/CI/badge.svg)](https://github.com/procatstler/crypto-tee-core/actions)

CryptoTEE is a unified Rust interface for hardware security modules (TEEs/HSMs) across different platforms. It provides secure key management, cryptographic operations, and HTTP message signatures (RFC 9421) with a consistent API.

## Features

- 🔐 **Hardware Security** - Leverage platform TEEs (Apple Secure Enclave, Samsung Knox, Android Keystore)
- 🌍 **Cross-Platform** - Single API works on macOS, iOS, Android, Linux, and Windows
- 📝 **RFC 9421** - Built-in HTTP Message Signatures support
- 🔑 **Key Management** - Generate, import, export, and manage cryptographic keys
- 🛡️ **Authentication** - Biometric and PIN protection for sensitive operations
- 🔌 **Extensible** - Plugin system for custom functionality
- ⚡ **Async/Await** - Modern async Rust API
- 🦀 **Pure Rust** - Safe, fast, and reliable

## Quick Start

```toml
[dependencies]
crypto-tee = "0.1"
```

```rust
use crypto_tee::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create CryptoTEE instance
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Generate a hardware-backed key
    let key = crypto_tee.generate_key(
        "my-signing-key",
        KeyOptions {
            algorithm: Algorithm::Ed25519,
            usage: KeyUsage::SIGN_VERIFY,
            hardware_backed: true,
            require_auth: false,
            ..Default::default()
        },
    ).await?;

    // Sign data
    let signature = crypto_tee.sign("my-signing-key", b"Hello, World!", None).await?;

    // Verify signature
    let valid = crypto_tee.verify("my-signing-key", b"Hello, World!", &signature, None).await?;
    println!("Signature valid: {}", valid);

    Ok(())
}
```

## Documentation

- **[API Documentation](https://docs.rs/crypto-tee)** - Complete API reference
- **[API Guide](docs/API_GUIDE.md)** - Comprehensive usage guide
- **[Examples](examples/)** - Sample code for common use cases
- **[Architecture](docs/ARCHITECTURE.md)** - System design and internals
- **[Contributing](CONTRIBUTING.md)** - How to contribute
- **[Development](DEVELOPMENT.md)** - Development setup and guidelines

## Platform Support

| Platform | Vendor | Hardware Security | Authentication | Status |
|----------|--------|-------------------|----------------|--------|
| macOS/iOS | Apple | Secure Enclave | Touch/Face ID | ✅ Complete |
| Samsung Android | Knox | TrustZone + Knox Vault | Fingerprint + Knox | ✅ Complete |
| Qualcomm Android | QSEE | TrustZone | Fingerprint | 🚧 In Progress |
| Android 6+ | AOSP | Keystore/StrongBox | Fingerprint | ✅ Complete |
| Linux | OP-TEE/SGX | Hardware TEE | PIN/Biometric | ✅ Complete |
| Windows | Software | None | PIN | ✅ Complete |
| Web/WASM | Software | None | None | 🚧 Beta |

## Architecture

```
┌─────────────────────────────────────────┐
│          Application Layer              │
├─────────────────────────────────────────┤
│    RFC 9421 HTTP Signatures (L4)       │
├─────────────────────────────────────────┤
│       CryptoTEE Core API (L3)          │
├─────────────────────────────────────────┤
│      Platform Abstraction (L2)          │
├─────────────────────────────────────────┤
│        Vendor TEE Layer (L1)            │
├─────────────────────────────────────────┤
│  Hardware TEE (Knox/SE/QSEE/etc.)      │
└─────────────────────────────────────────┘
```

## Examples

### Basic Key Management

```rust
// Generate different key types
let signing_key = crypto_tee.generate_key(
    "signing-key",
    KeyOptions {
        algorithm: Algorithm::Ed25519,
        usage: KeyUsage::SIGN_VERIFY,
        ..Default::default()
    },
).await?;

let encryption_key = crypto_tee.generate_key(
    "encryption-key",
    KeyOptions {
        algorithm: Algorithm::Aes256,
        usage: KeyUsage::ENCRYPT_DECRYPT,
        ..Default::default()
    },
).await?;
```

### Authenticated Operations

```rust
// Create key requiring biometric authentication
let secure_key = crypto_tee.generate_key(
    "secure-key",
    KeyOptions {
        algorithm: Algorithm::EcdsaP256,
        require_auth: true,  // Requires Touch/Face ID
        ..Default::default()
    },
).await?;

// This will prompt for biometric authentication
let signature = crypto_tee.sign("secure-key", data, None).await?;
```

### Samsung Knox Vault

```rust
use crypto_tee::vendors::samsung::KnoxParams;

// Create key in Knox Vault for maximum security
let knox_key = crypto_tee.generate_key_with_vendor_params(
    "knox-key",
    KeyOptions {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: true,
        ..Default::default()
    },
    VendorParams::Samsung(KnoxParams {
        use_knox_vault: true,
        require_user_auth: true,
        use_trustzone: true,
        enable_attestation: true,
        ..Default::default()
    }),
).await?;
```

### HTTP Message Signatures (RFC 9421)

```rust
use crypto_tee_rfc9421::HttpSignatureBuilder;

// Sign HTTP requests
let builder = HttpSignatureBuilder::new(crypto_tee, "signing-key".to_string());
let signed_request = builder.sign_request(request).await?;
```

See the [examples directory](examples/) for more:
- [Basic key management](examples/basic_key_management.rs)
- [Signing and verification](examples/signing_verification.rs)
- [HTTP signatures](examples/http_signatures.rs)
- [Apple Secure Enclave](examples/apple_secure_enclave.rs)
- [Samsung Knox Vault](examples/samsung_knox_vault.rs)
- [Multi-platform usage](examples/multi_platform.rs)
- [Plugin development](examples/plugin_development.rs)
- [Authentication flows](examples/auth_required.rs)

## Security Features

- **Hardware-backed keys** - Private keys never leave the secure hardware (Apple Secure Enclave, Samsung Knox Vault)
- **Biometric authentication** - Protect operations with Touch/Face ID, fingerprint, or Knox authentication
- **Hardware attestation** - Cryptographic proof that keys are hardware-protected with certificate chains
- **Constant-time operations** - Protection against timing side-channel attacks
- **Automatic zeroization** - Sensitive data is cleared from memory after use
- **Non-extractable keys** - Prevent key export for maximum security
- **Knox Vault integration** - Samsung's highest security tier with hardware isolation
- **TrustZone support** - ARM TrustZone integration on Android devices
- **Platform detection** - Automatic selection of best available security features

## Performance

Typical operation times with hardware-backed keys:

| Operation | Ed25519 | ECDSA P-256 | RSA-2048 |
|-----------|---------|-------------|----------|
| Generate | 10-20ms | 15-30ms | 100-200ms |
| Sign | 1-5ms | 5-15ms | 20-100ms |
| Verify | 1-3ms | 3-10ms | 5-20ms |

## Installation

### Cargo

```toml
[dependencies]
crypto-tee = "0.1"

# Optional features
crypto-tee = { version = "0.1", features = ["plugins"] }

# Platform-specific features
[target.'cfg(target_os = "macos")'.dependencies]
crypto-tee = { version = "0.1", features = ["apple"] }

[target.'cfg(target_os = "android")'.dependencies]
crypto-tee = { version = "0.1", features = ["samsung", "qualcomm"] }
```

### Feature Flags

- `plugins` - Enable plugin system
- `software-fallback` - Enable software implementation
- `apple` - Apple Secure Enclave support
- `samsung` - Samsung Knox support
- `qualcomm` - Qualcomm QSEE support
- `simulator` - TEE simulator for development

## Building from Source

```bash
# Clone the repository
git clone https://github.com/procatstler/crypto-tee-core.git
cd crypto-tee-core

# Build all features
cargo build --all-features

# Run tests
cargo test --all-features

# Run benchmarks
cargo bench

# Build documentation
cargo doc --all-features --open
```

## Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Development Setup

1. Install Rust 1.70+
2. Clone the repository
3. Run `cargo test` to verify setup
4. See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed instructions

## Security

For security issues, please see our [Security Policy](.github/SECURITY.md). Do not report security vulnerabilities through public GitHub issues.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

## Acknowledgments

- Built with [ring](https://github.com/briansmith/ring) for cryptographic primitives
- Inspired by [Web Crypto API](https://www.w3.org/TR/WebCryptoAPI/) design
- RFC 9421 implementation based on [HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)

## Support

- 📧 Email: security@example.com
- 💬 Discord: [Join our server](https://discord.gg/cryptotee)
- 🐛 Issues: [GitHub Issues](https://github.com/procatstler/crypto-tee-core/issues)
- 📖 Docs: [docs.rs/crypto-tee](https://docs.rs/crypto-tee)


