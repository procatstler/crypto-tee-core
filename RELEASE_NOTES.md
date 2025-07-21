# Release Notes - CryptoTEE v0.1.0

We're excited to announce the first public release of CryptoTEE, a unified Rust interface for hardware security modules (TEEs/HSMs) across different platforms.

## Highlights

### 🔐 Hardware Security Made Easy
CryptoTEE provides a single, consistent API for interacting with various hardware security modules:
- Apple Secure Enclave on macOS/iOS
- Samsung Knox on Samsung devices
- Qualcomm QSEE on Android devices
- Software fallback for development and unsupported platforms

### 🌍 True Cross-Platform Support
Write once, run securely everywhere:
```rust
let crypto_tee = CryptoTEEBuilder::new().build().await?;
let key = crypto_tee.generate_key("my-key", options).await?;
```

### 📝 RFC 9421 HTTP Message Signatures
Built-in support for the latest HTTP signature standard:
```rust
let builder = HttpSignatureBuilder::new(crypto_tee, "signing-key");
let signed_request = builder.sign_request(request).await?;
```

### 🛡️ Security First
- Hardware-backed keys that never leave the secure enclave
- Constant-time operations to prevent timing attacks
- Automatic memory zeroization
- Biometric authentication support

## Key Features

- **Unified API**: Same code works across all platforms
- **Async/Await**: Modern Rust async support throughout
- **Plugin System**: Extend functionality with custom plugins
- **Performance**: Optimized with caching and memory pooling
- **Documentation**: Comprehensive docs with examples

## Getting Started

Add to your `Cargo.toml`:
```toml
[dependencies]
crypto-tee = "0.1"
```

See our [examples](https://github.com/procatstler/crypto-tee-core/tree/main/examples) to get started quickly.

## Platform Support

| Platform | Hardware Security | Status |
|----------|-------------------|---------|
| macOS/iOS | Secure Enclave | ✅ Stable |
| Samsung Android | Knox | ✅ Stable |
| Android 6+ | Keystore | ✅ Stable |
| Linux/Windows | Software | ✅ Stable |
| WebAssembly | Software | 🚧 Beta |

## What's Next

We're planning the following for future releases:
- TPM 2.0 support for Linux/Windows
- Additional TEE vendor support
- Enhanced plugin ecosystem
- Performance improvements

## Acknowledgments

Thank you to all contributors who made this release possible!

## Feedback

We'd love to hear from you! Please report issues or feature requests on our [GitHub repository](https://github.com/procatstler/crypto-tee-core/issues).

## License

CryptoTEE is licensed under the Apache License 2.0.