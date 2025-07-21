# crypto-tee

[![Crates.io](https://img.shields.io/crates/v/crypto-tee.svg)](https://crates.io/crates/crypto-tee)
[![Documentation](https://docs.rs/crypto-tee/badge.svg)](https://docs.rs/crypto-tee)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](../LICENSE)

The main CryptoTEE crate providing a unified Rust interface for hardware security modules (TEEs/HSMs).

## Features

- 🔐 Hardware-backed key storage
- 🌍 Cross-platform support
- 🔑 Key lifecycle management
- ✍️ Digital signatures
- 🔌 Plugin system
- ⚡ Async/await API

## Quick Start

```rust
use crypto_tee::prelude::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize CryptoTEE
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Generate a key
    let key = crypto_tee.generate_key(
        "my-key",
        KeyOptions {
            algorithm: Algorithm::Ed25519,
            usage: KeyUsage::SIGN_VERIFY,
            hardware_backed: true,
            ..Default::default()
        },
    ).await?;

    // Sign data
    let signature = crypto_tee.sign("my-key", b"Hello!", None).await?;

    Ok(())
}
```

## Platform Support

| Platform | Hardware Security | Feature Flag |
|----------|-------------------|--------------|
| macOS/iOS | Secure Enclave | `apple` |
| Samsung | Knox | `samsung` |
| Android | Keystore | Default |
| Linux/Windows | Software | `software-fallback` |

## Documentation

See the [full documentation](https://docs.rs/crypto-tee) for detailed API reference and examples.

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.