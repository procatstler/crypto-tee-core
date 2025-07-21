# crypto-tee-platform

[![Crates.io](https://img.shields.io/crates/v/crypto-tee-platform.svg)](https://crates.io/crates/crypto-tee-platform)
[![Documentation](https://docs.rs/crypto-tee-platform/badge.svg)](https://docs.rs/crypto-tee-platform)

Platform abstraction layer for CryptoTEE - Layer 2 platform detection and vendor selection.

This crate provides platform-specific detection and vendor selection logic, automatically choosing the best available TEE implementation for the current platform.

## Features

- **Auto-detection** - Automatically detect available TEE vendors
- **Fallback Logic** - Graceful fallback to software implementation
- **Platform Support** - Android, iOS, macOS, Linux, Windows
- **Vendor Selection** - Choose the best vendor for the platform

## Usage

This crate is typically not used directly. Instead, use the main `crypto-tee` crate which provides a high-level API.

For platform detection details, see the [documentation](https://docs.rs/crypto-tee-platform).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.