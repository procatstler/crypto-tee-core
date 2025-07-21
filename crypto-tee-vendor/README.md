# crypto-tee-vendor

[![Crates.io](https://img.shields.io/crates/v/crypto-tee-vendor.svg)](https://crates.io/crates/crypto-tee-vendor)
[![Documentation](https://docs.rs/crypto-tee-vendor/badge.svg)](https://docs.rs/crypto-tee-vendor)

Vendor-specific TEE implementations for CryptoTEE - Layer 1 hardware interfaces.

This crate provides the low-level vendor-specific implementations for various hardware security modules and trusted execution environments.

## Features

- **Mock Implementation** - For testing and development
- **Software Fallback** - Pure software implementation
- **Samsung Knox** - Samsung's enterprise security platform
- **Apple Secure Enclave** - Apple's hardware security coprocessor
- **Qualcomm QSEE** - Qualcomm's Secure Execution Environment

## Usage

This crate is typically not used directly. Instead, use the main `crypto-tee` crate which provides a high-level API.

For vendor implementations, see the [documentation](https://docs.rs/crypto-tee-vendor).

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.