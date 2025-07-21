# crypto-tee-rfc9421

[![Crates.io](https://img.shields.io/crates/v/crypto-tee-rfc9421.svg)](https://crates.io/crates/crypto-tee-rfc9421)
[![Documentation](https://docs.rs/crypto-tee-rfc9421/badge.svg)](https://docs.rs/crypto-tee-rfc9421)

RFC 9421 HTTP Message Signatures implementation using CryptoTEE for hardware-backed signing.

This crate provides a complete implementation of [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) HTTP Message Signatures, leveraging CryptoTEE's hardware security features for key storage and signing operations.

## Features

- **RFC 9421 Compliant** - Full implementation of the standard
- **Hardware-backed Signing** - Use TEE/HSM for signature generation
- **Content Digest** - Automatic content digest generation
- **Flexible Components** - Sign any combination of HTTP components
- **Verification** - Built-in signature verification

## Quick Start

```rust
use crypto_tee_rfc9421::{HttpSignatureBuilder, HttpSignatureVerifier};
use crypto_tee::CryptoTEEBuilder;

// Create HTTP request
let request = http::Request::builder()
    .method("GET")
    .uri("https://api.example.com/data")
    .header("Host", "api.example.com")
    .body(Vec::new())?;

// Sign request
let crypto_tee = CryptoTEEBuilder::new().build().await?;
let builder = HttpSignatureBuilder::new(crypto_tee, "signing-key".to_string());
let signed_request = builder.sign_request(request).await?;

// Verify signature
let verifier = HttpSignatureVerifier::new(crypto_tee);
let result = verifier.verify_request(&signed_request).await?;
```

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for details.