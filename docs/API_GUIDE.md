# CryptoTEE API Guide

This guide provides comprehensive documentation for the CryptoTEE API, including detailed examples and best practices.

## Table of Contents

1. [Core Concepts](#core-concepts)
2. [Initialization](#initialization)
3. [Key Management](#key-management)
4. [Cryptographic Operations](#cryptographic-operations)
5. [Platform-Specific Features](#platform-specific-features)
6. [Plugin System](#plugin-system)
7. [Error Handling](#error-handling)
8. [Performance Optimization](#performance-optimization)
9. [Security Best Practices](#security-best-practices)

## Core Concepts

### Architecture Overview

CryptoTEE follows a layered architecture:

```
Application
    ↓
CryptoTEE API (L3)
    ↓
Platform Layer (L2)
    ↓
Vendor Layer (L1)
    ↓
Hardware TEE
```

### Key Terminology

- **TEE**: Trusted Execution Environment - Hardware-isolated secure area
- **HSM**: Hardware Security Module - Dedicated crypto hardware
- **Key Handle**: Reference to a key stored in the TEE
- **Attestation**: Cryptographic proof of hardware security

## Initialization

### Basic Initialization

```rust
use crypto_tee::{CryptoTEEBuilder, CryptoTEE};

// Auto-detect best available TEE
let crypto_tee = CryptoTEEBuilder::new()
    .build()
    .await?;
```

### Platform-Specific Initialization

```rust
use crypto_tee::{CryptoTEEBuilder, PlatformConfig};

// Prefer Apple Secure Enclave, fall back to software
let crypto_tee = CryptoTEEBuilder::new()
    .with_platform_config(PlatformConfig {
        auto_detect: true,
        preferred_vendor: Some("apple".to_string()),
        fallback_to_software: true,
        cache_keys: true,
    })
    .build()
    .await?;
```

### Vendor-Specific Initialization

```rust
// Force specific vendor
let crypto_tee = CryptoTEEBuilder::new()
    .with_vendor("samsung".to_string())
    .build()
    .await?;
```

## Key Management

### Key Generation

```rust
use crypto_tee::{KeyOptions, Algorithm, KeyUsage};

// Basic key generation
let key = crypto_tee.generate_key(
    "my-key",
    KeyOptions {
        algorithm: Algorithm::Ed25519,
        usage: KeyUsage::SIGN_VERIFY,
        hardware_backed: true,
        extractable: false,
        require_auth: false,
        expires_at: None,
    },
).await?;
```

### Key Options Explained

| Field | Description | Default |
|-------|-------------|---------|
| `algorithm` | Cryptographic algorithm | Ed25519 |
| `usage` | Permitted operations | SIGN_VERIFY |
| `hardware_backed` | Store in hardware if available | true |
| `extractable` | Can export private key | false |
| `require_auth` | Requires biometric/PIN | false |
| `expires_at` | Key expiration time | None |

### Key Import

```rust
// Import existing key material
let imported_key = crypto_tee.import_key(
    "imported-key",
    &key_bytes,
    KeyOptions {
        algorithm: Algorithm::EcdsaP256,
        usage: KeyUsage::SIGN_VERIFY,
        hardware_backed: true,
        extractable: false,
        require_auth: false,
        expires_at: None,
    },
).await?;
```

### Key Listing and Info

```rust
// List all keys
let keys = crypto_tee.list_keys().await?;
for key in keys {
    println!("{}: {:?}", key.alias, key.algorithm);
}

// Get specific key info
let info = crypto_tee.get_key_info("my-key").await?;
println!("Created: {:?}", info.created_at);
println!("Hardware: {}", info.hardware_backed);
```

### Key Deletion

```rust
// Delete a key
crypto_tee.delete_key("my-key").await?;
```

## Cryptographic Operations

### Signing

```rust
use crypto_tee::SignOptions;

// Basic signing
let data = b"Message to sign";
let signature = crypto_tee.sign("my-key", data, None).await?;

// Signing with options
let signature = crypto_tee.sign(
    "my-key",
    data,
    Some(SignOptions {
        hash_algorithm: Some(HashAlgorithm::SHA256),
        padding: Some(PaddingScheme::PSS),
        aad: None,
    }),
).await?;
```

### Verification

```rust
// Verify signature
let is_valid = crypto_tee.verify(
    "my-key",
    data,
    &signature,
    None,
).await?;

if is_valid {
    println!("Signature is valid");
}
```

### Algorithm-Specific Examples

#### Ed25519
```rust
let ed_key = crypto_tee.generate_key(
    "ed25519-key",
    KeyOptions {
        algorithm: Algorithm::Ed25519,
        ..Default::default()
    },
).await?;

// Ed25519 uses EdDSA (includes hashing)
let signature = crypto_tee.sign("ed25519-key", data, None).await?;
```

#### ECDSA P-256
```rust
let ec_key = crypto_tee.generate_key(
    "ecdsa-key",
    KeyOptions {
        algorithm: Algorithm::EcdsaP256,
        ..Default::default()
    },
).await?;

// ECDSA with SHA-256
let signature = crypto_tee.sign("ecdsa-key", data, None).await?;
```

#### RSA
```rust
let rsa_key = crypto_tee.generate_key(
    "rsa-key",
    KeyOptions {
        algorithm: Algorithm::Rsa2048,
        ..Default::default()
    },
).await?;

// RSA with PSS padding
let signature = crypto_tee.sign(
    "rsa-key",
    data,
    Some(SignOptions {
        padding: Some(PaddingScheme::PSS),
        ..Default::default()
    }),
).await?;
```

## Platform-Specific Features

### Apple Secure Enclave

```rust
#[cfg(target_os = "macos")]
{
    // Require Touch ID for operations
    let secure_key = crypto_tee.generate_key(
        "touch-id-key",
        KeyOptions {
            algorithm: Algorithm::EcdsaP256,
            usage: KeyUsage::SIGN_VERIFY,
            hardware_backed: true,
            require_auth: true,  // Touch ID required
            ..Default::default()
        },
    ).await?;
}
```

### Samsung Knox

```rust
#[cfg(all(target_os = "android", feature = "samsung"))]
{
    // Knox-specific features
    let knox_key = crypto_tee.generate_key(
        "knox-key",
        KeyOptions {
            algorithm: Algorithm::EcdsaP256,
            hardware_backed: true,
            require_auth: true,  // Fingerprint required
            ..Default::default()
        },
    ).await?;
}
```

### Android Keystore

```rust
#[cfg(target_os = "android")]
{
    // StrongBox if available
    let strongbox_key = crypto_tee.generate_key(
        "strongbox-key",
        KeyOptions {
            algorithm: Algorithm::Aes256,
            usage: KeyUsage::ENCRYPT_DECRYPT,
            hardware_backed: true,
            ..Default::default()
        },
    ).await?;
}
```

## Plugin System

### Creating a Plugin

```rust
use crypto_tee::plugins::{CryptoPlugin, OperationContext};
use async_trait::async_trait;

struct LoggingPlugin;

#[async_trait]
impl CryptoPlugin for LoggingPlugin {
    async fn on_key_generated(
        &self,
        alias: &str,
        handle: &KeyHandle,
    ) -> CryptoTEEResult<()> {
        println!("Key generated: {} ({:?})", alias, handle.metadata.algorithm);
        Ok(())
    }

    async fn on_sign(
        &self,
        alias: &str,
        data_len: usize,
    ) -> CryptoTEEResult<()> {
        println!("Signing {} bytes with {}", data_len, alias);
        Ok(())
    }
}
```

### Registering Plugins

```rust
let crypto_tee = CryptoTEEBuilder::new().build().await?;
crypto_tee.register_plugin(Box::new(LoggingPlugin)).await;
```

### Built-in Plugin Examples

- **Audit Plugin**: Track all operations for compliance
- **Rate Limit Plugin**: Prevent abuse
- **Metrics Plugin**: Collect performance data
- **Key Rotation Plugin**: Automatic key rotation

## Error Handling

### Error Types

```rust
use crypto_tee::CryptoTEEError;

match crypto_tee.generate_key("key", options).await {
    Ok(key) => { /* success */ },
    Err(CryptoTEEError::HardwareNotAvailable) => {
        // TEE not available, use software
    },
    Err(CryptoTEEError::AuthenticationRequired) => {
        // User must authenticate
    },
    Err(CryptoTEEError::KeyNotFound(alias)) => {
        // Key doesn't exist
    },
    Err(CryptoTEEError::InvalidAlgorithm(algo)) => {
        // Algorithm not supported
    },
    Err(e) => {
        // Other errors
        eprintln!("Error: {}", e);
    },
}
```

### Retry Logic

```rust
use std::time::Duration;
use tokio::time::sleep;

async fn sign_with_retry(
    crypto_tee: &impl CryptoTEE,
    key: &str,
    data: &[u8],
) -> Result<Vec<u8>, CryptoTEEError> {
    let mut attempts = 0;
    loop {
        match crypto_tee.sign(key, data, None).await {
            Ok(sig) => return Ok(sig),
            Err(CryptoTEEError::AuthenticationRequired) if attempts < 3 => {
                attempts += 1;
                println!("Authentication required, attempt {}/3", attempts);
                sleep(Duration::from_secs(1)).await;
            },
            Err(e) => return Err(e),
        }
    }
}
```

## Performance Optimization

### Caching

```rust
use crypto_tee::PlatformConfig;

// Enable key caching
let crypto_tee = CryptoTEEBuilder::new()
    .with_platform_config(PlatformConfig {
        cache_keys: true,
        ..Default::default()
    })
    .build()
    .await?;
```

### Batch Operations

```rust
use futures::future::join_all;

// Parallel signing
let signatures = join_all(
    messages.iter().map(|msg| {
        crypto_tee.sign("key", msg, None)
    })
).await;
```

### Connection Pooling

```rust
// Reuse CryptoTEE instances
lazy_static! {
    static ref CRYPTO_TEE: Arc<CryptoTEEImpl> = {
        Arc::new(
            CryptoTEEBuilder::new()
                .build()
                .await
                .expect("Failed to initialize CryptoTEE")
        )
    };
}
```

## Security Best Practices

### 1. Always Use Hardware When Available

```rust
let key = crypto_tee.generate_key(
    "secure-key",
    KeyOptions {
        hardware_backed: true,
        ..Default::default()
    },
).await?;

// Verify it's hardware-backed
let info = crypto_tee.get_key_info("secure-key").await?;
assert!(info.hardware_backed);
```

### 2. Enable Authentication for Sensitive Operations

```rust
let payment_key = crypto_tee.generate_key(
    "payment-key",
    KeyOptions {
        require_auth: true,  // Always require auth
        ..Default::default()
    },
).await?;
```

### 3. Set Key Expiration

```rust
use std::time::{SystemTime, Duration};

let temp_key = crypto_tee.generate_key(
    "session-key",
    KeyOptions {
        expires_at: Some(SystemTime::now() + Duration::from_secs(3600)),
        ..Default::default()
    },
).await?;
```

### 4. Use Non-Extractable Keys

```rust
let secure_key = crypto_tee.generate_key(
    "non-extractable",
    KeyOptions {
        extractable: false,  // Cannot export private key
        ..Default::default()
    },
).await?;
```

### 5. Implement Key Rotation

```rust
// Check key age and rotate if needed
let info = crypto_tee.get_key_info("signing-key").await?;
let age = SystemTime::now()
    .duration_since(info.created_at)
    .unwrap_or_default();

if age > Duration::from_days(90) {
    // Generate new key
    let new_key = crypto_tee.generate_key(
        "signing-key-v2",
        KeyOptions::default(),
    ).await?;
    
    // Migrate to new key
    // ... update references ...
    
    // Delete old key
    crypto_tee.delete_key("signing-key").await?;
}
```

### 6. Audit All Operations

```rust
// Use audit plugin
crypto_tee.register_plugin(Box::new(AuditPlugin::new())).await;
```

### 7. Handle Errors Gracefully

```rust
// Never expose internal errors to users
match crypto_tee.sign("key", data, None).await {
    Ok(sig) => Ok(sig),
    Err(_) => Err("Signing failed".into()),
}
```

## Advanced Topics

### Remote Attestation

```rust
// Get TEE attestation
let attestation = crypto_tee.get_attestation().await?;

// Get key-specific attestation
let key_attestation = crypto_tee.get_key_attestation("my-key").await?;
```

### Custom Vendor Implementation

```rust
use crypto_tee_vendor::{VendorTEE, VendorResult};

struct CustomVendor;

#[async_trait]
impl VendorTEE for CustomVendor {
    async fn probe(&self) -> VendorResult<VendorCapabilities> {
        // Implementation
    }
    
    // ... other methods ...
}
```

### HTTP Message Signatures (RFC 9421)

```rust
use crypto_tee_rfc9421::HttpSignatureBuilder;

let builder = HttpSignatureBuilder::new(crypto_tee, "signing-key".to_string());
let signed_request = builder.sign_request(request).await?;
```

## Troubleshooting

### Common Issues

1. **Hardware Not Available**
   - Check platform compatibility
   - Enable software fallback
   - Use simulator for development

2. **Authentication Failed**
   - Ensure biometric/PIN is set up
   - Handle auth prompts in UI
   - Implement retry logic

3. **Key Not Found**
   - Check key alias spelling
   - Verify key hasn't expired
   - List keys to debug

4. **Performance Issues**
   - Enable caching
   - Use batch operations
   - Profile with benchmarks

### Debug Logging

```rust
// Enable debug logging
std::env::set_var("RUST_LOG", "crypto_tee=debug");
tracing_subscriber::fmt::init();
```

## Migration Guide

### From Other Libraries

#### From ring
```rust
// Before (ring)
let key_pair = signature::Ed25519KeyPair::generate()?;
let signature = key_pair.sign(data);

// After (CryptoTEE)
let key = crypto_tee.generate_key(
    "ed25519-key",
    KeyOptions {
        algorithm: Algorithm::Ed25519,
        ..Default::default()
    },
).await?;
let signature = crypto_tee.sign("ed25519-key", data, None).await?;
```

#### From native platform APIs
```rust
// Before (iOS SecKeyChain)
let query = [
    kSecClass: kSecClassKey,
    kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
    // ...
];

// After (CryptoTEE)
let key = crypto_tee.generate_key(
    "ecdsa-key",
    KeyOptions {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: true,
        ..Default::default()
    },
).await?;
```

## Performance Benchmarks

Typical performance on common platforms:

| Operation | Software | Apple SE | Knox | StrongBox |
|-----------|----------|----------|------|-----------|
| Ed25519 Gen | 0.5ms | 10ms | 15ms | N/A |
| Ed25519 Sign | 0.1ms | 2ms | 3ms | N/A |
| ECDSA Gen | 2ms | 15ms | 20ms | 25ms |
| ECDSA Sign | 1ms | 5ms | 8ms | 10ms |
| RSA-2048 Gen | 50ms | 100ms | 150ms | 200ms |
| RSA-2048 Sign | 5ms | 20ms | 30ms | 40ms |

## Version Compatibility

| CryptoTEE | Rust | MSRV | Platform Requirements |
|-----------|------|------|----------------------|
| 0.1.x | 1.70+ | 1.70 | See platform table |

## Further Resources

- [API Reference](https://docs.rs/crypto-tee)
- [GitHub Repository](https://github.com/procatstler/crypto-tee-core)
- [Security Advisories](https://github.com/procatstler/crypto-tee-core/security)
- [RFC 9421 Specification](https://www.rfc-editor.org/rfc/rfc9421.html)