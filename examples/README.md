# CryptoTEE Examples

This directory contains examples demonstrating how to use the CryptoTEE library for various cryptographic operations with hardware security modules.

## Examples

### Basic Examples

- **[basic_key_management.rs](basic_key_management.rs)** - Key generation, storage, and deletion
- **[signing_verification.rs](signing_verification.rs)** - Digital signatures and verification
- **[key_import_export.rs](key_import_export.rs)** - Importing and exporting keys

### Advanced Examples

- **[http_signatures.rs](http_signatures.rs)** - RFC 9421 HTTP message signatures
- **[multi_platform.rs](multi_platform.rs)** - Cross-platform key management
- **[plugin_development.rs](plugin_development.rs)** - Creating custom plugins
- **[auth_required.rs](auth_required.rs)** - Using biometric/PIN authentication
- **[performance_optimization.rs](performance_optimization.rs)** - Optimizing for performance

### Platform-Specific Examples

- **[apple_secure_enclave.rs](apple_secure_enclave.rs)** - Apple Secure Enclave features (macOS/iOS)
- **[samsung_knox_vault.rs](samsung_knox_vault.rs)** - Samsung Knox Vault integration (Samsung Android)
- **[android_keystore.rs](android_keystore.rs)** - Android Keystore usage (AOSP)

## Running Examples

To run an example:

```bash
cargo run --example basic_key_management
```

For platform-specific examples, enable the appropriate features:

```bash
# Apple Secure Enclave (macOS/iOS)
cargo run --example apple_secure_enclave --features apple

# Samsung Knox Vault (Samsung devices)
cargo run --example samsung_knox_vault --features samsung

# Software fallback (any platform)
cargo run --example basic_key_management --features software-fallback
```

## Requirements

- Rust 1.70 or later
- Platform-specific requirements:
  - **macOS**: macOS 10.12.1+ for Secure Enclave
  - **iOS**: iOS 9.0+ for Secure Enclave
  - **Android**: Android 6.0+ for hardware-backed keys
  - **Samsung**: Knox SDK license for Knox features

## Common Patterns

### Error Handling

All examples use proper error handling:

```rust
use crypto_tee::{CryptoTEE, CryptoTEEError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crypto_tee = CryptoTEE::new().await?;
    // ... operations ...
    Ok(())
}
```

### Async Operations

CryptoTEE uses async/await for all operations:

```rust
let key = crypto_tee.generate_key(alias, options).await?;
let signature = crypto_tee.sign(alias, data, None).await?;
```

### Key Options

Common key generation patterns:

```rust
use crypto_tee::{KeyOptions, Algorithm, KeyUsage};

// Signing key
let signing_options = KeyOptions {
    algorithm: Algorithm::Ed25519,
    usage: KeyUsage::SIGN_VERIFY,
    extractable: false,
    hardware_backed: true,
    require_auth: false,
    expires_at: None,
};

// Encryption key
let encryption_options = KeyOptions {
    algorithm: Algorithm::Aes256,
    usage: KeyUsage::ENCRYPT_DECRYPT,
    extractable: false,
    hardware_backed: true,
    require_auth: true,  // Requires biometric/PIN
    expires_at: Some(SystemTime::now() + Duration::from_secs(86400)),
};
```

## Security Best Practices

1. **Always use hardware-backed keys when available**
   ```rust
   options.hardware_backed = true;
   ```

2. **Enable authentication for sensitive operations**
   ```rust
   options.require_auth = true;
   ```

3. **Set appropriate key usage restrictions**
   ```rust
   options.usage = KeyUsage::SIGN_VERIFY;  // Can't be used for encryption
   ```

4. **Handle errors gracefully**
   ```rust
   match crypto_tee.generate_key(alias, options).await {
       Ok(key) => { /* use key */ },
       Err(CryptoTEEError::HardwareNotAvailable) => {
           // Fall back to software
       },
       Err(e) => return Err(e.into()),
   }
   ```

5. **Clean up keys when done**
   ```rust
   crypto_tee.delete_key(alias).await?;
   ```

## Troubleshooting

### Hardware Not Available

If you get `HardwareNotAvailable` errors:

1. Check platform compatibility
2. Enable software fallback in platform config
3. Use the simulator for development

### Authentication Failed

For `AuthenticationRequired` errors:

1. Ensure biometric/PIN is set up on device
2. Handle authentication prompts in UI
3. Consider fallback authentication methods

### Performance Issues

For optimal performance:

1. Reuse CryptoTEE instances
2. Use caching for public keys
3. Batch operations when possible
4. See [performance_optimization.rs](performance_optimization.rs)

## License

These examples are part of the CryptoTEE project and are licensed under the same terms.