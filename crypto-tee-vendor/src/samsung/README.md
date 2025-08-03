# Samsung Knox TEE Implementation

This module provides integration with Samsung Knox TEE (Trusted Execution Environment) for secure cryptographic operations on Samsung Galaxy devices.

## Features

- **Knox Vault**: Hardware-backed secure key storage
- **TrustZone Integration**: Secure world execution for cryptographic operations
- **Biometric Authentication**: Support for fingerprint and face authentication
- **Key Attestation**: Hardware attestation for generated keys
- **Secure Boot Verification**: Ensure device integrity

## Requirements

- Samsung Galaxy device with Knox 3.0 or higher
- Android 10 (API level 29) or higher
- Samsung Knox SDK 3.9
- Android NDK for building native code

## Building for Android

1. Install Android NDK and set up environment:
```bash
export ANDROID_NDK_HOME=/path/to/android-ndk
export PATH=$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH
```

2. Add Android targets to Rust:
```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
```

3. Build the library:
```bash
cargo build --target aarch64-linux-android --release --features samsung
```

## Integration

### 1. Add Samsung Knox SDK to your Android project

In your app's `build.gradle`:
```gradle
dependencies {
    implementation 'com.samsung.android.knox:knox-sdk:3.9'
}
```

### 2. Add permissions

In your `AndroidManifest.xml`:
```xml
<uses-permission android:name="com.samsung.android.knox.permission.KNOX_KEYSTORE" />
<uses-permission android:name="com.samsung.android.knox.permission.KNOX_ATTESTATION" />
```

### 3. Load the native library

In your Android application:
```kotlin
companion object {
    init {
        System.loadLibrary("crypto_tee_vendor")
    }
}
```

### 4. Initialize Knox TEE

```kotlin
// Initialize Knox TEE with application context
val result = KnoxTEE.initialize(applicationContext)
if (result == 0) {
    // Knox TEE initialized successfully
}
```

## Usage Examples

### Generate a key with Knox Vault

```rust
use crypto_tee_vendor::samsung::{get_samsung_tee, KnoxParams};
use crypto_tee_vendor::types::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get Samsung Knox TEE instance
    let knox_tee = get_samsung_tee()?;
    
    // Configure Knox parameters
    let knox_params = KnoxParams {
        use_knox_vault: true,        // Use hardware-backed Knox Vault
        require_user_auth: true,     // Require biometric authentication
        auth_validity_seconds: Some(300), // Auth valid for 5 minutes
        use_trustzone: true,         // Use TrustZone for operations
        enable_attestation: true,    // Enable key attestation
        container_id: None,          // Use default container
    };
    
    // Set up key generation parameters
    let key_params = KeyGenParams {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: true,
        exportable: false,
        vendor_params: Some(VendorParams::Samsung(knox_params)),
    };
    
    // Generate key
    let key_handle = knox_tee.generate_key(&key_params).await?;
    println!("Generated key: {}", key_handle.id);
    
    Ok(())
}
```

### Sign data with biometric authentication

```rust
// Sign data - will prompt for biometric authentication if required
let data = b"Message to sign";
let signature = knox_tee.sign(&key_handle, data).await?;
println!("Signature: {:?}", signature);
```

### Get key attestation

```rust
// Get hardware attestation for the key
let attestation = knox_tee.get_key_attestation(&key_handle).await?;
println!("Attestation certificates: {} certs", attestation.certificates.len());
```

## Security Considerations

1. **Knox Vault Keys**: Keys stored in Knox Vault are hardware-backed and cannot be extracted
2. **Biometric Binding**: Keys can be bound to biometric authentication for additional security
3. **Attestation**: Always verify attestation certificates to ensure key authenticity
4. **Secure Boot**: Knox TEE operations require verified boot state

## Troubleshooting

### Knox not available
- Ensure device is a Samsung Galaxy with Knox support
- Check Knox version: Settings > Biometrics and security > Other security settings > Knox version

### Permission denied
- Ensure Knox permissions are granted in AndroidManifest.xml
- Some Knox features require Samsung partner registration

### Key generation fails
- Check if Knox Vault is available on the device
- Verify that the device has not been rooted or compromised

## Platform-Specific Notes

- Knox Vault has a limited number of key slots (typically 50-100)
- Some operations may require user presence (device unlocked)
- Attestation certificates are specific to Samsung's certificate chain
- Knox features may vary by device model and Android version