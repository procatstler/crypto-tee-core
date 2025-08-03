# Qualcomm QSEE Implementation

This module provides integration with Qualcomm Secure Execution Environment (QSEE) for secure cryptographic operations on Android devices with Qualcomm Snapdragon processors.

## Features

- **Hardware-backed Security**: Leverages ARM TrustZone technology
- **Keymaster Integration**: Full Android Keymaster HAL support
- **Secure Storage**: Keys stored in hardware-protected memory
- **StrongBox Support**: Dedicated secure element on Pixel 3+ and select devices
- **Hardware Attestation**: Key and device attestation support
- **Secure Channel**: Encrypted communication with TrustZone

## Architecture

```
┌─────────────────────┐
│   Android App       │
├─────────────────────┤
│   JNI Bridge        │
├─────────────────────┤
│   Rust Library      │
├─────────────────────┤
│ Android Keystore    │
├─────────────────────┤
│   Keymaster HAL     │
├─────────────────────┤
│   QSEE (TrustZone)  │
└─────────────────────┘
```

## Requirements

- Android 6.0+ (API level 23+)
- Qualcomm Snapdragon processor
- ARM TrustZone support
- Android Keystore provider

## Building for Android

1. Install Android NDK:
```bash
# Set up NDK (version r21 or later)
export ANDROID_NDK_HOME=/path/to/android-ndk
```

2. Add Rust targets:
```bash
rustup target add aarch64-linux-android
rustup target add armv7-linux-androideabi
rustup target add x86_64-linux-android
rustup target add i686-linux-android
```

3. Install cargo-ndk:
```bash
cargo install cargo-ndk
```

4. Build the library:
```bash
# For ARM64
cargo ndk -t arm64-v8a --platform 23 build --release --features qualcomm

# For ARMv7
cargo ndk -t armeabi-v7a --platform 23 build --release --features qualcomm

# For x86_64 (emulator)
cargo ndk -t x86_64 --platform 23 build --release --features qualcomm
```

## Integration

### Android (Java/Kotlin)

1. Add the native library to your Android project:
```
app/src/main/
├── jniLibs/
│   ├── arm64-v8a/
│   │   └── libcrypto_tee_vendor.so
│   ├── armeabi-v7a/
│   │   └── libcrypto_tee_vendor.so
│   └── x86_64/
│       └── libcrypto_tee_vendor.so
```

2. Load the library:
```kotlin
class QSEEBridge {
    companion object {
        init {
            System.loadLibrary("crypto_tee_vendor")
        }
    }
    
    // Native methods
    external fun nativeInit()
    external fun nativeGenerateKey(
        alias: String,
        algorithm: String,
        keySize: Int,
        hardwareBacked: Boolean,
        requireAuth: Boolean,
        authValidity: Int
    ): Boolean
    
    external fun nativeSign(
        alias: String,
        data: ByteArray
    ): ByteArray?
    
    external fun nativeVerify(
        alias: String,
        data: ByteArray,
        signature: ByteArray
    ): Boolean
    
    external fun nativeGetAttestation(
        alias: String
    ): ByteArray?
}
```

3. Use in your app:
```kotlin
class CryptoManager(context: Context) {
    private val qseeBridge = QSEEBridge()
    
    init {
        qseeBridge.nativeInit()
    }
    
    fun generateKey(alias: String, requireBiometric: Boolean = false) {
        val success = qseeBridge.nativeGenerateKey(
            alias = alias,
            algorithm = "EC",
            keySize = 256,
            hardwareBacked = true,
            requireAuth = requireBiometric,
            authValidity = 300 // 5 minutes
        )
        
        if (!success) {
            throw SecurityException("Failed to generate key in QSEE")
        }
    }
    
    fun signData(alias: String, data: ByteArray): ByteArray {
        return qseeBridge.nativeSign(alias, data)
            ?: throw SecurityException("Failed to sign data")
    }
}
```

### Usage Examples

#### Generate a hardware-backed key

```rust
use crypto_tee_vendor::qualcomm::{get_qualcomm_tee, QSEEParams, ProtectionLevel};
use crypto_tee_vendor::types::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get QSEE instance
    let qsee = get_qualcomm_tee()?;
    
    // Configure QSEE parameters
    let qsee_params = QSEEParams {
        use_hardware_keystore: true,
        use_secure_channel: true,
        protection_level: ProtectionLevel::Hardware,
        require_auth: true,
        auth_validity_duration: Some(300), // 5 minutes
        use_strongbox: false, // Use true on Pixel 3+
        ..Default::default()
    };
    
    // Set up key generation parameters
    let key_params = KeyGenParams {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: true,
        exportable: false,
        vendor_params: Some(VendorParams::Qualcomm(qsee_params)),
    };
    
    // Generate key
    let key_handle = qsee.generate_key(&key_params).await?;
    println!("Generated key: {}", key_handle.id);
    
    Ok(())
}
```

#### Sign with user authentication

```rust
// Sign data - will prompt for fingerprint/face/PIN
let data = b"Important transaction";
let signature = qsee.sign(&key_handle, data).await?;
println!("Signature created: {} bytes", signature.data.len());
```

#### Use StrongBox (Pixel 3+ and select devices)

```rust
let qsee_params = QSEEParams {
    protection_level: ProtectionLevel::StrongBox,
    use_strongbox: true,
    ..Default::default()
};
```

## Security Features

### Key Protection Levels

1. **Software**: Keys protected by Android Keystore software implementation
2. **Hardware**: Keys protected by QSEE/TrustZone
3. **StrongBox**: Keys protected by dedicated secure element

### Authentication

- **No Authentication**: Key can be used without user verification
- **Biometric**: Requires fingerprint or face recognition
- **Device Credential**: Requires PIN/pattern/password
- **Time-based**: Key usage valid for specified duration after auth

### Attestation

QSEE provides hardware attestation for:
- Key origin (hardware-generated)
- Key properties (algorithm, size, usage)
- Device properties (OS version, patch level)
- Application identity

## Platform-Specific Features

### Qualcomm-Specific Capabilities

- **Secure Display**: Protected UI rendering in TrustZone
- **Secure Camera**: Direct camera-to-TEE data path
- **DRM**: Hardware-backed content protection
- **Secure Payment**: EMVCo-certified payment applications

### Device Support

Verified on:
- Snapdragon 8 Gen 3 (flagship devices)
- Snapdragon 8 Gen 2
- Snapdragon 888/888+
- Snapdragon 865/865+
- Snapdragon 855/855+
- Snapdragon 845

## Build Configuration

### Android.mk
```makefile
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := crypto_tee_vendor
LOCAL_SRC_FILES := $(TARGET_ARCH_ABI)/libcrypto_tee_vendor.so
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_SHARED_LIBRARY)
```

### CMakeLists.txt
```cmake
add_library(crypto_tee_vendor SHARED IMPORTED)
set_target_properties(crypto_tee_vendor PROPERTIES
    IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/libs/${ANDROID_ABI}/libcrypto_tee_vendor.so
)
```

## Troubleshooting

### QSEE not available
- Verify device has Qualcomm chipset: `getprop ro.board.platform`
- Check for QSEE support: `ls /vendor/lib*/libQSEEComAPI.so`
- Ensure SELinux permits access

### Key generation fails
- Check Android Keystore is initialized
- Verify app has required permissions
- Ensure no root/custom ROM interference

### Authentication issues
- Verify biometrics are enrolled
- Check lockscreen is set up
- Ensure auth validity duration is reasonable

### Attestation failures
- Verify Google Play Services is up to date
- Check device is not rooted
- Ensure bootloader is locked

## Performance Considerations

- **Key Generation**: ~50-200ms (hardware-dependent)
- **Signing**: ~10-30ms per operation
- **Verification**: ~5-15ms per operation
- **Secure Channel**: Adds ~5-10ms overhead

## Testing

### Unit Tests
```bash
cargo test --features qualcomm --target x86_64-linux-android
```

### Integration Tests on Device
```bash
adb push target/aarch64-linux-android/release/test_qsee /data/local/tmp/
adb shell chmod +x /data/local/tmp/test_qsee
adb shell /data/local/tmp/test_qsee
```

### Emulator Support
QSEE is not available in Android emulators. Use physical devices for testing.

## Security Best Practices

1. **Always use hardware backing** when available
2. **Enable user authentication** for sensitive operations
3. **Set appropriate auth validity** durations
4. **Verify attestation** for critical keys
5. **Use StrongBox** for highest security needs
6. **Implement secure channel** for sensitive data
7. **Handle errors gracefully** - don't expose internals
8. **Audit key usage** regularly
9. **Rotate keys periodically**
10. **Test on actual hardware** before release