# Apple Secure Enclave Implementation

This module provides integration with Apple's Secure Enclave for secure cryptographic operations on iOS and macOS devices.

## Features

- **Secure Enclave**: Hardware-backed key generation and storage
- **Touch ID/Face ID**: Biometric authentication for key operations
- **Keychain Integration**: Secure key storage with access control
- **CryptoKit Support**: Modern cryptographic operations (iOS 13+/macOS 10.15+)
- **Hardware Attestation**: Key and device attestation support

## Requirements

- iOS 11.0+ or macOS 10.13+ (for basic Secure Enclave)
- iOS 13.0+ or macOS 10.15+ (for CryptoKit features)
- Device with Secure Enclave:
  - iPhone 5s and later
  - iPad Air and later
  - Mac with Apple Silicon or T2 chip

## Building for iOS/macOS

1. Install Rust targets:
```bash
# For iOS
rustup target add aarch64-apple-ios
rustup target add x86_64-apple-ios       # For simulator

# For macOS
rustup target add aarch64-apple-darwin   # Apple Silicon
rustup target add x86_64-apple-darwin    # Intel
```

2. Install cargo-lipo for universal binaries:
```bash
cargo install cargo-lipo
```

3. Build the library:
```bash
# For iOS
cargo lipo --release --features apple

# For macOS
cargo build --target aarch64-apple-darwin --release --features apple
```

## Integration

### Swift/Objective-C Integration

1. Create a bridging header:
```c
// CryptoTEE-Bridging-Header.h
extern void crypto_tee_initialize(void);
extern const char* crypto_tee_generate_key(bool require_biometric, const char* label);
extern const uint8_t* crypto_tee_sign_data(const char* key_id, const uint8_t* data, size_t data_len, size_t* out_len);
```

2. Add to your Xcode project:
- Add the built `.a` library to "Link Binary With Libraries"
- Set the bridging header in build settings
- Add required frameworks: Security, LocalAuthentication

3. Configure Info.plist:
```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access your secure keys</string>
```

### Usage Examples

#### Generate a key with biometric protection

```rust
use crypto_tee_vendor::apple::{get_apple_tee, SecureEnclaveParams, AccessControl};
use crypto_tee_vendor::types::*;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Get Apple Secure Enclave instance
    let secure_enclave = get_apple_tee()?;
    
    // Configure Secure Enclave parameters
    let mut access_control = AccessControl::default();
    access_control.biometry_current_set = true;  // Require current Touch ID/Face ID
    access_control.device_passcode = true;        // Fallback to passcode
    
    let se_params = SecureEnclaveParams {
        use_secure_enclave: true,
        require_biometric: true,
        require_passcode: false,
        access_control: Some(access_control),
        access_group: Some("com.example.app".to_string()),
        label: Some("My Secure Key".to_string()),
        application_tag: Some(b"com.example.key1".to_vec()),
    };
    
    // Set up key generation parameters
    let key_params = KeyGenParams {
        algorithm: Algorithm::EcdsaP256,  // Secure Enclave supports P-256
        hardware_backed: true,
        exportable: false,  // Secure Enclave keys cannot be exported
        vendor_params: Some(VendorParams::Apple(se_params)),
    };
    
    // Generate key
    let key_handle = secure_enclave.generate_key(&key_params).await?;
    println!("Generated key: {}", key_handle.id);
    
    Ok(())
}
```

#### Sign data with biometric authentication

```rust
// Sign data - will prompt for Touch ID/Face ID
let data = b"Message to sign";
let signature = secure_enclave.sign(&key_handle, data).await?;
println!("Signature: {:?}", signature);
```

#### Use from Swift

```swift
import LocalAuthentication

class SecureEnclaveManager {
    func generateKey() {
        // Check biometric availability
        let context = LAContext()
        var error: NSError?
        
        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            // Generate key with biometric protection
            let keyId = crypto_tee_generate_key(true, "My Secure Key")
            print("Key generated: \(String(cString: keyId!))")
        }
    }
    
    func signData(keyId: String, data: Data) {
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                              localizedReason: "Sign with your secure key") { success, error in
            if success {
                var outLen: Int = 0
                let signature = crypto_tee_sign_data(keyId, data.bytes, data.count, &outLen)
                // Use signature
            }
        }
    }
}
```

## Security Considerations

1. **Key Protection**: Secure Enclave keys are hardware-protected and cannot be extracted
2. **Biometric Changes**: Keys bound to `biometry_current_set` become invalid if biometrics change
3. **Access Groups**: Use keychain access groups for app sharing
4. **Device Lock**: Keys with `DeviceUnlocked` constraint require unlocked device

## Platform-Specific Features

### iOS-Specific
- Face ID support on iPhone X and later
- App-specific passwords
- Keychain sharing between apps

### macOS-Specific
- Touch ID on MacBook Pro/Air with Touch Bar
- T2 chip secure storage
- Keychain access from command line tools

## Troubleshooting

### Secure Enclave not available
- Check device compatibility (A7 chip or later for iOS)
- Verify not running in simulator
- Check for jailbreak (Secure Enclave disabled on jailbroken devices)

### Biometric authentication fails
- Ensure biometrics are enrolled in Settings
- Check NSFaceIDUsageDescription in Info.plist
- Verify LAContext evaluation on main thread

### Key generation fails
- Verify algorithm is ECDSA P-256 (primary support)
- Check keychain entitlements
- Ensure unique key labels/tags

## Keychain Access

Keys are stored in the iOS/macOS Keychain with the following attributes:
- `kSecAttrTokenID`: `kSecAttrTokenIDSecureEnclave`
- `kSecAttrKeyType`: `kSecAttrKeyTypeECSECPrimeRandom`
- `kSecAttrAccessControl`: Configured biometric/passcode requirements
- `kSecAttrAccessGroup`: For app group sharing

## Testing

### Unit Tests
```bash
cargo test --features apple --target x86_64-apple-darwin
```

### Integration Tests on Device
1. Deploy test app to physical device
2. Ensure biometrics enrolled
3. Run test suite with biometric prompts

### Simulator Limitations
- Secure Enclave not available in simulator
- Use mock implementation for development
- Test on physical device before release