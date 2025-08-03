//! Apple Secure Enclave Example
//!
//! This example demonstrates how to use the Apple Secure Enclave for maximum 
//! security on macOS and iOS devices.

use crypto_tee::prelude::*;
use crypto_tee_vendor::apple::SecureEnclaveParams;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Apple Secure Enclave Example");
    println!("============================");

    // Initialize CryptoTEE
    let crypto_tee = CryptoTEEBuilder::new()
        .prefer_hardware(true)
        .build()
        .await?;

    // Check if Secure Enclave is available
    let platform_info = crypto_tee.get_platform_info().await?;
    println!("Platform: {} v{}", platform_info.name, platform_info.version);

    let vendors = crypto_tee.list_available_vendors().await?;
    let secure_enclave_available = vendors.iter()
        .any(|v| v.name.contains("Secure Enclave"));
    
    if !secure_enclave_available {
        println!("⚠️  Apple Secure Enclave not available on this device");
        println!("This example requires an Apple device with Secure Enclave:");
        println!("   • iPhone 5s or later");
        println!("   • iPad Air or later"); 
        println!("   • Apple Silicon Mac or T2 Mac");
        return Ok(());
    }

    println!("✅ Apple Secure Enclave detected");

    // Generate key with Secure Enclave
    println!("\n1. Generating key in Secure Enclave...");
    
    let se_key = crypto_tee.generate_key_with_vendor_params(
        "secure-enclave-key",
        KeyOptions {
            algorithm: Algorithm::EcdsaP256, // Secure Enclave supports P-256
            usage: KeyUsage::SIGN_VERIFY,
            hardware_backed: true,
            exportable: false,  // Keys cannot be exported from Secure Enclave
            require_auth: true, // Require Touch ID/Face ID
            expires_at: None,
            metadata: Some(KeyMetadata {
                description: Some("Secure Enclave signing key".to_string()),
                tags: vec!["secure-enclave".to_string(), "biometric".to_string()],
                created_by: Some("se_example".to_string()),
                purpose: Some("Secure document signing".to_string()),
            }),
        },
        Some(VendorParams::Apple(SecureEnclaveParams {
            require_biometric: true,                    // Require Touch/Face ID
            label: Some("My App Signing Key".to_string()), // Human-readable label
            access_group: Some("com.myapp.keys".to_string()), // App group sharing
            access_control: Some(AccessConstraint {
                user_presence: true,      // Require user presence
                device_passcode: false,   // Don't require passcode
                biometry_any: true,       // Accept any enrolled biometry
                biometry_current_set: false, // Don't require current biometry set
            }),
            ..Default::default()
        })),
    ).await?;

    println!("✅ Key generated in Secure Enclave");
    println!("   Key ID: {}", se_key.id);
    println!("   Algorithm: {:?}", se_key.algorithm);
    println!("   Hardware-backed: {}", se_key.hardware_backed);

    // Get Secure Enclave device attestation
    println!("\n2. Getting device attestation...");
    
    let device_attestation = crypto_tee.get_device_attestation().await?;
    println!("✅ Device attestation obtained");
    println!("   Format: {:?}", device_attestation.format);
    
    // Get key-specific attestation
    let key_attestation = crypto_tee.get_key_attestation("secure-enclave-key").await?;
    println!("✅ Key attestation obtained");
    println!("   Format: {:?}", key_attestation.format);
    println!("   Certificate chain length: {}", key_attestation.certificates.len());

    // Sign with Secure Enclave (will trigger biometric prompt)
    println!("\n3. Signing with Secure Enclave...");
    #[cfg(target_os = "macos")]
    println!("🔐 Touch ID authentication may be required...");
    #[cfg(target_os = "ios")]
    println!("🔐 Touch ID/Face ID authentication may be required...");
    
    let message = b"Secure message requiring Secure Enclave protection";
    let signature = crypto_tee.sign("secure-enclave-key", message, None).await?;
    
    println!("✅ Message signed with Secure Enclave");
    println!("   Signature length: {} bytes", signature.data.len());
    println!("   Algorithm: {:?}", signature.algorithm);

    // Verify signature
    println!("\n4. Verifying signature...");
    
    let is_valid = crypto_tee.verify(
        "secure-enclave-key", 
        message, 
        &signature, 
        None
    ).await?;
    
    println!("✅ Signature verification: {}", if is_valid { "VALID" } else { "INVALID" });

    // Demonstrate public key export (private key stays in Secure Enclave)
    println!("\n5. Exporting public key...");
    
    let public_key = crypto_tee.export_public_key("secure-enclave-key").await?;
    println!("✅ Public key exported ({} bytes)", public_key.len());
    println!("   Private key remains in Secure Enclave");

    // Show key information
    println!("\n6. Key information...");
    
    let key_info = crypto_tee.get_key_info("secure-enclave-key").await?;
    println!("✅ Key information:");
    println!("   Created: {:?}", key_info.metadata.created_at);
    println!("   Algorithm: {:?}", key_info.algorithm);
    println!("   Usage: {:?}", key_info.usage);
    println!("   Requires auth: {}", key_info.requires_auth);
    
    if let Some(ref description) = key_info.metadata.description {
        println!("   Description: {}", description);
    }

    // Secure Enclave capabilities
    println!("\n7. Secure Enclave capabilities...");
    
    let se_vendor = crypto_tee.get_vendor("Apple Secure Enclave").await?;
    let se_caps = se_vendor.probe().await?;
    
    println!("✅ Secure Enclave capabilities:");
    println!("   Version: {}", se_caps.version);
    println!("   Max keys: {}", se_caps.max_keys);
    println!("   Supported algorithms: {:?}", se_caps.algorithms);
    println!("   Features:");
    println!("     - Hardware-backed: {}", se_caps.features.hardware_backed);
    println!("     - Key import: {}", se_caps.features.secure_key_import);
    println!("     - Key export: {}", se_caps.features.secure_key_export);
    println!("     - Attestation: {}", se_caps.features.attestation);
    println!("     - Biometric bound: {}", se_caps.features.biometric_bound);
    println!("     - Secure deletion: {}", se_caps.features.secure_deletion);

    // Performance demonstration
    println!("\n8. Performance test...");
    
    let start = std::time::Instant::now();
    let test_data = b"Performance test data";
    let perf_signature = crypto_tee.sign("secure-enclave-key", test_data, None).await?;
    let sign_time = start.elapsed();
    
    let start = std::time::Instant::now();
    let _is_valid = crypto_tee.verify("secure-enclave-key", test_data, &perf_signature, None).await?;
    let verify_time = start.elapsed();
    
    println!("✅ Performance results:");
    println!("   Sign time: {:?}", sign_time);
    println!("   Verify time: {:?}", verify_time);

    // Security reminders
    println!("\n🔒 Secure Enclave Security Features:");
    println!("   • Private keys never leave the Secure Enclave");
    println!("   • Hardware-isolated secure processor");
    println!("   • Biometric authentication protection");
    println!("   • No key extraction possible");
    println!("   • Hardware-backed attestation");
    println!("   • Automatic secure deletion on tampering");
    
    #[cfg(target_os = "macos")]
    println!("   • T2 or Apple Silicon security chip");
    #[cfg(target_os = "ios")]
    println!("   • A7 or later secure processor");

    println!("\n✅ Secure Enclave example completed successfully!");
    
    Ok(())
}