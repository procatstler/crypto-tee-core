//! Samsung Knox Vault Example
//!
//! This example demonstrates how to use Samsung Knox Vault for maximum security
//! on Samsung Android devices.

use crypto_tee::prelude::*;
use crypto_tee_vendor::samsung::KnoxParams;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Samsung Knox Vault Example");
    println!("==========================");

    // Initialize CryptoTEE
    let crypto_tee = CryptoTEEBuilder::new()
        .prefer_hardware(true)
        .build()
        .await?;

    // Check if Knox is available
    let platform_info = crypto_tee.get_platform_info().await?;
    println!("Platform: {} v{}", platform_info.name, platform_info.version);

    let vendors = crypto_tee.list_available_vendors().await?;
    let knox_available = vendors.iter().any(|v| v.name.contains("Knox"));
    
    if !knox_available {
        println!("⚠️  Samsung Knox not available on this device");
        println!("This example requires a Samsung device with Knox support");
        return Ok(());
    }

    println!("✅ Samsung Knox detected");

    // Generate key with Knox Vault
    println!("\n1. Generating key in Knox Vault...");
    
    let knox_key = crypto_tee.generate_key_with_vendor_params(
        "knox-vault-signing-key",
        KeyOptions {
            algorithm: Algorithm::EcdsaP256,
            usage: KeyUsage::SIGN_VERIFY,
            hardware_backed: true,
            exportable: false,  // Non-extractable for maximum security
            require_auth: true, // Require biometric/PIN
            expires_at: None,   // No expiration
            metadata: Some(KeyMetadata {
                description: Some("Knox Vault signing key".to_string()),
                tags: vec!["knox".to_string(), "high-security".to_string()],
                created_by: Some("knox_example".to_string()),
                purpose: Some("Document signing".to_string()),
            }),
        },
        Some(VendorParams::Samsung(KnoxParams {
            use_knox_vault: true,           // Store in Knox Vault (highest security)
            require_user_auth: true,        // Require biometric or PIN
            auth_validity_seconds: Some(300), // Auth valid for 5 minutes
            use_trustzone: true,            // Use ARM TrustZone TEE
            enable_attestation: true,       // Enable key attestation
            container_id: None,             // Use default Knox container
        })),
    ).await?;

    println!("✅ Key generated in Knox Vault");
    println!("   Key ID: {}", knox_key.id);
    println!("   Algorithm: {:?}", knox_key.algorithm);
    println!("   Hardware-backed: {}", knox_key.hardware_backed);

    // Get Knox key attestation
    println!("\n2. Getting Knox attestation...");
    
    let attestation = crypto_tee.get_key_attestation("knox-vault-signing-key").await?;
    println!("✅ Attestation obtained");
    println!("   Format: {:?}", attestation.format);
    println!("   Certificate chain length: {}", attestation.certificates.len());
    println!("   Attestation data size: {} bytes", attestation.data.len());

    // Sign document with Knox key (will require biometric/PIN)
    println!("\n3. Signing document with Knox key...");
    println!("📱 Biometric authentication may be required...");
    
    let document = b"Important contract that requires Knox-level security";
    let signature = crypto_tee.sign("knox-vault-signing-key", document, None).await?;
    
    println!("✅ Document signed with Knox Vault key");
    println!("   Signature length: {} bytes", signature.data.len());
    println!("   Algorithm: {:?}", signature.algorithm);

    // Verify signature
    println!("\n4. Verifying signature...");
    
    let is_valid = crypto_tee.verify(
        "knox-vault-signing-key", 
        document, 
        &signature, 
        None
    ).await?;
    
    println!("✅ Signature verification: {}", if is_valid { "VALID" } else { "INVALID" });

    // Display key information
    println!("\n5. Key information...");
    
    let key_info = crypto_tee.get_key_info("knox-vault-signing-key").await?;
    println!("✅ Key information retrieved");
    println!("   Created: {:?}", key_info.metadata.created_at);
    println!("   Last used: {:?}", key_info.metadata.last_used);
    println!("   Usage count: {:?}", key_info.metadata.usage_count);
    
    if let Some(ref description) = key_info.metadata.description {
        println!("   Description: {}", description);
    }
    
    if !key_info.metadata.tags.is_empty() {
        println!("   Tags: {:?}", key_info.metadata.tags);
    }

    // Knox-specific security features
    println!("\n6. Knox security features...");
    
    // Get vendor-specific information
    let knox_vendor = crypto_tee.get_vendor("Samsung Knox").await?;
    let knox_caps = knox_vendor.probe().await?;
    
    println!("✅ Knox capabilities:");
    println!("   Version: {}", knox_caps.version);
    println!("   Max keys: {}", knox_caps.max_keys);
    println!("   Hardware-backed: {}", knox_caps.hardware_backed);
    println!("   Attestation: {}", knox_caps.attestation);
    println!("   Features:");
    println!("     - Knox Vault: {}", knox_caps.features.strongbox);
    println!("     - Secure import: {}", knox_caps.features.secure_key_import);
    println!("     - Biometric bound: {}", knox_caps.features.biometric_bound);
    println!("     - Secure deletion: {}", knox_caps.features.secure_deletion);

    // Demonstrate key rotation (optional)
    println!("\n7. Key management...");
    
    // List all keys
    let keys = crypto_tee.list_keys(None).await?;
    println!("✅ Total keys in store: {}", keys.len());
    
    for key in &keys {
        if key.vendor == "Samsung Knox" {
            println!("   Knox key: {} ({:?})", key.id, key.algorithm);
        }
    }

    // Security best practices reminder
    println!("\n🔒 Knox Security Best Practices:");
    println!("   • Keys are stored in hardware-isolated Knox Vault");
    println!("   • Private keys never leave the secure hardware");
    println!("   • Biometric authentication protects key usage");
    println!("   • Attestation proves hardware security");
    println!("   • TrustZone provides additional isolation");
    println!("   • Regular Samsung security updates protect the TEE");

    println!("\n✅ Knox Vault example completed successfully!");
    
    Ok(())
}