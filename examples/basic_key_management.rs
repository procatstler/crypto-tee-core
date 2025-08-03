//! Basic key management example
//!
//! This example demonstrates fundamental key management operations:
//! - Generating keys
//! - Listing keys
//! - Getting key information
//! - Deleting keys

use crypto_tee::{Algorithm, CryptoTEE, CryptoTEEBuilder, KeyOptions, KeyUsage};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("CryptoTEE Basic Key Management Example\n");

    // Create CryptoTEE instance with auto-detection
    println!("Initializing CryptoTEE...");
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // List capabilities
    println!("\nAvailable capabilities:");
    let capabilities = crypto_tee.list_capabilities().await?;
    for cap in &capabilities {
        println!("  - {}", cap);
    }

    // Generate different types of keys
    println!("\nGenerating keys...");

    // 1. Ed25519 signing key
    let signing_key = crypto_tee
        .generate_key(
            "example-signing-key",
            KeyOptions {
                algorithm: Algorithm::Ed25519,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: false,
                expires_at: None,
            },
        )
        .await?;
    println!("✓ Generated signing key: {}", signing_key.alias);

    // 2. ECDSA P-256 key with authentication
    let auth_key = crypto_tee
        .generate_key(
            "example-auth-key",
            KeyOptions {
                algorithm: Algorithm::EcdsaP256,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: true, // Requires biometric/PIN
                expires_at: None,
            },
        )
        .await?;
    println!("✓ Generated authenticated key: {}", auth_key.alias);

    // 3. RSA key for compatibility
    let rsa_key = crypto_tee
        .generate_key(
            "example-rsa-key",
            KeyOptions {
                algorithm: Algorithm::Rsa2048,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: false,
                expires_at: None,
            },
        )
        .await?;
    println!("✓ Generated RSA key: {}", rsa_key.alias);

    // List all keys
    println!("\nListing all keys:");
    let keys = crypto_tee.list_keys().await?;
    for key in &keys {
        println!(
            "  - {} ({:?}) - Hardware: {}, Auth Required: {}",
            key.alias, key.algorithm, key.hardware_backed, key.requires_auth
        );
    }

    // Get detailed information about a specific key
    println!("\nKey information for '{}':", signing_key.alias);
    let key_info = crypto_tee.get_key_info(&signing_key.alias).await?;
    println!("  Algorithm: {:?}", key_info.algorithm);
    println!("  Created: {:?}", key_info.created_at);
    println!("  Hardware-backed: {}", key_info.hardware_backed);
    println!("  Requires auth: {}", key_info.requires_auth);

    // Demonstrate key usage
    println!("\nUsing signing key...");
    let message = b"Hello, CryptoTEE!";
    let signature = crypto_tee.sign(&signing_key.alias, message, None).await?;
    println!("  ✓ Signed message (signature length: {} bytes)", signature.len());

    // Verify the signature
    let is_valid = crypto_tee
        .verify(&signing_key.alias, message, &signature, None)
        .await?;
    println!("  ✓ Signature verified: {}", is_valid);

    // Clean up: Delete keys
    println!("\nCleaning up keys...");
    for key in &keys {
        crypto_tee.delete_key(&key.alias).await?;
        println!("  ✓ Deleted key: {}", key.alias);
    }

    // Verify keys are deleted
    let remaining_keys = crypto_tee.list_keys().await?;
    println!("\nRemaining keys: {}", remaining_keys.len());

    println!("\nExample completed successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_key_lifecycle() {
        // Create CryptoTEE instance
        let crypto_tee = CryptoTEEBuilder::new().build().await.unwrap();

        // Generate a key
        let key = crypto_tee
            .generate_key(
                "test-key",
                KeyOptions {
                    algorithm: Algorithm::Ed25519,
                    usage: KeyUsage::SIGN_VERIFY,
                    extractable: false,
                    hardware_backed: false, // Use software for tests
                    require_auth: false,
                    expires_at: None,
                },
            )
            .await
            .unwrap();

        // Verify key exists
        let keys = crypto_tee.list_keys().await.unwrap();
        assert!(keys.iter().any(|k| k.alias == "test-key"));

        // Delete key
        crypto_tee.delete_key(&key.alias).await.unwrap();

        // Verify key is deleted
        let keys = crypto_tee.list_keys().await.unwrap();
        assert!(!keys.iter().any(|k| k.alias == "test-key"));
    }
}