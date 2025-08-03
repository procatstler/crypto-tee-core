//! Authentication-required operations example
//!
//! This example demonstrates how to use keys that require user
//! authentication (biometric or PIN) for operations.

use crypto_tee::{
    Algorithm, CryptoTEE, CryptoTEEBuilder, CryptoTEEError, KeyOptions, KeyUsage,
};
use std::error::Error;
use std::io::{self, Write};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    println!("CryptoTEE Authentication Example\n");
    println!("This example demonstrates keys that require user authentication.\n");

    // Initialize CryptoTEE
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Check if authentication is supported
    let capabilities = crypto_tee.list_capabilities().await?;
    let supports_auth = capabilities
        .iter()
        .any(|c| c.contains("auth") || c.contains("biometric"));

    if !supports_auth {
        println!("⚠️  Warning: This platform may not support authentication.");
        println!("   The example will continue but auth may not be enforced.\n");
    }

    // Example 1: Create a key requiring authentication
    println!("Example 1: Creating an authentication-protected key");
    
    let auth_key = crypto_tee
        .generate_key(
            "auth-protected-key",
            KeyOptions {
                algorithm: Algorithm::Ed25519,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: true, // This key requires authentication
                expires_at: None,
            },
        )
        .await?;

    println!("✓ Created key '{}' requiring authentication", auth_key.alias);
    println!("  Hardware-backed: {}", auth_key.metadata.hardware_backed);
    println!("  Requires auth: {}", auth_key.platform_handle.requires_auth);

    // Example 2: Create a normal key for comparison
    println!("\nExample 2: Creating a normal key (no auth required)");
    
    let normal_key = crypto_tee
        .generate_key(
            "normal-key",
            KeyOptions {
                algorithm: Algorithm::Ed25519,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: false, // No authentication required
                expires_at: None,
            },
        )
        .await?;

    println!("✓ Created key '{}' without authentication", normal_key.alias);

    // Example 3: Using the normal key (should work immediately)
    println!("\nExample 3: Using normal key (no authentication needed)");
    
    let data = b"Important document to sign";
    let signature = crypto_tee.sign(&normal_key.alias, data, None).await?;
    println!("✓ Successfully signed with normal key");
    
    let valid = crypto_tee
        .verify(&normal_key.alias, data, &signature, None)
        .await?;
    println!("✓ Signature verified: {}", valid);

    // Example 4: Using the auth-protected key
    println!("\nExample 4: Using auth-protected key");
    println!("⚠️  Authentication may be required for this operation.");
    println!("   On supported devices, you may see a biometric or PIN prompt.");
    
    // Simulate user acknowledgment
    print!("\nPress Enter to attempt signing with auth-protected key...");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;

    match crypto_tee.sign(&auth_key.alias, data, None).await {
        Ok(signature) => {
            println!("✓ Successfully signed with auth-protected key");
            
            // Verify the signature
            let valid = crypto_tee
                .verify(&auth_key.alias, data, &signature, None)
                .await?;
            println!("✓ Signature verified: {}", valid);
        }
        Err(CryptoTEEError::AuthenticationRequired) => {
            println!("✗ Authentication was required but not provided");
            println!("   On a real device, you would see a biometric/PIN prompt");
        }
        Err(e) => {
            println!("✗ Operation failed: {}", e);
        }
    }

    // Example 5: Key usage patterns with authentication
    println!("\nExample 5: Authentication patterns");

    // Pattern 1: High-value operations
    let payment_key = crypto_tee
        .generate_key(
            "payment-signing-key",
            KeyOptions {
                algorithm: Algorithm::EcdsaP256,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: true, // Always require auth for payments
                expires_at: None,
            },
        )
        .await?;

    println!("✓ Created payment signing key (always requires auth)");

    // Pattern 2: Time-based authentication
    let session_key = crypto_tee
        .generate_key(
            "session-key",
            KeyOptions {
                algorithm: Algorithm::Ed25519,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: false, // Could implement time-based auth in plugin
                expires_at: Some(
                    std::time::SystemTime::now() + std::time::Duration::from_secs(3600)
                ),
            },
        )
        .await?;

    println!("✓ Created session key (expires in 1 hour)");

    // Example 6: Handling authentication errors gracefully
    println!("\nExample 6: Error handling for auth-protected operations");

    async fn sign_with_retry(
        crypto_tee: &impl CryptoTEE,
        key_alias: &str,
        data: &[u8],
        max_attempts: u32,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        for attempt in 1..=max_attempts {
            println!("  Attempt {}/{}", attempt, max_attempts);
            
            match crypto_tee.sign(key_alias, data, None).await {
                Ok(signature) => {
                    println!("  ✓ Authentication successful");
                    return Ok(signature);
                }
                Err(CryptoTEEError::AuthenticationRequired) => {
                    if attempt < max_attempts {
                        println!("  ⚠️  Authentication required, please try again");
                        // In a real app, this would trigger UI for auth
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        Err("Maximum authentication attempts exceeded".into())
    }

    // Try signing with retry logic
    match sign_with_retry(&crypto_tee, &payment_key.alias, data, 3).await {
        Ok(_) => println!("✓ Payment signed successfully"),
        Err(e) => println!("✗ Failed to sign payment: {}", e),
    }

    // Clean up
    println!("\nCleaning up...");
    crypto_tee.delete_key(&auth_key.alias).await?;
    crypto_tee.delete_key(&normal_key.alias).await?;
    crypto_tee.delete_key(&payment_key.alias).await?;
    crypto_tee.delete_key(&session_key.alias).await?;

    println!("\nExample completed successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auth_key_creation() {
        let crypto_tee = CryptoTEEBuilder::new().build().await.unwrap();

        // Create auth-required key
        let auth_key = crypto_tee
            .generate_key(
                "test-auth-key",
                KeyOptions {
                    algorithm: Algorithm::Ed25519,
                    usage: KeyUsage::SIGN_VERIFY,
                    extractable: false,
                    hardware_backed: false, // Use software for testing
                    require_auth: true,
                    expires_at: None,
                },
            )
            .await
            .unwrap();

        // Verify auth requirement is set
        assert!(auth_key.platform_handle.requires_auth);

        // Clean up
        crypto_tee.delete_key(&auth_key.alias).await.unwrap();
    }

    #[tokio::test]
    async fn test_auth_vs_normal_key() {
        let crypto_tee = CryptoTEEBuilder::new().build().await.unwrap();

        // Create both types of keys
        let normal_key = crypto_tee
            .generate_key(
                "normal",
                KeyOptions {
                    algorithm: Algorithm::Ed25519,
                    usage: KeyUsage::SIGN_VERIFY,
                    extractable: false,
                    hardware_backed: false,
                    require_auth: false,
                    expires_at: None,
                },
            )
            .await
            .unwrap();

        let auth_key = crypto_tee
            .generate_key(
                "auth",
                KeyOptions {
                    algorithm: Algorithm::Ed25519,
                    usage: KeyUsage::SIGN_VERIFY,
                    extractable: false,
                    hardware_backed: false,
                    require_auth: true,
                    expires_at: None,
                },
            )
            .await
            .unwrap();

        // Normal key should work without auth
        let data = b"test";
        let result = crypto_tee.sign(&normal_key.alias, data, None).await;
        assert!(result.is_ok());

        // Auth key behavior depends on platform support
        // In tests, it might work without actual auth
        let _ = crypto_tee.sign(&auth_key.alias, data, None).await;

        // Clean up
        crypto_tee.delete_key(&normal_key.alias).await.unwrap();
        crypto_tee.delete_key(&auth_key.alias).await.unwrap();
    }
}