//! Digital signature and verification example
//!
//! This example demonstrates:
//! - Creating signatures with different algorithms
//! - Verifying signatures
//! - Handling signature formats
//! - Cross-key verification

use crypto_tee::{Algorithm, CryptoTEE, CryptoTEEBuilder, KeyOptions, KeyUsage};
use std::error::Error;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    println!("CryptoTEE Digital Signature Example\n");

    // Initialize CryptoTEE
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Test data to sign
    let short_message = b"Hello, World!";
    let long_message = b"The quick brown fox jumps over the lazy dog. \
                        The quick brown fox jumps over the lazy dog. \
                        The quick brown fox jumps over the lazy dog.";

    // Generate keys with different algorithms
    println!("Generating keys with different algorithms...\n");

    let ed25519_key = crypto_tee
        .generate_key(
            "ed25519-signing-key",
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

    let ecdsa_key = crypto_tee
        .generate_key(
            "ecdsa-p256-signing-key",
            KeyOptions {
                algorithm: Algorithm::EcdsaP256,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: false,
                expires_at: None,
            },
        )
        .await?;

    let rsa_key = crypto_tee
        .generate_key(
            "rsa-2048-signing-key",
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

    // Test signing and verification with each algorithm
    println!("Testing signature algorithms:\n");

    // Ed25519
    println!("Ed25519 Signatures:");
    test_algorithm(&crypto_tee, &ed25519_key.alias, short_message).await?;
    test_algorithm(&crypto_tee, &ed25519_key.alias, long_message).await?;

    // ECDSA P-256
    println!("\nECDSA P-256 Signatures:");
    test_algorithm(&crypto_tee, &ecdsa_key.alias, short_message).await?;
    test_algorithm(&crypto_tee, &ecdsa_key.alias, long_message).await?;

    // RSA-2048
    println!("\nRSA-2048 Signatures:");
    test_algorithm(&crypto_tee, &rsa_key.alias, short_message).await?;
    test_algorithm(&crypto_tee, &rsa_key.alias, long_message).await?;

    // Performance comparison
    println!("\nPerformance Comparison:");
    benchmark_signing(&crypto_tee, &ed25519_key.alias, "Ed25519", short_message).await?;
    benchmark_signing(&crypto_tee, &ecdsa_key.alias, "ECDSA P-256", short_message).await?;
    benchmark_signing(&crypto_tee, &rsa_key.alias, "RSA-2048", short_message).await?;

    // Signature format information
    println!("\nSignature Formats:");
    let ed_sig = crypto_tee.sign(&ed25519_key.alias, short_message, None).await?;
    let ec_sig = crypto_tee.sign(&ecdsa_key.alias, short_message, None).await?;
    let rsa_sig = crypto_tee.sign(&rsa_key.alias, short_message, None).await?;

    println!("  Ed25519: {} bytes (fixed size)", ed_sig.len());
    println!("  ECDSA P-256: {} bytes (DER encoded)", ec_sig.len());
    println!("  RSA-2048: {} bytes (PKCS#1 v1.5)", rsa_sig.len());

    // Demonstrate signature verification failure
    println!("\nDemonstrating signature verification failure:");
    let tampered_message = b"Hello, World?"; // Different message
    let valid = crypto_tee
        .verify(&ed25519_key.alias, tampered_message, &ed_sig, None)
        .await?;
    println!("  Verification with tampered message: {}", valid);

    // Demonstrate invalid signature
    let mut invalid_sig = ed_sig.clone();
    invalid_sig[0] ^= 0xFF; // Flip bits
    let valid = crypto_tee
        .verify(&ed25519_key.alias, short_message, &invalid_sig, None)
        .await?;
    println!("  Verification with invalid signature: {}", valid);

    // Clean up
    println!("\nCleaning up...");
    crypto_tee.delete_key(&ed25519_key.alias).await?;
    crypto_tee.delete_key(&ecdsa_key.alias).await?;
    crypto_tee.delete_key(&rsa_key.alias).await?;

    println!("\nExample completed successfully!");
    Ok(())
}

async fn test_algorithm(
    crypto_tee: &impl CryptoTEE,
    key_alias: &str,
    message: &[u8],
) -> Result<(), Box<dyn Error>> {
    // Sign the message
    let signature = crypto_tee.sign(key_alias, message, None).await?;

    // Verify the signature
    let is_valid = crypto_tee
        .verify(key_alias, message, &signature, None)
        .await?;

    println!(
        "  Message ({} bytes) -> Signature ({} bytes) - Valid: {}",
        message.len(),
        signature.len(),
        is_valid
    );

    Ok(())
}

async fn benchmark_signing(
    crypto_tee: &impl CryptoTEE,
    key_alias: &str,
    algorithm_name: &str,
    message: &[u8],
) -> Result<(), Box<dyn Error>> {
    const ITERATIONS: u32 = 10;

    // Benchmark signing
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = crypto_tee.sign(key_alias, message, None).await?;
    }
    let sign_duration = start.elapsed();
    let sign_avg = sign_duration.as_micros() as f64 / ITERATIONS as f64;

    // Get one signature for verification benchmark
    let signature = crypto_tee.sign(key_alias, message, None).await?;

    // Benchmark verification
    let start = Instant::now();
    for _ in 0..ITERATIONS {
        let _ = crypto_tee
            .verify(key_alias, message, &signature, None)
            .await?;
    }
    let verify_duration = start.elapsed();
    let verify_avg = verify_duration.as_micros() as f64 / ITERATIONS as f64;

    println!(
        "  {:<12} - Sign: {:.2} µs, Verify: {:.2} µs",
        algorithm_name, sign_avg, verify_avg
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_signature_verification() {
        let crypto_tee = CryptoTEEBuilder::new().build().await.unwrap();

        // Generate a key
        let key = crypto_tee
            .generate_key(
                "test-sig-key",
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

        // Test data
        let message = b"Test message";

        // Sign
        let signature = crypto_tee.sign(&key.alias, message, None).await.unwrap();

        // Verify - should succeed
        let valid = crypto_tee
            .verify(&key.alias, message, &signature, None)
            .await
            .unwrap();
        assert!(valid);

        // Verify with wrong message - should fail
        let wrong_message = b"Wrong message";
        let valid = crypto_tee
            .verify(&key.alias, wrong_message, &signature, None)
            .await
            .unwrap();
        assert!(!valid);

        // Clean up
        crypto_tee.delete_key(&key.alias).await.unwrap();
    }
}