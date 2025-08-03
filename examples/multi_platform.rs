//! Multi-platform key management example
//!
//! This example demonstrates how to use CryptoTEE across different platforms
//! with automatic vendor selection and fallback mechanisms.

use crypto_tee::{
    Algorithm, CryptoTEE, CryptoTEEBuilder, KeyOptions, KeyUsage, PlatformConfig,
};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    println!("CryptoTEE Multi-Platform Example\n");

    // Example 1: Auto-detect best vendor
    println!("Example 1: Auto-detection");
    auto_detect_example().await?;

    // Example 2: Platform-specific configuration
    println!("\nExample 2: Platform-specific configuration");
    platform_specific_example().await?;

    // Example 3: Fallback handling
    println!("\nExample 3: Fallback handling");
    fallback_example().await?;

    // Example 4: Cross-platform key migration
    println!("\nExample 4: Cross-platform key migration");
    key_migration_example().await?;

    println!("\nExample completed successfully!");
    Ok(())
}

async fn auto_detect_example() -> Result<(), Box<dyn Error>> {
    // Create with auto-detection
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Check what was detected
    let capabilities = crypto_tee.list_capabilities().await?;
    println!("  Detected capabilities:");
    for cap in &capabilities {
        if cap.contains("vendor:") || cap.contains("hardware") {
            println!("    - {}", cap);
        }
    }

    // Generate a key using detected vendor
    let key = crypto_tee
        .generate_key(
            "auto-detected-key",
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

    println!("  ✓ Created key with auto-detected vendor");

    // Clean up
    crypto_tee.delete_key(&key.alias).await?;

    Ok(())
}

async fn platform_specific_example() -> Result<(), Box<dyn Error>> {
    // Platform-specific configurations
    let configs = vec![
        (
            "Apple Priority",
            PlatformConfig {
                auto_detect: true,
                preferred_vendor: Some("apple".to_string()),
                fallback_to_software: true,
                cache_keys: true,
            },
        ),
        (
            "Samsung Priority",
            PlatformConfig {
                auto_detect: true,
                preferred_vendor: Some("samsung".to_string()),
                fallback_to_software: true,
                cache_keys: true,
            },
        ),
        (
            "Software Only",
            PlatformConfig {
                auto_detect: false,
                preferred_vendor: Some("software".to_string()),
                fallback_to_software: true,
                cache_keys: false,
            },
        ),
    ];

    for (name, config) in configs {
        println!("\n  Testing configuration: {}", name);

        match CryptoTEEBuilder::new()
            .with_platform_config(config)
            .build()
            .await
        {
            Ok(crypto_tee) => {
                // Check vendor
                let caps = crypto_tee.list_capabilities().await?;
                let vendor = caps
                    .iter()
                    .find(|c| c.starts_with("vendor:"))
                    .map(|c| c.trim_start_matches("vendor:"))
                    .unwrap_or("unknown");
                println!("    ✓ Using vendor: {}", vendor);

                // Test key generation
                let key = crypto_tee
                    .generate_key(
                        &format!("{}-test-key", name.to_lowercase().replace(' ', "-")),
                        KeyOptions {
                            algorithm: Algorithm::Ed25519,
                            usage: KeyUsage::SIGN_VERIFY,
                            extractable: false,
                            hardware_backed: vendor != "software",
                            require_auth: false,
                            expires_at: None,
                        },
                    )
                    .await?;

                crypto_tee.delete_key(&key.alias).await?;
            }
            Err(e) => {
                println!("    ✗ Configuration not available: {}", e);
            }
        }
    }

    Ok(())
}

async fn fallback_example() -> Result<(), Box<dyn Error>> {
    // Try hardware first, fall back to software
    let config = PlatformConfig {
        auto_detect: true,
        preferred_vendor: Some("hardware".to_string()), // Prefer any hardware
        fallback_to_software: true,
        cache_keys: true,
    };

    let crypto_tee = CryptoTEEBuilder::new()
        .with_platform_config(config)
        .build()
        .await?;

    // Try to create hardware-backed key
    match crypto_tee
        .generate_key(
            "hardware-preferred-key",
            KeyOptions {
                algorithm: Algorithm::Ed25519,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: false,
                expires_at: None,
            },
        )
        .await
    {
        Ok(key) => {
            let info = crypto_tee.get_key_info(&key.alias).await?;
            println!(
                "  ✓ Created key - Hardware-backed: {}",
                info.hardware_backed
            );
            crypto_tee.delete_key(&key.alias).await?;
        }
        Err(e) => {
            println!("  ✗ Hardware key creation failed: {}", e);

            // Try software fallback
            let key = crypto_tee
                .generate_key(
                    "software-fallback-key",
                    KeyOptions {
                        algorithm: Algorithm::Ed25519,
                        usage: KeyUsage::SIGN_VERIFY,
                        extractable: false,
                        hardware_backed: false,
                        require_auth: false,
                        expires_at: None,
                    },
                )
                .await?;

            println!("  ✓ Created software-backed key as fallback");
            crypto_tee.delete_key(&key.alias).await?;
        }
    }

    Ok(())
}

async fn key_migration_example() -> Result<(), Box<dyn Error>> {
    println!("  Demonstrating key migration between platforms:");

    // Create source platform (software for portability)
    let source_config = PlatformConfig {
        auto_detect: false,
        preferred_vendor: Some("software".to_string()),
        fallback_to_software: true,
        cache_keys: false,
    };

    let source_tee = CryptoTEEBuilder::new()
        .with_platform_config(source_config)
        .build()
        .await?;

    // Generate exportable key
    let source_key = source_tee
        .generate_key(
            "migration-source-key",
            KeyOptions {
                algorithm: Algorithm::Ed25519,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: true, // Must be exportable
                hardware_backed: false,
                require_auth: false,
                expires_at: None,
            },
        )
        .await?;

    println!("  ✓ Created exportable key on source platform");

    // Sign test data with source key
    let test_data = b"Migration test data";
    let signature = source_tee.sign(&source_key.alias, test_data, None).await?;
    println!("  ✓ Signed data with source key");

    // Export key (in real scenario, this would use export_key method)
    // For this example, we'll simulate by using the same key data
    let exported_key_data = b"<exported-key-data>"; // Placeholder

    // Create destination platform
    let dest_tee = CryptoTEEBuilder::new().build().await?;

    // Import key to destination
    // Note: In real implementation, you'd need to handle key format conversion
    match dest_tee
        .import_key(
            "migration-dest-key",
            exported_key_data,
            KeyOptions {
                algorithm: Algorithm::Ed25519,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true, // Try to import to hardware
                require_auth: false,
                expires_at: None,
            },
        )
        .await
    {
        Ok(_) => {
            println!("  ✓ Successfully imported key to destination platform");
        }
        Err(_) => {
            println!("  ℹ Key import would require actual key data");
        }
    }

    // Clean up
    source_tee.delete_key(&source_key.alias).await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_platform_fallback() {
        // Configure to use software fallback
        let config = PlatformConfig {
            auto_detect: false,
            preferred_vendor: Some("nonexistent".to_string()),
            fallback_to_software: true,
            cache_keys: false,
        };

        // Should fall back to software
        let crypto_tee = CryptoTEEBuilder::new()
            .with_platform_config(config)
            .build()
            .await
            .unwrap();

        // Should be able to create software keys
        let key = crypto_tee
            .generate_key(
                "fallback-test",
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

        crypto_tee.delete_key(&key.alias).await.unwrap();
    }
}