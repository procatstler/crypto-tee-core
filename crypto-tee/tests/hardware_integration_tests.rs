//! Hardware-specific integration tests for vendor TEE implementations
//!
//! This module contains tests for different hardware TEE implementations.
//! Tests are designed to work with software fallback when hardware is not available.

use crypto_tee::{Algorithm, CryptoTEE, CryptoTEEBuilder, KeyOptions, KeyUsage};
use std::time::Duration;

/// Test hardware TEE functionality with software fallback
#[tokio::test]
async fn test_hardware_key_generation_with_fallback() {
    let crypto_tee =
        CryptoTEEBuilder::new().build().await.expect("Should initialize CryptoTEE with fallback");

    let key_options = KeyOptions {
        algorithm: Algorithm::EcdsaP256,
        usage: KeyUsage::default(),
        hardware_backed: false,
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };

    // Generate key (will use software fallback in CI)
    let key = crypto_tee
        .generate_key("hardware_test_key", key_options)
        .await
        .expect("Should generate test key with fallback");

    assert_eq!(key.metadata.algorithm, Algorithm::EcdsaP256);
    assert_eq!(key.alias, "hardware_test_key");

    // Test signing
    let test_data = b"Hardware integration test data";
    let signature =
        crypto_tee.sign("hardware_test_key", test_data, None).await.expect("Should sign test data");

    assert!(!signature.is_empty());

    // Test verification
    let is_valid = crypto_tee
        .verify("hardware_test_key", test_data, &signature, None)
        .await
        .expect("Should verify signature");
    assert!(is_valid, "Signature should be valid");

    // Test key info
    let key_info = crypto_tee.get_key_info("hardware_test_key").await.expect("Should get key info");
    assert_eq!(key_info.algorithm, Algorithm::EcdsaP256);
    assert!(!key_info.requires_auth);

    println!("✅ Hardware integration test with fallback completed");

    // Cleanup
    crypto_tee.delete_key("hardware_test_key").await.expect("Should cleanup test key");
}

/// Test cross-platform compatibility
#[tokio::test]
async fn test_cross_platform_key_operations() {
    let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Should initialize CryptoTEE");

    // Test different algorithms for cross-platform compatibility
    let test_algorithms = vec![Algorithm::Ed25519, Algorithm::EcdsaP256];

    for algorithm in test_algorithms {
        let key_alias = format!("cross_platform_{algorithm:?}");

        let key_options = KeyOptions {
            algorithm,
            usage: KeyUsage::default(),
            hardware_backed: false,
            exportable: true,
            require_auth: false,
            expires_at: None,
            metadata: None,
        };

        // Generate key
        let key = crypto_tee
            .generate_key(&key_alias, key_options)
            .await
            .expect("Should generate cross-platform key");

        assert_eq!(key.metadata.algorithm, algorithm);

        // Test operations
        let test_data = format!("Cross-platform test for {algorithm:?}");
        let signature = crypto_tee
            .sign(&key_alias, test_data.as_bytes(), None)
            .await
            .expect("Should sign with cross-platform key");

        let is_valid = crypto_tee
            .verify(&key_alias, test_data.as_bytes(), &signature, None)
            .await
            .expect("Should verify cross-platform signature");

        assert!(is_valid, "Cross-platform signature should be valid for {algorithm:?}");

        println!("✅ Cross-platform compatibility verified for {algorithm:?}");

        // Cleanup
        crypto_tee.delete_key(&key_alias).await.expect("Should cleanup test key");
    }
}

/// Test performance with multiple keys and operations
#[tokio::test]
async fn test_hardware_performance_simulation() {
    let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Should initialize CryptoTEE");

    let key_options = KeyOptions {
        algorithm: Algorithm::Ed25519, // Use fast algorithm for performance test
        usage: KeyUsage::default(),
        hardware_backed: false,
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };

    // Generate test key
    let _key = crypto_tee
        .generate_key("perf_test_key", key_options)
        .await
        .expect("Should generate performance test key");

    // Performance measurements
    let test_data = b"Performance test data";
    let iterations = 50;
    let mut sign_times = Vec::new();
    let mut verify_times = Vec::new();

    for _ in 0..iterations {
        // Measure signing time
        let start = std::time::Instant::now();
        let signature = crypto_tee
            .sign("perf_test_key", test_data, None)
            .await
            .expect("Should sign for performance test");
        sign_times.push(start.elapsed());

        // Measure verification time
        let start = std::time::Instant::now();
        let is_valid = crypto_tee
            .verify("perf_test_key", test_data, &signature, None)
            .await
            .expect("Should verify for performance test");
        verify_times.push(start.elapsed());

        assert!(is_valid, "Performance test signature should be valid");
    }

    // Calculate averages
    let avg_sign_time = sign_times.iter().sum::<Duration>() / iterations as u32;
    let avg_verify_time = verify_times.iter().sum::<Duration>() / iterations as u32;

    println!("🏃 Hardware Performance Simulation Results:");
    println!("   Average sign time: {avg_sign_time:?}");
    println!("   Average verify time: {avg_verify_time:?}");

    // Basic performance assertions
    assert!(
        avg_sign_time < Duration::from_millis(100),
        "Average signing should be reasonable: {avg_sign_time:?}"
    );
    assert!(
        avg_verify_time < Duration::from_millis(50),
        "Average verification should be reasonable: {avg_verify_time:?}"
    );

    // Cleanup
    crypto_tee.delete_key("perf_test_key").await.expect("Should cleanup test key");
}

/// Test sequential operations simulation (simulating concurrency)
#[tokio::test]
async fn test_concurrent_hardware_operations() {
    let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Should initialize CryptoTEE");

    // Generate multiple keys sequentially (simulating concurrent operations)
    let key_count = 10;
    let mut key_aliases = Vec::new();

    for i in 0..key_count {
        let key_alias = format!("concurrent_key_{i}");

        let key_options = KeyOptions {
            algorithm: Algorithm::Ed25519,
            usage: KeyUsage::default(),
            hardware_backed: false,
            exportable: false,
            require_auth: false,
            expires_at: None,
            metadata: None,
        };

        crypto_tee
            .generate_key(&key_alias, key_options)
            .await
            .expect("Should generate concurrent key");

        // Test signing with this key
        let test_data = format!("Concurrent test data {i}");
        let signature = crypto_tee
            .sign(&key_alias, test_data.as_bytes(), None)
            .await
            .expect("Should sign with concurrent key");

        let is_valid = crypto_tee
            .verify(&key_alias, test_data.as_bytes(), &signature, None)
            .await
            .expect("Should verify concurrent signature");
        assert!(is_valid);

        key_aliases.push(key_alias);
    }

    // Cleanup all keys
    for key_alias in key_aliases {
        crypto_tee.delete_key(&key_alias).await.expect("Should cleanup concurrent test key");
    }

    println!("✅ Concurrent hardware operations simulation completed: {key_count} keys");
}

/// Test error handling and edge cases
#[tokio::test]
async fn test_hardware_error_handling() {
    let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Should initialize CryptoTEE");

    // Test operations on non-existent key
    let result = crypto_tee.get_key_info("non_existent_key").await;
    assert!(result.is_err(), "Should fail for non-existent key");

    let result = crypto_tee.sign("non_existent_key", b"test", None).await;
    assert!(result.is_err(), "Should fail to sign with non-existent key");

    let result = crypto_tee.delete_key("non_existent_key").await;
    assert!(result.is_err(), "Should fail to delete non-existent key");

    // Test duplicate key generation
    let key_options = KeyOptions::default();

    let _key = crypto_tee
        .generate_key("duplicate_test", key_options.clone())
        .await
        .expect("First key generation should succeed");

    let result = crypto_tee.generate_key("duplicate_test", key_options).await;
    assert!(result.is_err(), "Duplicate key generation should fail");

    // Cleanup
    crypto_tee.delete_key("duplicate_test").await.expect("Should cleanup duplicate test");

    println!("✅ Hardware error handling tests completed");
}

/// Test platform capabilities using the documented API
#[tokio::test]
async fn test_platform_capabilities() {
    let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Should initialize CryptoTEE");

    // List capabilities
    let capabilities = crypto_tee.list_capabilities().await.expect("Should list capabilities");

    assert!(!capabilities.is_empty());
    println!("🔍 Platform Capabilities:");
    for capability in &capabilities {
        println!("   - {capability}");
    }

    // Test that we can list keys (should be empty initially)
    let keys = crypto_tee.list_keys().await.expect("Should list keys");

    let key_count = keys.len();
    println!("   Current keys: {key_count}");

    println!("✅ Platform capabilities test completed");
}
