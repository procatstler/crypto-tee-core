//! Comprehensive integration tests for CryptoTEE

mod helpers;

use helpers::{TestHelper, TestConfig, test_scenarios::TestScenarios, test_keys::TestKeyConfigs};
use crypto_tee_vendor::types::Algorithm;

#[tokio::test]
async fn test_all_algorithms_comprehensive() {
    let algorithms = TestKeyConfigs::fast_algorithms(); // Use fast algorithms for CI
    
    for algorithm in algorithms {
        let config = TestConfig {
            algorithm,
            use_hardware_backed: false,
            key_count: 3,
            concurrent_operations: 5,
        };
        
        let helper = TestHelper::with_config(config).await
            .expect("Failed to create test helper");
        
        // Run comprehensive test for this algorithm
        TestScenarios::test_all_algorithms_lifecycle(&helper).await
            .expect(&format!("Algorithm lifecycle test failed for {:?}", algorithm));
    }
}

#[tokio::test]
async fn test_concurrent_operations() {
    let helper = TestHelper::new().await
        .expect("Failed to create test helper");
    
    TestScenarios::test_concurrent_operations(&helper).await
        .expect("Concurrent operations test failed");
}

#[tokio::test]
async fn test_error_handling() {
    let helper = TestHelper::new().await
        .expect("Failed to create test helper");
    
    TestScenarios::test_error_scenarios(&helper).await
        .expect("Error scenarios test failed");
}

#[tokio::test]
async fn test_key_metadata_management() {
    let helper = TestHelper::new().await
        .expect("Failed to create test helper");
    
    TestScenarios::test_key_metadata(&helper).await
        .expect("Key metadata test failed");
}

#[tokio::test]
async fn test_large_data_operations() {
    let helper = TestHelper::new().await
        .expect("Failed to create test helper");
    
    TestScenarios::test_large_data_signing(&helper).await
        .expect("Large data signing test failed");
}

#[tokio::test]
async fn test_key_listing_operations() {
    let helper = TestHelper::new().await
        .expect("Failed to create test helper");
    
    TestScenarios::test_key_listing(&helper).await
        .expect("Key listing test failed");
}

#[tokio::test]
#[ignore] // Ignore by default as it's resource intensive
async fn stress_test_operations() {
    let config = TestConfig {
        algorithm: Algorithm::Ed25519, // Use fast algorithm for stress test
        use_hardware_backed: false,
        key_count: 50,
        concurrent_operations: 20,
    };
    
    let helper = TestHelper::with_config(config).await
        .expect("Failed to create test helper");
    
    TestScenarios::stress_test(&helper).await
        .expect("Stress test failed");
}

#[tokio::test]
async fn test_different_algorithms_interoperability() {
    let helper = TestHelper::new().await
        .expect("Failed to create test helper");
    
    // Test that different algorithm keys can coexist
    let algorithms = vec![Algorithm::Ed25519, Algorithm::EcdsaP256];
    let mut keys = Vec::new();
    
    // Generate all keys using the same helper instance
    for (i, algorithm) in algorithms.iter().enumerate() {
        let alias = format!("interop_key_{}", i);
        
        let options = crypto_tee::types::KeyOptions {
            algorithm: *algorithm,
            hardware_backed: false,
            exportable: true,
            usage: crypto_tee_vendor::types::KeyUsage::default(),
            expires_at: None,
            require_auth: false,
            metadata: None,
        };
        
        helper.crypto_tee.generate_key(&alias, options).await
            .expect("Failed to generate test key");
        
        keys.push((alias, *algorithm));
    }
    
    // Test that each key works with its respective algorithm
    for (alias, algorithm) in &keys {
        let test_data = TestKeyConfigs::test_data_for_algorithm(*algorithm);
        let signature = helper.crypto_tee.sign(alias, &test_data, None).await
            .expect("Failed to sign with algorithm-specific key");
        
        let valid = helper.crypto_tee.verify(alias, &test_data, &signature, None).await
            .expect("Failed to verify algorithm-specific signature");
        
        assert!(valid, "Signature verification failed for algorithm {:?}", algorithm);
    }
    
    // Clean up
    for (alias, _) in &keys {
        helper.crypto_tee.delete_key(alias).await
            .expect("Failed to delete test key");
    }
}

#[tokio::test]
async fn test_key_usage_permissions() {
    use crypto_tee::types::KeyOptions;
    use crypto_tee_vendor::types::KeyUsage;
    
    let helper = TestHelper::new().await
        .expect("Failed to create test helper");
    
    // Create a sign-only key
    let alias = "sign_only_key";
    let options = KeyOptions {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: true,
        usage: KeyUsage {
            sign: true,
            verify: true, // Need verify for our test
            encrypt: false,
            decrypt: false,
            wrap: false,
            unwrap: false,
        },
        expires_at: None,
        require_auth: false,
        metadata: None,
    };
    
    helper.crypto_tee.generate_key(alias, options).await
        .expect("Failed to generate sign-only key");
    
    // Test that signing works
    let test_data = b"test data";
    let signature = helper.crypto_tee.sign(alias, test_data, None).await
        .expect("Signing should work with sign-only key");
    
    let valid = helper.crypto_tee.verify(alias, test_data, &signature, None).await
        .expect("Verification should work");
    
    assert!(valid, "Signature should be valid");
    
    // Clean up
    helper.crypto_tee.delete_key(alias).await
        .expect("Failed to delete test key");
}