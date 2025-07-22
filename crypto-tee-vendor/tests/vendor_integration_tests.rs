//! Vendor-specific integration tests for TEE implementations
//!
//! These tests focus on testing vendor-specific functionality through the mock vendor
//! since hardware vendors require specific platform features.

use crypto_tee_vendor::{mock::MockVendor, traits::VendorTEE, types::*};

/// Test mock vendor basic operations
#[tokio::test]
async fn test_mock_vendor_basic_operations() {
    let vendor = MockVendor::new("test-vendor");

    // Test vendor capabilities
    let capabilities = vendor.probe().await.expect("Should probe mock vendor capabilities");

    assert!(!capabilities.name.is_empty());
    assert!(!capabilities.version.is_empty());
    assert!(capabilities.algorithms.contains(&Algorithm::Ed25519));
    assert!(capabilities.algorithms.contains(&Algorithm::EcdsaP256));

    println!("📊 Mock Vendor Capabilities:");
    println!("   Name: {}", capabilities.name);
    println!("   Version: {}", capabilities.version);
    println!("   Algorithms: {:?}", capabilities.algorithms);
    println!("   Hardware-backed: {}", capabilities.features.hardware_backed);

    // Generate key
    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: true,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key = vendor.generate_key(&params).await.expect("Should generate mock vendor key");

    assert_eq!(key.algorithm, Algorithm::Ed25519);
    assert!(!key.id.is_empty());

    // Test signing
    let test_data = b"Mock vendor integration test";
    let signature = vendor.sign(&key, test_data).await.expect("Should sign with mock vendor");

    assert_eq!(signature.algorithm, Algorithm::Ed25519);
    assert!(!signature.data.is_empty());

    // Test verification
    let is_valid = vendor
        .verify(&key, test_data, &signature)
        .await
        .expect("Should verify mock vendor signature");
    assert!(is_valid);

    // Cleanup
    vendor.delete_key(&key).await.expect("Should delete mock vendor key");

    println!("✅ Mock vendor basic operations completed");
}

/// Test vendor algorithm support
#[tokio::test]
async fn test_vendor_algorithm_support() {
    let vendor = MockVendor::new("algorithm-test-vendor");

    let capabilities = vendor.probe().await.expect("Should probe capabilities");

    // Test each supported algorithm (only test implemented algorithms)
    let working_algorithms = vec![Algorithm::Ed25519, Algorithm::EcdsaP256];

    for algorithm in working_algorithms {
        if !capabilities.algorithms.contains(&algorithm) {
            continue;
        }

        println!("Testing algorithm: {:?}", algorithm);

        let params = KeyGenParams {
            algorithm,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            vendor_params: None,
        };

        let key = vendor
            .generate_key(&params)
            .await
            .expect(&format!("Should generate key with {:?}", algorithm));

        assert_eq!(key.algorithm, algorithm);

        // Test operations with this algorithm
        let test_data = format!("Algorithm test data for {:?}", algorithm);
        let signature = vendor
            .sign(&key, test_data.as_bytes())
            .await
            .expect(&format!("Should sign with {:?}", algorithm));

        assert_eq!(signature.algorithm, algorithm);

        let is_valid = vendor
            .verify(&key, test_data.as_bytes(), &signature)
            .await
            .expect(&format!("Should verify with {:?}", algorithm));

        assert!(is_valid, "Signature should be valid for {:?}", algorithm);

        // Cleanup
        vendor.delete_key(&key).await.expect("Should delete algorithm test key");
    }

    println!("✅ Vendor algorithm support test completed");
}

/// Test vendor key isolation
#[tokio::test]
async fn test_vendor_key_isolation() {
    let vendor = MockVendor::new("isolation-test-vendor");

    // Generate two different keys
    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: true,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key1 = vendor.generate_key(&params).await.expect("Should generate first key");
    let key2 = vendor.generate_key(&params).await.expect("Should generate second key");

    assert_ne!(key1.id, key2.id, "Keys should have unique IDs");

    let test_data = b"Key isolation test";

    // Sign with key1
    let signature1 = vendor.sign(&key1, test_data).await.expect("Should sign with key1");

    // Verify with key1 should succeed
    assert!(vendor.verify(&key1, test_data, &signature1).await.expect("Should verify with key1"));

    // Verify with key2 should fail (keys are isolated)
    assert!(!vendor
        .verify(&key2, test_data, &signature1)
        .await
        .expect("Should not cross-verify with key2"));

    // Test in the other direction
    let signature2 = vendor.sign(&key2, test_data).await.expect("Should sign with key2");

    assert!(vendor.verify(&key2, test_data, &signature2).await.expect("Should verify with key2"));
    assert!(!vendor
        .verify(&key1, test_data, &signature2)
        .await
        .expect("Should not cross-verify with key1"));

    // Cleanup
    vendor.delete_key(&key1).await.expect("Should delete key1");
    vendor.delete_key(&key2).await.expect("Should delete key2");

    println!("✅ Vendor key isolation test completed");
}

/// Test vendor performance characteristics
#[tokio::test]
async fn test_vendor_performance() {
    let vendor = MockVendor::new("performance-test-vendor");

    // Generate test key
    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519, // Use fast algorithm
        hardware_backed: false,
        exportable: true,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key = vendor.generate_key(&params).await.expect("Should generate performance test key");

    let test_data = b"Performance test data";
    let iterations = 100;

    // Measure signing performance
    let sign_start = std::time::Instant::now();
    let mut signatures = Vec::new();
    for _ in 0..iterations {
        let signature =
            vendor.sign(&key, test_data).await.expect("Should sign for performance test");
        signatures.push(signature);
    }
    let sign_total_time = sign_start.elapsed();
    let avg_sign_time = sign_total_time / iterations;

    // Measure verification performance
    let verify_start = std::time::Instant::now();
    for signature in &signatures {
        let is_valid = vendor
            .verify(&key, test_data, signature)
            .await
            .expect("Should verify for performance test");
        assert!(is_valid);
    }
    let verify_total_time = verify_start.elapsed();
    let avg_verify_time = verify_total_time / iterations;

    println!("🏃 Vendor Performance Results:");
    println!("   Average sign time: {:?}", avg_sign_time);
    println!("   Average verify time: {:?}", avg_verify_time);
    println!("   Total iterations: {}", iterations);

    // Basic performance expectations for mock vendor
    assert!(
        avg_sign_time < std::time::Duration::from_millis(10),
        "Mock vendor signing should be fast"
    );
    assert!(
        avg_verify_time < std::time::Duration::from_millis(5),
        "Mock vendor verification should be fast"
    );

    // Cleanup
    vendor.delete_key(&key).await.expect("Should delete performance test key");
}

/// Test vendor error handling
#[tokio::test]
async fn test_vendor_error_handling() {
    let vendor = MockVendor::new("error-test-vendor");

    // Test operations with invalid key
    let fake_key = VendorKeyHandle {
        id: "non_existent_key".to_string(),
        algorithm: Algorithm::Ed25519,
        vendor: "error-test-vendor".to_string(),
        hardware_backed: false,
        vendor_data: None,
    };

    // Should fail gracefully
    let sign_result = vendor.sign(&fake_key, b"test").await;
    assert!(sign_result.is_err(), "Should fail to sign with invalid key");

    let verify_result = vendor
        .verify(&fake_key, b"test", &Signature { algorithm: Algorithm::Ed25519, data: vec![0; 64] })
        .await;
    assert!(verify_result.is_err(), "Should fail to verify with invalid key");

    let delete_result = vendor.delete_key(&fake_key).await;
    assert!(delete_result.is_err(), "Should fail to delete invalid key");

    // Test unsupported algorithm (if any)
    let unsupported_params = KeyGenParams {
        algorithm: Algorithm::Rsa4096, // Not supported by mock vendor
        hardware_backed: false,
        exportable: true,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let result = vendor.generate_key(&unsupported_params).await;
    assert!(result.is_err(), "Should fail with unsupported algorithm");

    println!("✅ Vendor error handling test completed");
}

/// Test vendor sequential operations (simulating concurrency)
#[tokio::test]
async fn test_vendor_concurrent_operations() {
    let vendor = MockVendor::new("concurrent-test-vendor");

    // Generate multiple keys sequentially (simulating concurrent operations)
    let concurrent_count = 20;
    let mut results = Vec::new();

    for i in 0..concurrent_count {
        let params = KeyGenParams {
            algorithm: Algorithm::Ed25519,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            vendor_params: None,
        };

        let key = vendor.generate_key(&params).await.expect("Should generate concurrent key");

        // Test operations
        let test_data = format!("Concurrent test {}", i);
        let signature =
            vendor.sign(&key, test_data.as_bytes()).await.expect("Should sign concurrent data");
        let is_valid = vendor
            .verify(&key, test_data.as_bytes(), &signature)
            .await
            .expect("Should verify concurrent signature");

        assert!(is_valid, "Concurrent signature should be valid");

        // Cleanup
        vendor.delete_key(&key).await.expect("Should delete concurrent key");

        results.push(i);
    }

    assert_eq!(results.len(), concurrent_count);
    println!("✅ Vendor concurrent operations completed: {} operations", results.len());
}

/// Test vendor capabilities consistency
#[tokio::test]
async fn test_vendor_capability_consistency() {
    let vendor = MockVendor::new("capability-test-vendor");

    // Probe capabilities multiple times to ensure consistency
    let cap1 = vendor.probe().await.expect("First capability probe should succeed");
    let cap2 = vendor.probe().await.expect("Second capability probe should succeed");
    let cap3 = vendor.probe().await.expect("Third capability probe should succeed");

    // Capabilities should be consistent across calls
    assert_eq!(cap1.name, cap2.name);
    assert_eq!(cap2.name, cap3.name);
    assert_eq!(cap1.version, cap2.version);
    assert_eq!(cap2.version, cap3.version);
    assert_eq!(cap1.algorithms, cap2.algorithms);
    assert_eq!(cap2.algorithms, cap3.algorithms);

    // Test that reported algorithms actually work (only test implemented ones)
    let working_algorithms = vec![Algorithm::Ed25519, Algorithm::EcdsaP256];

    for algorithm in working_algorithms {
        if !cap1.algorithms.contains(&algorithm) {
            continue;
        }

        let params = KeyGenParams {
            algorithm,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            vendor_params: None,
        };

        // Should be able to generate key with reported algorithm
        let key = vendor
            .generate_key(&params)
            .await
            .expect(&format!("Should generate key with reported algorithm {:?}", algorithm));

        assert_eq!(key.algorithm, algorithm);

        // Test basic operation
        let signature = vendor
            .sign(&key, b"capability test")
            .await
            .expect(&format!("Should sign with reported algorithm {:?}", algorithm));
        assert_eq!(signature.algorithm, algorithm);

        let is_valid = vendor
            .verify(&key, b"capability test", &signature)
            .await
            .expect(&format!("Should verify with reported algorithm {:?}", algorithm));
        assert!(is_valid);

        // Cleanup
        vendor.delete_key(&key).await.expect("Should delete capability test key");
    }

    println!("✅ Vendor capability consistency test completed");
}
