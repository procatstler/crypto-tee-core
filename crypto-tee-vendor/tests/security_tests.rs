//! Security-focused tests for CryptoTEE vendor implementations

use crypto_tee_vendor::{mock::MockVendor, traits::VendorTEE, types::*};
use std::time::Instant;

#[tokio::test]
async fn test_no_sensitive_data_in_error_messages() {
    let vendor = MockVendor::new("test-vendor");

    // Generate a test key
    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let _key = vendor.generate_key(&params).await.unwrap();

    // Try to use invalid key ID
    let fake_key = VendorKeyHandle {
        id: "non_existent_key".to_string(),
        algorithm: Algorithm::Ed25519,
        vendor: "test".to_string(),
        hardware_backed: false,
        vendor_data: None,
    };

    // Operation should fail
    let result = vendor.sign(&fake_key, b"test data").await;
    assert!(result.is_err());

    // Error message should not contain sensitive information
    let error_msg = format!("{:?}", result.unwrap_err());
    assert!(!error_msg.contains("private"));
    assert!(!error_msg.contains("secret"));
    assert!(!error_msg.contains("key_material"));
}

#[tokio::test]
async fn test_timing_attack_resistance() {
    let vendor = MockVendor::new("test-vendor");

    // Generate a test key
    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key = vendor.generate_key(&params).await.unwrap();
    let test_data = b"test message for timing analysis";

    // Valid signature
    let valid_signature = vendor.sign(&key, test_data).await.unwrap();

    // Invalid signature (different data)
    let invalid_data = b"different message";
    let invalid_signature = vendor.sign(&key, invalid_data).await.unwrap();

    // Measure timing for valid verification
    let start = Instant::now();
    let valid_result = vendor.verify(&key, test_data, &valid_signature).await.unwrap();
    let valid_time = start.elapsed();

    // Measure timing for invalid verification
    let start = Instant::now();
    let invalid_result = vendor.verify(&key, test_data, &invalid_signature).await.unwrap();
    let invalid_time = start.elapsed();

    assert!(valid_result);
    assert!(!invalid_result);

    // Times should be reasonably similar (within 50% variance)
    // This is a basic timing analysis - real implementations need more sophisticated testing
    let time_ratio = valid_time.as_nanos() as f64 / invalid_time.as_nanos() as f64;
    assert!(
        time_ratio > 0.5 && time_ratio < 2.0,
        "Timing difference too large: valid={}ns, invalid={}ns, ratio={}",
        valid_time.as_nanos(),
        invalid_time.as_nanos(),
        time_ratio
    );
}

#[tokio::test]
async fn test_key_isolation() {
    let vendor = MockVendor::new("test-vendor");

    // Generate two different keys
    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key1 = vendor.generate_key(&params).await.unwrap();
    let key2 = vendor.generate_key(&params).await.unwrap();

    assert_ne!(key1.id, key2.id, "Keys should have unique IDs");

    let test_data = b"test message";

    // Sign with key1
    let signature1 = vendor.sign(&key1, test_data).await.unwrap();

    // Verify with key1 should succeed
    assert!(vendor.verify(&key1, test_data, &signature1).await.unwrap());

    // Verify with key2 should fail (keys are isolated)
    assert!(!vendor.verify(&key2, test_data, &signature1).await.unwrap());
}

#[tokio::test]
async fn test_input_validation() {
    let vendor = MockVendor::new("test-vendor");

    // Generate a test key
    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key = vendor.generate_key(&params).await.unwrap();

    // Test with empty data
    let empty_signature = vendor.sign(&key, &[]).await.unwrap();
    assert!(vendor.verify(&key, &[], &empty_signature).await.unwrap());

    // Test with large data (should not panic)
    let large_data = vec![0u8; 1024 * 1024]; // 1MB
    let large_signature = vendor.sign(&key, &large_data).await.unwrap();
    assert!(vendor.verify(&key, &large_data, &large_signature).await.unwrap());
}

#[tokio::test]
async fn test_key_deletion_security() {
    let vendor = MockVendor::new("test-vendor");

    // Generate a test key
    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key = vendor.generate_key(&params).await.unwrap();
    let test_data = b"test message";

    // Key should work before deletion
    let signature = vendor.sign(&key, test_data).await.unwrap();
    assert!(vendor.verify(&key, test_data, &signature).await.unwrap());

    // Delete the key
    vendor.delete_key(&key).await.unwrap();

    // Key should not work after deletion
    let result = vendor.sign(&key, test_data).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_algorithm_isolation() {
    let vendor = MockVendor::new("test-vendor");

    // Test supported algorithms work independently
    let algorithms = vec![Algorithm::Ed25519, Algorithm::EcdsaP256];

    for algorithm in algorithms {
        let params = KeyGenParams {
            algorithm,
            hardware_backed: false,
            exportable: false,
            usage: KeyUsage::default(),
            vendor_params: None,
        };

        // Each algorithm should work independently
        let key = vendor.generate_key(&params).await.unwrap();
        assert_eq!(key.algorithm, algorithm);

        let test_data = b"test message";
        let signature = vendor.sign(&key, test_data).await.unwrap();
        assert_eq!(signature.algorithm, algorithm);

        assert!(vendor.verify(&key, test_data, &signature).await.unwrap());

        // Clean up
        vendor.delete_key(&key).await.unwrap();
    }

    // Test that unsupported algorithm fails gracefully
    let unsupported_params = KeyGenParams {
        algorithm: Algorithm::Rsa2048,
        hardware_backed: false,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let result = vendor.generate_key(&unsupported_params).await;
    assert!(result.is_err(), "Unsupported algorithm should fail");
}

#[test]
fn test_no_debug_info_in_release() {
    // This test ensures sensitive structures don't leak info in Debug output
    let key_handle = VendorKeyHandle {
        id: "test_key".to_string(),
        algorithm: Algorithm::Ed25519,
        vendor: "test".to_string(),
        hardware_backed: true,
        vendor_data: None,
    };

    let debug_output = format!("{:?}", key_handle);

    // Debug output should not contain actual key material
    // (This is a basic check - the types are designed to not contain key material)
    assert!(!debug_output.contains("private"));
    assert!(!debug_output.contains("secret"));
}

#[test]
fn test_zeroize_implementation() {
    use crypto_tee_vendor::types::Signature;
    use zeroize::Zeroize;

    let mut signature = Signature { algorithm: Algorithm::Ed25519, data: vec![1, 2, 3, 4, 5] };

    let original_data = signature.data.clone();
    assert_eq!(signature.data, original_data);
    assert!(!original_data.is_empty());

    // Zeroize should clear the data
    signature.zeroize();

    // After zeroize, Vec<u8> should be empty (zeroized)
    assert!(signature.data.is_empty());
    // And should be different from original non-empty data
    assert_ne!(signature.data, original_data);
}
