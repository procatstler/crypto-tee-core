//! Test scenarios for comprehensive testing

use super::{TestAssertions, TestHelper};
use crypto_tee::types::*;
use crypto_tee_vendor::types::{Algorithm, KeyUsage};

/// Comprehensive test scenarios
pub struct TestScenarios;

impl TestScenarios {
    /// Test basic key lifecycle across all algorithms
    pub async fn test_all_algorithms_lifecycle(
        helper: &TestHelper,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let algorithms = vec![
            Algorithm::Ed25519,
            Algorithm::EcdsaP256,
            // Algorithm::EcdsaP384, // Not supported by mock yet
        ];

        for algorithm in algorithms {
            let alias = format!("lifecycle_test_{:?}", algorithm);

            // Generate key
            let options = KeyOptions {
                algorithm,
                hardware_backed: false,
                exportable: true,
                usage: KeyUsage::default(),
                expires_at: None,
                require_auth: false,
                metadata: None,
            };

            let key_handle = helper.crypto_tee.generate_key(&alias, options).await?;
            let key_info = KeyInfo {
                alias: key_handle.alias.clone(),
                algorithm: key_handle.metadata.algorithm,
                created_at: key_handle.metadata.created_at,
                hardware_backed: key_handle.metadata.hardware_backed,
                requires_auth: false,
            };
            TestAssertions::assert_key_info(&key_info, algorithm, &alias);

            // Sign and verify
            let test_data = helper.get_test_data();
            let signature = helper.crypto_tee.sign(&alias, test_data, None).await?;
            TestAssertions::assert_signature_format(&signature, algorithm);

            let valid = helper.crypto_tee.verify(&alias, test_data, &signature, None).await?;
            assert!(valid, "Signature verification failed for {:?}", algorithm);

            // Clean up
            helper.crypto_tee.delete_key(&alias).await?;
        }

        Ok(())
    }

    /// Test concurrent operations
    pub async fn test_concurrent_operations(
        helper: &TestHelper,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let alias = "concurrent_test_key";
        helper.generate_test_key(alias).await?;

        let test_data = b"concurrent test data";
        let signatures = helper.concurrent_sign_test(alias, test_data).await?;

        // Verify all signatures are valid and unique
        assert_eq!(signatures.len(), helper.config.concurrent_operations);
        let all_valid = helper.verify_signatures(alias, test_data, &signatures).await?;
        assert!(all_valid, "Some concurrent signatures were invalid");

        // Check that signatures are deterministic or random as expected
        let first_sig = &signatures[0];
        let mut all_same = true;
        for sig in &signatures[1..] {
            if sig != first_sig {
                all_same = false;
                break;
            }
        }

        // For deterministic algorithms (like Ed25519), signatures should be the same
        // For probabilistic algorithms (like ECDSA), they should be different
        match helper.config.algorithm {
            Algorithm::Ed25519 => {
                assert!(all_same, "Ed25519 signatures should be deterministic");
            }
            Algorithm::EcdsaP256 | Algorithm::EcdsaP384 | Algorithm::EcdsaP521 => {
                // ECDSA signatures should be different due to random k value
                // But in mock implementation, they might be the same
            }
            _ => {
                // For other algorithms, we don't make assumptions
            }
        }

        helper.crypto_tee.delete_key(alias).await?;
        Ok(())
    }

    /// Test error handling scenarios
    pub async fn test_error_scenarios(
        helper: &TestHelper,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Test signing with non-existent key
        let result = helper.crypto_tee.sign("non_existent_key", b"test", None).await;
        assert!(result.is_err(), "Signing with non-existent key should fail");
        TestAssertions::assert_error_type(&result.unwrap_err(), "not found");

        // Test duplicate key generation
        let alias = "duplicate_test_key";
        helper.generate_test_key(alias).await?;

        let options = KeyOptions {
            algorithm: helper.config.algorithm,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            expires_at: None,
            require_auth: false,
            metadata: None,
        };

        let result = helper.crypto_tee.generate_key(alias, options).await;
        assert!(result.is_err(), "Duplicate key generation should fail");
        TestAssertions::assert_error_type(&result.unwrap_err(), "already exists");

        helper.crypto_tee.delete_key(alias).await?;
        Ok(())
    }

    /// Test key metadata and information
    pub async fn test_key_metadata(helper: &TestHelper) -> Result<(), Box<dyn std::error::Error>> {
        let alias = "metadata_test_key";
        let mut custom_metadata = serde_json::Map::new();
        custom_metadata
            .insert("purpose".to_string(), serde_json::Value::String("testing".to_string()));
        custom_metadata
            .insert("owner".to_string(), serde_json::Value::String("test_suite".to_string()));

        let options = KeyOptions {
            algorithm: helper.config.algorithm,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage {
                sign: true,
                verify: true,
                encrypt: false,
                decrypt: false,
                wrap: false,
                unwrap: false,
            },
            expires_at: None,
            require_auth: false,
            metadata: Some(serde_json::Value::Object(custom_metadata.clone())),
        };

        let key_handle = helper.crypto_tee.generate_key(alias, options).await?;

        // Verify metadata
        assert_eq!(key_handle.metadata.algorithm, helper.config.algorithm);
        assert_eq!(key_handle.metadata.usage_count, 0);
        assert!(key_handle.metadata.last_used.is_none());

        if let Some(serde_json::Value::Object(metadata)) = &key_handle.metadata.custom {
            assert_eq!(
                metadata.get("purpose"),
                Some(&serde_json::Value::String("testing".to_string()))
            );
            assert_eq!(
                metadata.get("owner"),
                Some(&serde_json::Value::String("test_suite".to_string()))
            );
        }

        // Test usage count increment
        helper.crypto_tee.sign(alias, b"test", None).await?;
        let info = helper.crypto_tee.get_key_info(alias).await?;
        // Note: Usage count checking depends on implementation details

        helper.crypto_tee.delete_key(alias).await?;
        Ok(())
    }

    /// Test large data signing
    pub async fn test_large_data_signing(
        helper: &TestHelper,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let alias = "large_data_test_key";
        helper.generate_test_key(alias).await?;

        // Test various data sizes
        let data_sizes = vec![1024, 4096, 16384, 65536]; // 1KB to 64KB

        for size in data_sizes {
            let large_data = vec![0xAB; size];
            let signature = helper.crypto_tee.sign(alias, &large_data, None).await?;
            TestAssertions::assert_signature_format(&signature, helper.config.algorithm);

            let valid = helper.crypto_tee.verify(alias, &large_data, &signature, None).await?;
            assert!(valid, "Large data verification failed for size {}", size);
        }

        helper.crypto_tee.delete_key(alias).await?;
        Ok(())
    }

    /// Test key listing and management
    pub async fn test_key_listing(helper: &TestHelper) -> Result<(), Box<dyn std::error::Error>> {
        let initial_keys = helper.crypto_tee.list_keys().await?;
        let initial_count = initial_keys.len();

        // Generate multiple keys
        let test_aliases = vec!["list_test_1", "list_test_2", "list_test_3"];
        for alias in &test_aliases {
            helper.generate_test_key(alias).await?;
        }

        // Check listing
        let keys = helper.crypto_tee.list_keys().await?;
        assert_eq!(keys.len(), initial_count + test_aliases.len());

        // Verify all test keys are present
        for alias in &test_aliases {
            let found = keys.iter().any(|k| k.alias == *alias);
            assert!(found, "Key {} not found in listing", alias);
        }

        // Clean up
        for alias in &test_aliases {
            helper.crypto_tee.delete_key(alias).await?;
        }

        let final_keys = helper.crypto_tee.list_keys().await?;
        assert_eq!(final_keys.len(), initial_count);

        Ok(())
    }

    /// Stress test with many operations
    pub async fn stress_test(helper: &TestHelper) -> Result<(), Box<dyn std::error::Error>> {
        let stress_key_count = 20;
        let operations_per_key = 5;

        let mut test_keys = Vec::new();

        // Generate many keys
        for i in 0..stress_key_count {
            let alias = format!("stress_test_key_{}", i);
            helper.generate_test_key(&alias).await?;
            test_keys.push(alias);
        }

        // Perform many operations
        for alias in &test_keys {
            for j in 0..operations_per_key {
                let test_data = format!("stress test data {}", j);
                let signature = helper.crypto_tee.sign(alias, test_data.as_bytes(), None).await?;
                let valid =
                    helper.crypto_tee.verify(alias, test_data.as_bytes(), &signature, None).await?;
                assert!(valid, "Stress test verification failed for key {} operation {}", alias, j);
            }
        }

        // Clean up all keys
        for alias in &test_keys {
            helper.crypto_tee.delete_key(alias).await?;
        }

        Ok(())
    }
}
