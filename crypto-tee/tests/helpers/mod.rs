//! Test helpers and utilities for CryptoTEE testing

use std::sync::Arc;
use crypto_tee::{CryptoTEE, CryptoTEEBuilder};
use crypto_tee::types::*;
use crypto_tee_vendor::types::{Algorithm, KeyUsage};

pub mod test_keys;
pub mod test_scenarios;

/// Test configuration for different scenarios
#[derive(Debug, Clone)]
pub struct TestConfig {
    pub use_hardware_backed: bool,
    pub algorithm: Algorithm,
    pub key_count: usize,
    pub concurrent_operations: usize,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            use_hardware_backed: false,
            algorithm: Algorithm::Ed25519,
            key_count: 5,
            concurrent_operations: 10,
        }
    }
}

/// Test helper for creating CryptoTEE instances
pub struct TestHelper {
    pub crypto_tee: Arc<dyn CryptoTEE>,
    pub config: TestConfig,
}

impl TestHelper {
    /// Create a new test helper with default configuration
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Self::with_config(TestConfig::default()).await
    }

    /// Create a test helper with custom configuration
    pub async fn with_config(config: TestConfig) -> Result<Self, Box<dyn std::error::Error>> {
        let crypto_tee = CryptoTEEBuilder::new()
            .build()
            .await?;

        Ok(Self {
            crypto_tee: Arc::new(crypto_tee),
            config,
        })
    }

    /// Generate a test key with given alias
    pub async fn generate_test_key(&self, alias: &str) -> Result<KeyHandle, Box<dyn std::error::Error>> {
        let options = KeyOptions {
            algorithm: self.config.algorithm,
            hardware_backed: self.config.use_hardware_backed,
            exportable: true,
            usage: KeyUsage::default(),
            expires_at: None,
            require_auth: false,
            metadata: None,
        };

        Ok(self.crypto_tee.generate_key(alias, options).await?)
    }

    /// Generate multiple test keys with numbered aliases
    pub async fn generate_test_keys(&self, prefix: &str) -> Result<Vec<KeyHandle>, Box<dyn std::error::Error>> {
        let mut handles = Vec::new();
        
        for i in 0..self.config.key_count {
            let alias = format!("{}-{}", prefix, i);
            let handle = self.generate_test_key(&alias).await?;
            handles.push(handle);
        }

        Ok(handles)
    }

    /// Perform concurrent signing operations
    pub async fn concurrent_sign_test(&self, key_alias: &str, data: &[u8]) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut tasks = Vec::new();
        
        for _ in 0..self.config.concurrent_operations {
            let crypto_tee = Arc::clone(&self.crypto_tee);
            let alias = key_alias.to_string();
            let test_data = data.to_vec();
            
            let task = tokio::spawn(async move {
                crypto_tee.sign(&alias, &test_data, None).await
            });
            
            tasks.push(task);
        }

        let mut results = Vec::new();
        for task in tasks {
            let signature = task.await??;
            results.push(signature);
        }

        Ok(results)
    }

    /// Verify that all signatures are valid
    pub async fn verify_signatures(&self, key_alias: &str, data: &[u8], signatures: &[Vec<u8>]) -> Result<bool, Box<dyn std::error::Error>> {
        for signature in signatures {
            let valid = self.crypto_tee.verify(key_alias, data, signature, None).await?;
            if !valid {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Clean up test keys
    pub async fn cleanup_keys(&self, aliases: &[String]) -> Result<(), Box<dyn std::error::Error>> {
        for alias in aliases {
            if let Err(e) = self.crypto_tee.delete_key(alias).await {
                eprintln!("Warning: Failed to delete key {}: {}", alias, e);
            }
        }
        Ok(())
    }

    /// Get algorithm-specific test data
    pub fn get_test_data(&self) -> &'static [u8] {
        match self.config.algorithm {
            Algorithm::Ed25519 => b"Ed25519 test message for signing",
            Algorithm::EcdsaP256 => b"ECDSA P-256 test message for signing",
            Algorithm::EcdsaP384 => b"ECDSA P-384 test message for signing",
            Algorithm::Rsa2048 | Algorithm::Rsa3072 | Algorithm::Rsa4096 => b"RSA test message for signing",
            _ => b"Generic test message for signing",
        }
    }
}

/// Assertion helpers for testing
pub struct TestAssertions;

impl TestAssertions {
    /// Assert that key info matches expected values
    pub fn assert_key_info(info: &KeyInfo, expected_algorithm: Algorithm, expected_alias: &str) {
        assert_eq!(info.algorithm, expected_algorithm);
        assert_eq!(info.alias, expected_alias);
        // Hardware-backed depends on vendor implementation in mock
    }

    /// Assert that signature is valid format
    pub fn assert_signature_format(signature: &[u8], algorithm: Algorithm) {
        assert!(!signature.is_empty(), "Signature should not be empty");
        
        match algorithm {
            Algorithm::Ed25519 => {
                assert_eq!(signature.len(), 64, "Ed25519 signature should be 64 bytes");
            },
            Algorithm::EcdsaP256 => {
                assert!(signature.len() >= 64 && signature.len() <= 72, "ECDSA P-256 signature length invalid");
            },
            Algorithm::EcdsaP384 => {
                assert!(signature.len() >= 96 && signature.len() <= 104, "ECDSA P-384 signature length invalid");
            },
            _ => {
                // For other algorithms, just check it's not empty
            }
        }
    }

    /// Assert that error is of expected type
    pub fn assert_error_type(error: &crypto_tee::CryptoTEEError, expected_contains: &str) {
        let error_str = format!("{}", error);
        assert!(error_str.contains(expected_contains), 
                "Error '{}' should contain '{}'", error_str, expected_contains);
    }
}

/// Benchmark utilities
pub struct BenchmarkHelper {
    pub test_helper: TestHelper,
}

impl BenchmarkHelper {
    pub async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            test_helper: TestHelper::new().await?,
        })
    }

    /// Measure key generation time
    pub async fn benchmark_key_generation(&self, iterations: usize) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
        let start = std::time::Instant::now();
        
        for i in 0..iterations {
            let alias = format!("bench-key-{}", i);
            self.test_helper.generate_test_key(&alias).await?;
            self.test_helper.cleanup_keys(&[alias]).await?;
        }
        
        Ok(start.elapsed())
    }

    /// Measure signing throughput
    pub async fn benchmark_signing(&self, key_alias: &str, iterations: usize) -> Result<std::time::Duration, Box<dyn std::error::Error>> {
        let data = self.test_helper.get_test_data();
        let start = std::time::Instant::now();
        
        for _ in 0..iterations {
            self.test_helper.crypto_tee.sign(key_alias, data, None).await?;
        }
        
        Ok(start.elapsed())
    }
}