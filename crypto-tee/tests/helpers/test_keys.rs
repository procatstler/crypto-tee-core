//! Test key management utilities

use crypto_tee_vendor::types::Algorithm;
use std::collections::HashMap;

/// Predefined test key configurations
pub struct TestKeyConfigs;

impl TestKeyConfigs {
    /// Get all supported algorithms for testing
    pub fn all_algorithms() -> Vec<Algorithm> {
        vec![
            Algorithm::Ed25519,
            Algorithm::EcdsaP256,
            Algorithm::EcdsaP384,
            Algorithm::EcdsaP521,
            Algorithm::Rsa2048,
            Algorithm::Rsa3072,
            Algorithm::Rsa4096,
        ]
    }

    /// Get fast algorithms for quick testing
    pub fn fast_algorithms() -> Vec<Algorithm> {
        vec![Algorithm::Ed25519, Algorithm::EcdsaP256]
    }

    /// Get test data for each algorithm
    pub fn test_data_for_algorithm(algorithm: Algorithm) -> Vec<u8> {
        match algorithm {
            Algorithm::Ed25519 => b"Ed25519: The quick brown fox jumps over the lazy dog".to_vec(),
            Algorithm::EcdsaP256 => b"ECDSA-P256: Pack my box with five dozen liquor jugs".to_vec(),
            Algorithm::EcdsaP384 => b"ECDSA-P384: How vexingly quick daft zebras jump!".to_vec(),
            Algorithm::EcdsaP521 => b"ECDSA-P521: Waltz, bad nymph, for quick jigs vex".to_vec(),
            Algorithm::Rsa2048 => b"RSA-2048: Sphinx of black quartz, judge my vow".to_vec(),
            Algorithm::Rsa3072 => b"RSA-3072: The five boxing wizards jump quickly".to_vec(),
            Algorithm::Rsa4096 => b"RSA-4096: Bright vixens jump; dozy fowl quack".to_vec(),
            _ => b"Generic test data for unknown algorithm".to_vec(),
        }
    }

    /// Get expected signature sizes (approximate ranges)
    pub fn expected_signature_size(algorithm: Algorithm) -> (usize, usize) {
        match algorithm {
            Algorithm::Ed25519 => (64, 64),     // Exactly 64 bytes
            Algorithm::EcdsaP256 => (64, 72),   // DER encoding variation
            Algorithm::EcdsaP384 => (96, 104),  // DER encoding variation
            Algorithm::EcdsaP521 => (132, 139), // DER encoding variation
            Algorithm::Rsa2048 => (256, 256),   // 2048 bits = 256 bytes
            Algorithm::Rsa3072 => (384, 384),   // 3072 bits = 384 bytes
            Algorithm::Rsa4096 => (512, 512),   // 4096 bits = 512 bytes
            _ => (32, 1024),                    // Wide range for unknown algorithms
        }
    }
}

/// Test key factory for creating various key types
pub struct TestKeyFactory {
    counter: std::sync::atomic::AtomicUsize,
}

impl TestKeyFactory {
    pub fn new() -> Self {
        Self { counter: std::sync::atomic::AtomicUsize::new(0) }
    }

    /// Generate unique key alias
    pub fn unique_alias(&self, prefix: &str) -> String {
        let count = self.counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        format!("{prefix}_{count:04}")
    }

    /// Generate alias for algorithm-specific testing
    pub fn algorithm_alias(&self, algorithm: Algorithm) -> String {
        let algo_name = match algorithm {
            Algorithm::Ed25519 => "ed25519",
            Algorithm::EcdsaP256 => "ecdsa_p256",
            Algorithm::EcdsaP384 => "ecdsa_p384",
            Algorithm::EcdsaP521 => "ecdsa_p521",
            Algorithm::Rsa2048 => "rsa_2048",
            Algorithm::Rsa3072 => "rsa_3072",
            Algorithm::Rsa4096 => "rsa_4096",
            _ => "unknown",
        };
        self.unique_alias(algo_name)
    }

    /// Generate batch of unique aliases
    pub fn batch_aliases(&self, prefix: &str, count: usize) -> Vec<String> {
        (0..count).map(|_| self.unique_alias(prefix)).collect()
    }
}

/// Key lifecycle management for tests
pub struct TestKeyLifecycle {
    active_keys: HashMap<String, Algorithm>,
}

impl TestKeyLifecycle {
    pub fn new() -> Self {
        Self { active_keys: HashMap::new() }
    }

    /// Register a key as active
    pub fn register_key(&mut self, alias: String, algorithm: Algorithm) {
        self.active_keys.insert(alias, algorithm);
    }

    /// Unregister a key
    pub fn unregister_key(&mut self, alias: &str) {
        self.active_keys.remove(alias);
    }

    /// Get all active key aliases
    pub fn active_aliases(&self) -> Vec<String> {
        self.active_keys.keys().cloned().collect()
    }

    /// Get keys by algorithm
    pub fn keys_by_algorithm(&self, algorithm: Algorithm) -> Vec<String> {
        self.active_keys
            .iter()
            .filter(|(_, &algo)| algo == algorithm)
            .map(|(alias, _)| alias.clone())
            .collect()
    }

    /// Clear all registered keys
    pub fn clear(&mut self) {
        self.active_keys.clear();
    }
}

impl Default for TestKeyFactory {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for TestKeyLifecycle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_factory_unique_aliases() {
        let factory = TestKeyFactory::new();
        let alias1 = factory.unique_alias("test");
        let alias2 = factory.unique_alias("test");
        assert_ne!(alias1, alias2);
        assert!(alias1.starts_with("test_"));
        assert!(alias2.starts_with("test_"));
    }

    #[test]
    fn test_key_lifecycle_management() {
        let mut lifecycle = TestKeyLifecycle::new();
        lifecycle.register_key("key1".to_string(), Algorithm::Ed25519);
        lifecycle.register_key("key2".to_string(), Algorithm::EcdsaP256);

        let aliases = lifecycle.active_aliases();
        assert_eq!(aliases.len(), 2);
        assert!(aliases.contains(&"key1".to_string()));
        assert!(aliases.contains(&"key2".to_string()));

        let ed25519_keys = lifecycle.keys_by_algorithm(Algorithm::Ed25519);
        assert_eq!(ed25519_keys.len(), 1);
        assert_eq!(ed25519_keys[0], "key1");
    }

    #[test]
    fn test_algorithm_configs() {
        let algorithms = TestKeyConfigs::all_algorithms();
        assert!(!algorithms.is_empty());
        assert!(algorithms.contains(&Algorithm::Ed25519));
        assert!(algorithms.contains(&Algorithm::EcdsaP256));

        let fast_algorithms = TestKeyConfigs::fast_algorithms();
        assert!(fast_algorithms.len() <= algorithms.len());
    }

    #[test]
    fn test_signature_size_expectations() {
        let (min, max) = TestKeyConfigs::expected_signature_size(Algorithm::Ed25519);
        assert_eq!(min, 64);
        assert_eq!(max, 64);

        let (min, max) = TestKeyConfigs::expected_signature_size(Algorithm::EcdsaP256);
        assert!(min <= max);
        assert!(min >= 64);
    }
}
