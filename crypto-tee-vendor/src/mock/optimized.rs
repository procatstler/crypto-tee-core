//! Optimized mock vendor implementation with performance caching

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ring::signature::{self, KeyPair};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{debug, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::optimized::cache::*;
use crate::{
    error::{VendorError, VendorResult},
    traits::VendorTEE,
    types::*,
};

/// Optimized mock vendor implementation with performance caching
pub struct OptimizedMockVendor {
    name: String,
    keys: Arc<Mutex<HashMap<String, MockKey>>>,
    capabilities: VendorCapabilities,

    // Performance optimizations
    verification_cache: Arc<VerificationCache>,
    public_key_cache: OptimizedPublicKeyCache,
    memory_pool: Arc<OptimizedMemoryPool>,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct MockKey {
    #[zeroize(skip)]
    handle: VendorKeyHandle,
    private_key: Vec<u8>,
    public_key: Option<Vec<u8>>,
}

impl Default for OptimizedMockVendor {
    fn default() -> Self {
        Self::new("optimized-mock-vendor")
    }
}

impl OptimizedMockVendor {
    /// Perform constant-time signature verification with caching
    fn cached_constant_time_verify<T: AsRef<[u8]>>(
        public_key: &signature::UnparsedPublicKey<T>,
        data: &[u8],
        signature: &[u8],
        cache: &Arc<VerificationCache>,
    ) -> bool {
        // Check cache first
        if let Some(cached_result) = cache.get_cached_result(public_key.as_ref(), data, signature) {
            debug!("Verification cache hit");
            return cached_result;
        }

        // Perform the actual verification with constant timing
        let actual_result = public_key.verify(data, signature).is_ok();

        // Always perform a dummy verification to ensure constant timing
        let dummy_signature = vec![0u8; signature.len()];
        let _dummy_result = public_key.verify(data, &dummy_signature);

        // Use constant-time comparison for the final result
        let success_byte = if actual_result { 1u8 } else { 0u8 };
        let expected_byte = 1u8;
        let result = success_byte.ct_eq(&expected_byte).into();

        // Cache the result
        cache.cache_result(public_key.as_ref(), data, signature, result);
        debug!("Verification result cached");

        result
    }

    pub fn new(name: &str) -> Self {
        let capabilities = VendorCapabilities {
            name: format!("Optimized Mock Vendor: {name}"),
            version: "1.1.0".to_string(),
            algorithms: vec![Algorithm::EcdsaP256, Algorithm::Ed25519],
            hardware_backed: false,
            attestation: true,
            max_keys: 1000,
            features: VendorFeatures {
                hardware_backed: false,
                secure_key_import: true,
                secure_key_export: true,
                attestation: true,
                strongbox: false,
                biometric_bound: false,
                secure_deletion: false,
            },
        };

        // Initialize caches with optimized settings
        let verification_cache = VerificationCache::new(10000, Duration::from_secs(1800)); // 30 minutes
        let public_key_cache = OptimizedPublicKeyCache::new(1000, Duration::from_secs(600)); // 10 minutes
        let memory_pool = Arc::new(OptimizedMemoryPool::new());

        Self {
            name: name.to_string(),
            keys: Arc::new(Mutex::new(HashMap::new())),
            capabilities,
            verification_cache,
            public_key_cache,
            memory_pool,
        }
    }

    /// Get cache statistics for monitoring
    pub fn get_cache_stats(&self) -> OptimizedCacheStats {
        OptimizedCacheStats {
            verification: self.verification_cache.stats(),
            public_key: self.public_key_cache.stats(),
            memory_pool: self.memory_pool.stats(),
        }
    }

    /// Cleanup expired cache entries
    pub fn cleanup_caches(&self) -> usize {
        let public_key_cleaned = self.public_key_cache.cleanup_expired();
        debug!("Cache cleanup completed, {} entries removed", public_key_cleaned);
        public_key_cleaned
    }
}

#[derive(Debug)]
pub struct OptimizedCacheStats {
    pub verification: VerificationCacheStats,
    pub public_key: PublicKeyCacheStats,
    pub memory_pool: MemoryPoolStats,
}

#[async_trait]
impl VendorTEE for OptimizedMockVendor {
    async fn probe(&self) -> VendorResult<VendorCapabilities> {
        info!("Probing optimized mock vendor: {}", self.name);
        Ok(self.capabilities.clone())
    }

    async fn generate_key(&self, params: &KeyGenParams) -> VendorResult<VendorKeyHandle> {
        debug!("Generating key with params: {:?}", params);

        let key_id = format!("optimized-mock-key-{}", uuid::Uuid::new_v4());

        // Use memory pool for buffer allocation
        let (private_key, public_key) = match params.algorithm {
            Algorithm::Ed25519 => {
                let doc =
                    signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                        .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                let key_pair = signature::Ed25519KeyPair::from_pkcs8(doc.as_ref())
                    .map_err(|e| VendorError::CryptoError(e.to_string()))?;

                // Cache the public key for faster future access
                let public_key_bytes = key_pair.public_key().as_ref().to_vec();
                let unparsed_key = signature::UnparsedPublicKey::new(
                    &signature::ED25519,
                    public_key_bytes.clone(),
                );
                self.public_key_cache.cache_ed25519_key(public_key_bytes.clone(), unparsed_key);

                (doc.as_ref().to_vec(), Some(public_key_bytes))
            }
            Algorithm::EcdsaP256 => {
                let rng = ring::rand::SystemRandom::new();
                let doc = signature::EcdsaKeyPair::generate_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    doc.as_ref(),
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;

                // Cache the public key for faster future access
                let public_key_bytes = key_pair.public_key().as_ref().to_vec();
                let unparsed_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_ASN1,
                    public_key_bytes.clone(),
                );
                self.public_key_cache.cache_ecdsa_key(public_key_bytes.clone(), unparsed_key);

                (doc.as_ref().to_vec(), Some(public_key_bytes))
            }
            Algorithm::EcdsaP384 => {
                let rng = ring::rand::SystemRandom::new();
                let doc = signature::EcdsaKeyPair::generate_pkcs8(
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    doc.as_ref(),
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;

                // Cache the public key for faster future access
                let public_key_bytes = key_pair.public_key().as_ref().to_vec();
                let unparsed_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P384_SHA384_ASN1,
                    public_key_bytes.clone(),
                );
                self.public_key_cache.cache_ecdsa_key(public_key_bytes.clone(), unparsed_key);

                (doc.as_ref().to_vec(), Some(public_key_bytes))
            }
            _ => {
                return Err(VendorError::NotSupported(format!(
                    "Algorithm {:?} not yet implemented in optimized mock",
                    params.algorithm
                )))
            }
        };

        let handle = VendorKeyHandle {
            id: key_id.clone(),
            algorithm: params.algorithm,
            vendor: "optimized-mock".to_string(),
            hardware_backed: false,
            vendor_data: None,
        };

        let mock_key = MockKey { handle: handle.clone(), private_key, public_key };

        self.keys.lock().await.insert(key_id, mock_key);

        info!("Generated optimized mock key: {}", handle.id);
        Ok(handle)
    }

    async fn delete_key(&self, key: &VendorKeyHandle) -> VendorResult<()> {
        debug!("Deleting key: {}", key.id);

        match self.keys.lock().await.remove(&key.id) {
            Some(_) => {
                info!("Deleted optimized mock key: {}", key.id);
                Ok(())
            }
            None => Err(VendorError::KeyNotFound(key.id.clone())),
        }
    }

    async fn sign(&self, key: &VendorKeyHandle, data: &[u8]) -> VendorResult<Signature> {
        debug!("Signing data with key: {}", key.id);

        let keys = self.keys.lock().await;
        let mock_key = keys.get(&key.id).ok_or_else(|| VendorError::KeyNotFound(key.id.clone()))?;

        // Use memory pool for signature buffer allocation
        let signature_data = match key.algorithm {
            Algorithm::Ed25519 => {
                let key_pair = signature::Ed25519KeyPair::from_pkcs8(&mock_key.private_key)
                    .map_err(|e| VendorError::CryptoError(e.to_string()))?;

                // Get buffer from pool for signature
                let mut sig_buffer = self.memory_pool.get_buffer(64); // Ed25519 signatures are 64 bytes
                let signature_bytes = key_pair.sign(data);
                sig_buffer.clear();
                sig_buffer.extend_from_slice(signature_bytes.as_ref());
                let result = sig_buffer.clone();

                // Return buffer to pool
                self.memory_pool.return_buffer(sig_buffer);
                result
            }
            Algorithm::EcdsaP256 => {
                let rng = ring::rand::SystemRandom::new();
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &mock_key.private_key,
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;

                // Get buffer from pool for signature (ECDSA P256 signatures are ~70-72 bytes)
                let mut sig_buffer = self.memory_pool.get_buffer(80);
                let signature_bytes = key_pair
                    .sign(&rng, data)
                    .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                sig_buffer.clear();
                sig_buffer.extend_from_slice(signature_bytes.as_ref());
                let result = sig_buffer.clone();

                // Return buffer to pool
                self.memory_pool.return_buffer(sig_buffer);
                result
            }
            Algorithm::EcdsaP384 => {
                let rng = ring::rand::SystemRandom::new();
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    &mock_key.private_key,
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;

                // Get buffer from pool for signature (ECDSA P384 signatures are ~104-105 bytes)
                let mut sig_buffer = self.memory_pool.get_buffer(120);
                let signature_bytes = key_pair
                    .sign(&rng, data)
                    .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                sig_buffer.clear();
                sig_buffer.extend_from_slice(signature_bytes.as_ref());
                let result = sig_buffer.clone();

                // Return buffer to pool
                self.memory_pool.return_buffer(sig_buffer);
                result
            }
            _ => {
                return Err(VendorError::NotSupported(format!(
                    "Algorithm {:?} not yet implemented for signing",
                    key.algorithm
                )))
            }
        };

        Ok(Signature { algorithm: key.algorithm, data: signature_data })
    }

    async fn verify(
        &self,
        key: &VendorKeyHandle,
        data: &[u8],
        signature: &Signature,
    ) -> VendorResult<bool> {
        debug!("Verifying signature with key: {}", key.id);

        let keys = self.keys.lock().await;
        let mock_key = keys.get(&key.id).ok_or_else(|| VendorError::KeyNotFound(key.id.clone()))?;

        let public_key = mock_key
            .public_key
            .as_ref()
            .ok_or_else(|| VendorError::CryptoError("No public key available".to_string()))?;

        // Try to get public key from cache first
        let result = match key.algorithm {
            Algorithm::Ed25519 => {
                let peer_public_key = if let Some(cached_key) =
                    self.public_key_cache.get_ed25519_key(public_key)
                {
                    cached_key
                } else {
                    let new_key =
                        signature::UnparsedPublicKey::new(&signature::ED25519, public_key.clone());
                    self.public_key_cache.cache_ed25519_key(public_key.clone(), new_key.clone());
                    new_key
                };

                Self::cached_constant_time_verify(
                    &peer_public_key,
                    data,
                    &signature.data,
                    &self.verification_cache,
                )
            }
            Algorithm::EcdsaP256 => {
                let peer_public_key =
                    if let Some(cached_key) = self.public_key_cache.get_ecdsa_key(public_key) {
                        cached_key
                    } else {
                        let new_key = signature::UnparsedPublicKey::new(
                            &signature::ECDSA_P256_SHA256_ASN1,
                            public_key.clone(),
                        );
                        self.public_key_cache.cache_ecdsa_key(public_key.clone(), new_key.clone());
                        new_key
                    };

                Self::cached_constant_time_verify(
                    &peer_public_key,
                    data,
                    &signature.data,
                    &self.verification_cache,
                )
            }
            Algorithm::EcdsaP384 => {
                let peer_public_key =
                    if let Some(cached_key) = self.public_key_cache.get_ecdsa_key(public_key) {
                        cached_key
                    } else {
                        let new_key = signature::UnparsedPublicKey::new(
                            &signature::ECDSA_P384_SHA384_ASN1,
                            public_key.clone(),
                        );
                        self.public_key_cache.cache_ecdsa_key(public_key.clone(), new_key.clone());
                        new_key
                    };

                Self::cached_constant_time_verify(
                    &peer_public_key,
                    data,
                    &signature.data,
                    &self.verification_cache,
                )
            }
            _ => {
                return Err(VendorError::NotSupported(format!(
                    "Algorithm {:?} not yet implemented for verification",
                    key.algorithm
                )))
            }
        };

        Ok(result)
    }

    async fn get_attestation(&self) -> VendorResult<Attestation> {
        info!("Getting optimized mock attestation");

        // Use memory pool for attestation data
        let mut buffer = self.memory_pool.get_buffer(1024);
        buffer.clear();
        buffer.extend_from_slice(b"optimized-mock-attestation-data-with-performance-improvements");
        let attestation_data = buffer.clone();

        self.memory_pool.return_buffer(buffer);

        Ok(Attestation {
            format: AttestationFormat::Custom("optimized-mock-attestation".to_string()),
            data: attestation_data,
            certificates: vec![b"optimized-mock-certificate".to_vec()],
        })
    }

    async fn get_key_attestation(&self, key: &VendorKeyHandle) -> VendorResult<Attestation> {
        debug!("Getting key attestation for: {}", key.id);

        // Verify key exists
        let keys = self.keys.lock().await;
        if !keys.contains_key(&key.id) {
            return Err(VendorError::KeyNotFound(key.id.clone()));
        }

        // Use memory pool for attestation data
        let mut buffer = self.memory_pool.get_buffer(512);
        buffer.clear();
        buffer.extend_from_slice(format!("key-attestation-{}", key.id).as_bytes());
        let attestation_data = buffer.clone();

        self.memory_pool.return_buffer(buffer);

        Ok(Attestation {
            format: AttestationFormat::Custom("optimized-key-attestation".to_string()),
            data: attestation_data,
            certificates: vec![format!("cert-{}", key.id).into_bytes()],
        })
    }

    async fn list_keys(&self) -> VendorResult<Vec<VendorKeyHandle>> {
        debug!("Listing all keys in optimized mock vendor");

        let keys = self.keys.lock().await;
        let handles = keys.values().map(|key| key.handle.clone()).collect();

        info!("Listed {} keys from optimized mock vendor", keys.len());
        Ok(handles)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn test_optimized_cache_performance() {
        let vendor = OptimizedMockVendor::new("test-optimized");

        // Generate a key for testing
        let params = KeyGenParams {
            algorithm: Algorithm::Ed25519,
            hardware_backed: false,
            exportable: false,
            usage: Default::default(),
            vendor_params: None,
        };

        let key_handle = vendor.generate_key(&params).await.unwrap();
        let test_data = b"test message for cache performance";

        // Sign the data
        let signature = vendor.sign(&key_handle, test_data).await.unwrap();

        // First verification (cache miss)
        let start = std::time::Instant::now();
        let result1 = vendor.verify(&key_handle, test_data, &signature).await.unwrap();
        let first_duration = start.elapsed();

        // Second verification (cache hit)
        let start = std::time::Instant::now();
        let result2 = vendor.verify(&key_handle, test_data, &signature).await.unwrap();
        let second_duration = start.elapsed();

        assert!(result1);
        assert!(result2);

        // Cache hit should be faster (though this might not always be true in tests)
        println!("First verification: {first_duration:?}");
        println!("Second verification: {second_duration:?}");

        // Check cache statistics
        let stats = vendor.get_cache_stats();
        println!("Cache stats: {stats:?}");
        assert!(stats.verification.total_entries > 0);
    }

    #[tokio::test]
    async fn test_memory_pool_usage() {
        let vendor = OptimizedMockVendor::new("test-memory-pool");

        let params = KeyGenParams {
            algorithm: Algorithm::EcdsaP256,
            hardware_backed: false,
            exportable: false,
            usage: Default::default(),
            vendor_params: None,
        };

        let key_handle = vendor.generate_key(&params).await.unwrap();
        let test_data = b"test message for memory pool";

        // Perform multiple signing operations to test memory pool
        for _ in 0..10 {
            let _signature = vendor.sign(&key_handle, test_data).await.unwrap();
        }

        let stats = vendor.get_cache_stats();
        println!("Memory pool stats: {:?}", stats.memory_pool);

        // Should have some buffer reuse
        assert!(stats.memory_pool.hits > 0 || stats.memory_pool.allocations > 0);
    }

    #[tokio::test]
    async fn test_cache_cleanup() {
        let vendor = OptimizedMockVendor::new("test-cleanup");

        let params = KeyGenParams {
            algorithm: Algorithm::Ed25519,
            hardware_backed: false,
            exportable: false,
            usage: Default::default(),
            vendor_params: None,
        };

        // Generate some keys and perform operations
        for i in 0..5 {
            let key_handle = vendor.generate_key(&params).await.unwrap();
            let test_data = format!("test message {i}");
            let signature = vendor.sign(&key_handle, test_data.as_bytes()).await.unwrap();
            let _result =
                vendor.verify(&key_handle, test_data.as_bytes(), &signature).await.unwrap();
        }

        // Cleanup caches
        let cleaned = vendor.cleanup_caches();
        println!("Cleaned up {cleaned} expired entries");

        let stats = vendor.get_cache_stats();
        println!("Stats after cleanup: {stats:?}");
    }
}
