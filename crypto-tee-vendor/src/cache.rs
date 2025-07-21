//! Performance optimization cache for CryptoTEE operations
//! 
//! This module provides caching mechanisms to improve performance of:
//! - Key lookups
//! - Public key operations  
//! - Verification results (for repeated verification of same data)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use ring::signature;
use crate::types::*;
use crate::error::VendorResult;

/// Cache entry with expiration
#[derive(Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

/// Pre-parsed public key cache to avoid repeated parsing
pub struct PublicKeyCache {
    ed25519_keys: Arc<RwLock<HashMap<Vec<u8>, CacheEntry<signature::UnparsedPublicKey<Vec<u8>>>>>>,
    ecdsa_keys: Arc<RwLock<HashMap<Vec<u8>, CacheEntry<signature::UnparsedPublicKey<Vec<u8>>>>>>,
    max_entries: usize,
    ttl: Duration,
}

impl PublicKeyCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            ed25519_keys: Arc::new(RwLock::new(HashMap::new())),
            ecdsa_keys: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            ttl,
        }
    }

    /// Get or create a parsed Ed25519 public key
    pub async fn get_ed25519_key(&self, public_key_bytes: &[u8]) -> signature::UnparsedPublicKey<Vec<u8>> {
        let key = public_key_bytes.to_vec();
        
        // Try to get from cache first
        {
            let cache = self.ed25519_keys.read().await;
            if let Some(entry) = cache.get(&key) {
                if !entry.is_expired() {
                    return signature::UnparsedPublicKey::new(&signature::ED25519, key);
                }
            }
        }

        // Create new key and cache it
        let parsed_key = signature::UnparsedPublicKey::new(&signature::ED25519, key.clone());
        
        {
            let mut cache = self.ed25519_keys.write().await;
            
            // Clean up expired entries and enforce size limit
            if cache.len() >= self.max_entries {
                cache.retain(|_, entry| !entry.is_expired());
                
                // If still too many entries, remove oldest
                if cache.len() >= self.max_entries {
                    if let Some(oldest_key) = cache.keys().next().cloned() {
                        cache.remove(&oldest_key);
                    }
                }
            }
            
            cache.insert(key, CacheEntry::new(parsed_key.clone(), self.ttl));
        }
        
        parsed_key
    }

    /// Get or create a parsed ECDSA P256 public key
    pub async fn get_ecdsa_p256_key(&self, public_key_bytes: &[u8]) -> signature::UnparsedPublicKey<Vec<u8>> {
        let key = public_key_bytes.to_vec();
        
        // Try to get from cache first
        {
            let cache = self.ecdsa_keys.read().await;
            if let Some(entry) = cache.get(&key) {
                if !entry.is_expired() {
                    return signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key);
                }
            }
        }

        // Create new key and cache it
        let parsed_key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, key.clone());
        
        {
            let mut cache = self.ecdsa_keys.write().await;
            
            // Clean up expired entries and enforce size limit
            if cache.len() >= self.max_entries {
                cache.retain(|_, entry| !entry.is_expired());
                
                // If still too many entries, remove oldest
                if cache.len() >= self.max_entries {
                    if let Some(oldest_key) = cache.keys().next().cloned() {
                        cache.remove(&oldest_key);
                    }
                }
            }
            
            cache.insert(key, CacheEntry::new(parsed_key.clone(), self.ttl));
        }
        
        parsed_key
    }

    /// Clear all cached keys
    pub async fn clear(&self) {
        self.ed25519_keys.write().await.clear();
        self.ecdsa_keys.write().await.clear();
    }

    /// Get cache statistics
    pub async fn stats(&self) -> CacheStats {
        let ed25519_count = self.ed25519_keys.read().await.len();
        let ecdsa_count = self.ecdsa_keys.read().await.len();
        
        CacheStats {
            ed25519_entries: ed25519_count,
            ecdsa_entries: ecdsa_count,
            total_entries: ed25519_count + ecdsa_count,
            max_entries: self.max_entries,
        }
    }
}

/// Cache statistics
#[derive(Debug)]
pub struct CacheStats {
    pub ed25519_entries: usize,
    pub ecdsa_entries: usize,
    pub total_entries: usize,
    pub max_entries: usize,
}

/// Key handle cache for faster key lookups
pub struct KeyHandleCache {
    cache: Arc<RwLock<HashMap<String, CacheEntry<VendorKeyHandle>>>>,
    max_entries: usize,
    ttl: Duration,
}

impl KeyHandleCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            max_entries,
            ttl,
        }
    }

    /// Get a cached key handle
    pub async fn get(&self, key_id: &str) -> Option<VendorKeyHandle> {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(key_id) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            }
        }
        None
    }

    /// Cache a key handle
    pub async fn put(&self, key_id: String, handle: VendorKeyHandle) {
        let mut cache = self.cache.write().await;
        
        // Clean up expired entries and enforce size limit
        if cache.len() >= self.max_entries {
            cache.retain(|_, entry| !entry.is_expired());
            
            // If still too many entries, remove oldest
            if cache.len() >= self.max_entries {
                if let Some(oldest_key) = cache.keys().next().cloned() {
                    cache.remove(&oldest_key);
                }
            }
        }
        
        cache.insert(key_id, CacheEntry::new(handle, self.ttl));
    }

    /// Remove a key from cache
    pub async fn remove(&self, key_id: &str) {
        self.cache.write().await.remove(key_id);
    }

    /// Clear all cached keys
    pub async fn clear(&self) {
        self.cache.write().await.clear();
    }
}

/// Memory pool for reducing allocations during crypto operations
pub struct MemoryPool {
    small_buffers: Arc<RwLock<Vec<Vec<u8>>>>,  // For signatures, typically 64-256 bytes
    medium_buffers: Arc<RwLock<Vec<Vec<u8>>>>, // For public keys, typically 32-128 bytes
    large_buffers: Arc<RwLock<Vec<Vec<u8>>>>,  // For large data, 1KB+
}

impl MemoryPool {
    pub fn new() -> Self {
        Self {
            small_buffers: Arc::new(RwLock::new(Vec::new())),
            medium_buffers: Arc::new(RwLock::new(Vec::new())),
            large_buffers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Get a buffer for small operations (signatures)
    pub async fn get_small_buffer(&self, min_size: usize) -> Vec<u8> {
        let mut buffers = self.small_buffers.write().await;
        
        // Find a suitable buffer
        for i in 0..buffers.len() {
            if buffers[i].capacity() >= min_size {
                let mut buffer = buffers.swap_remove(i);
                buffer.clear();
                return buffer;
            }
        }
        
        // No suitable buffer found, create new one
        Vec::with_capacity(min_size.max(256))
    }

    /// Return a small buffer to the pool
    pub async fn return_small_buffer(&self, mut buffer: Vec<u8>) {
        use zeroize::Zeroize;
        
        buffer.zeroize(); // Clear sensitive data
        buffer.clear();
        
        let mut buffers = self.small_buffers.write().await;
        if buffers.len() < 10 { // Limit pool size
            buffers.push(buffer);
        }
    }

    /// Get a buffer for medium operations (public keys)
    pub async fn get_medium_buffer(&self, min_size: usize) -> Vec<u8> {
        let mut buffers = self.medium_buffers.write().await;
        
        for i in 0..buffers.len() {
            if buffers[i].capacity() >= min_size {
                let mut buffer = buffers.swap_remove(i);
                buffer.clear();
                return buffer;
            }
        }
        
        Vec::with_capacity(min_size.max(128))
    }

    /// Return a medium buffer to the pool
    pub async fn return_medium_buffer(&self, mut buffer: Vec<u8>) {
        use zeroize::Zeroize;
        
        buffer.zeroize();
        buffer.clear();
        
        let mut buffers = self.medium_buffers.write().await;
        if buffers.len() < 20 {
            buffers.push(buffer);
        }
    }
}

impl Default for MemoryPool {
    fn default() -> Self {
        Self::new()
    }
}

/// Performance optimization configuration
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Enable public key caching
    pub enable_key_cache: bool,
    
    /// Maximum cached public keys
    pub max_cached_keys: usize,
    
    /// Key cache TTL
    pub key_cache_ttl: Duration,
    
    /// Enable memory pooling
    pub enable_memory_pool: bool,
    
    /// Enable key handle caching
    pub enable_handle_cache: bool,
    
    /// Maximum cached handles
    pub max_cached_handles: usize,
    
    /// Handle cache TTL  
    pub handle_cache_ttl: Duration,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            enable_key_cache: true,
            max_cached_keys: 1000,
            key_cache_ttl: Duration::from_secs(300), // 5 minutes
            enable_memory_pool: true,
            enable_handle_cache: true,
            max_cached_handles: 500,
            handle_cache_ttl: Duration::from_secs(600), // 10 minutes
        }
    }
}