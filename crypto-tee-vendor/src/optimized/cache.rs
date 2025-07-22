//! Optimized cache implementations for CryptoTEE
//!
//! This module provides high-performance caching mechanisms using:
//! - LRU cache with TTL support
//! - Lock-free concurrent data structures
//! - Batch processing capabilities

use dashmap::DashMap;
use lru::LruCache;
use parking_lot::RwLock;
use ring::signature;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::time::sleep;
use tracing::debug;

/// Hash-based verification cache entry
#[derive(Debug, Clone)]
struct VerificationEntry {
    result: bool,
    timestamp: Instant,
    ttl: Duration,
}

impl VerificationEntry {
    fn new(result: bool, ttl: Duration) -> Self {
        Self {
            result,
            timestamp: Instant::now(),
            ttl,
        }
    }

    fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > self.ttl
    }
}

/// Optimized LRU cache with TTL support
pub struct OptimizedLruCache<K, V> {
    cache: RwLock<LruCache<K, (V, Instant)>>,
    ttl: Duration,
}

impl<K: Hash + Eq + Clone, V: Clone> OptimizedLruCache<K, V> {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            cache: RwLock::new(LruCache::new(
                NonZeroUsize::new(capacity).unwrap_or(NonZeroUsize::new(100).unwrap()),
            )),
            ttl,
        }
    }

    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.write();
        if let Some((value, timestamp)) = cache.get(key) {
            if timestamp.elapsed() < self.ttl {
                return Some(value.clone());
            } else {
                cache.pop(key);
            }
        }
        None
    }

    pub fn insert(&self, key: K, value: V) {
        let mut cache = self.cache.write();
        cache.put(key, (value, Instant::now()));
    }

    pub fn clear(&self) {
        let mut cache = self.cache.write();
        cache.clear();
    }

    pub fn len(&self) -> usize {
        let cache = self.cache.read();
        cache.len()
    }

    /// Clean up expired entries in batch
    pub fn cleanup_expired(&self) -> usize {
        let mut cache = self.cache.write();
        let mut expired_keys = Vec::new();
        let now = Instant::now();

        // Collect expired keys (can't modify during iteration)
        for (key, (_, timestamp)) in cache.iter() {
            if now.duration_since(*timestamp) > self.ttl {
                expired_keys.push(key.clone());
            }
        }

        // Remove expired entries
        let removed_count = expired_keys.len();
        for key in expired_keys {
            cache.pop(&key);
        }

        removed_count
    }
}

/// High-performance verification cache using content hashing
pub struct VerificationCache {
    // Use DashMap for concurrent access without locks
    cache: DashMap<[u8; 32], VerificationEntry>,
    max_entries: usize,
    default_ttl: Duration,
    cleanup_interval: Duration,
}

impl VerificationCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Arc<Self> {
        let cache = Arc::new(Self {
            cache: DashMap::new(),
            max_entries,
            default_ttl: ttl,
            cleanup_interval: Duration::from_secs(300), // 5 minutes
        });

        // Start background cleanup task
        let cache_clone = Arc::clone(&cache);
        tokio::spawn(async move {
            cache_clone.cleanup_task().await;
        });

        cache
    }

    /// Generate hash key for verification cache
    fn hash_key(public_key: &[u8], message: &[u8], signature: &[u8]) -> [u8; 32] {
        use ring::digest;
        let mut context = digest::Context::new(&digest::SHA256);
        context.update(public_key);
        context.update(message);
        context.update(signature);
        let digest = context.finish();
        let mut key = [0u8; 32];
        key.copy_from_slice(digest.as_ref());
        key
    }

    /// Cache verification result
    pub fn cache_result(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
        result: bool,
    ) {
        if self.cache.len() >= self.max_entries {
            // Don't cache if at capacity (background cleanup will make space)
            return;
        }

        let key = Self::hash_key(public_key, message, signature);
        let entry = VerificationEntry::new(result, self.default_ttl);
        self.cache.insert(key, entry);
    }

    /// Get cached verification result
    pub fn get_cached_result(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Option<bool> {
        let key = Self::hash_key(public_key, message, signature);
        if let Some(entry) = self.cache.get(&key) {
            if !entry.is_expired() {
                return Some(entry.result);
            } else {
                self.cache.remove(&key);
            }
        }
        None
    }

    /// Background cleanup task
    async fn cleanup_task(&self) {
        loop {
            sleep(self.cleanup_interval).await;
            let removed = self.cleanup_expired_entries();
            if removed > 0 {
                debug!("Cleaned up {} expired verification cache entries", removed);
            }
        }
    }

    /// Clean up expired entries
    fn cleanup_expired_entries(&self) -> usize {
        let mut removed_count = 0;
        let mut keys_to_remove = Vec::new();

        // Collect expired keys
        for entry in self.cache.iter() {
            if entry.value().is_expired() {
                keys_to_remove.push(*entry.key());
            }
        }

        // Remove expired entries
        for key in keys_to_remove {
            if self.cache.remove(&key).is_some() {
                removed_count += 1;
            }
        }

        removed_count
    }

    /// Get cache statistics
    pub fn stats(&self) -> VerificationCacheStats {
        let total_entries = self.cache.len();
        let expired_entries = self
            .cache
            .iter()
            .filter(|entry| entry.value().is_expired())
            .count();

        VerificationCacheStats {
            total_entries,
            expired_entries,
            active_entries: total_entries - expired_entries,
            max_entries: self.max_entries,
            hit_ratio: 0.0, // TODO: Implement hit/miss tracking
        }
    }
}

#[derive(Debug)]
pub struct VerificationCacheStats {
    pub total_entries: usize,
    pub expired_entries: usize,
    pub active_entries: usize,
    pub max_entries: usize,
    pub hit_ratio: f64,
}

/// Optimized public key cache using LRU with concurrent access
pub struct OptimizedPublicKeyCache {
    ed25519_cache: OptimizedLruCache<Vec<u8>, signature::UnparsedPublicKey<Vec<u8>>>,
    ecdsa_cache: OptimizedLruCache<Vec<u8>, signature::UnparsedPublicKey<Vec<u8>>>,
    stats: Arc<parking_lot::Mutex<CacheStats>>,
}

impl OptimizedPublicKeyCache {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            ed25519_cache: OptimizedLruCache::new(max_entries / 2, ttl),
            ecdsa_cache: OptimizedLruCache::new(max_entries / 2, ttl),
            stats: Arc::new(parking_lot::Mutex::new(CacheStats::default())),
        }
    }

    /// Get cached Ed25519 public key
    pub fn get_ed25519_key(&self, key_bytes: &[u8]) -> Option<signature::UnparsedPublicKey<Vec<u8>>> {
        let result = self.ed25519_cache.get(&key_bytes.to_vec());
        self.update_stats(result.is_some());
        result
    }

    /// Cache Ed25519 public key
    pub fn cache_ed25519_key(&self, key_bytes: Vec<u8>, public_key: signature::UnparsedPublicKey<Vec<u8>>) {
        self.ed25519_cache.insert(key_bytes, public_key);
    }

    /// Get cached ECDSA public key
    pub fn get_ecdsa_key(&self, key_bytes: &[u8]) -> Option<signature::UnparsedPublicKey<Vec<u8>>> {
        let result = self.ecdsa_cache.get(&key_bytes.to_vec());
        self.update_stats(result.is_some());
        result
    }

    /// Cache ECDSA public key
    pub fn cache_ecdsa_key(&self, key_bytes: Vec<u8>, public_key: signature::UnparsedPublicKey<Vec<u8>>) {
        self.ecdsa_cache.insert(key_bytes, public_key);
    }

    /// Batch cleanup of expired entries
    pub fn cleanup_expired(&self) -> usize {
        let ed25519_removed = self.ed25519_cache.cleanup_expired();
        let ecdsa_removed = self.ecdsa_cache.cleanup_expired();
        let total_removed = ed25519_removed + ecdsa_removed;

        if total_removed > 0 {
            debug!("Cleaned up {} expired public key cache entries", total_removed);
        }

        total_removed
    }

    /// Update cache hit/miss statistics
    fn update_stats(&self, hit: bool) {
        let mut stats = self.stats.lock();
        if hit {
            stats.hits += 1;
        } else {
            stats.misses += 1;
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> PublicKeyCacheStats {
        let stats = self.stats.lock();
        PublicKeyCacheStats {
            ed25519_entries: self.ed25519_cache.len(),
            ecdsa_entries: self.ecdsa_cache.len(),
            total_entries: self.ed25519_cache.len() + self.ecdsa_cache.len(),
            hits: stats.hits,
            misses: stats.misses,
            hit_ratio: if stats.hits + stats.misses > 0 {
                stats.hits as f64 / (stats.hits + stats.misses) as f64
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Default)]
struct CacheStats {
    hits: u64,
    misses: u64,
}

#[derive(Debug)]
pub struct PublicKeyCacheStats {
    pub ed25519_entries: usize,
    pub ecdsa_entries: usize,
    pub total_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_ratio: f64,
}

/// Lock-free memory pool for high-performance buffer allocation
pub struct OptimizedMemoryPool {
    small_buffers: crossbeam::queue::SegQueue<Vec<u8>>, // < 1KB
    medium_buffers: crossbeam::queue::SegQueue<Vec<u8>>, // 1KB - 64KB
    large_buffers: crossbeam::queue::SegQueue<Vec<u8>>, // > 64KB
    stats: Arc<parking_lot::Mutex<MemoryPoolStats>>,
}

impl OptimizedMemoryPool {
    const SMALL_SIZE: usize = 1024; // 1KB
    const MEDIUM_SIZE: usize = 65536; // 64KB
    const MAX_POOL_SIZE: usize = 50;

    pub fn new() -> Self {
        Self {
            small_buffers: crossbeam::queue::SegQueue::new(),
            medium_buffers: crossbeam::queue::SegQueue::new(),
            large_buffers: crossbeam::queue::SegQueue::new(),
            stats: Arc::new(parking_lot::Mutex::new(MemoryPoolStats::default())),
        }
    }

    /// Get a buffer of appropriate size from the pool
    pub fn get_buffer(&self, size: usize) -> Vec<u8> {
        let queue = if size <= Self::SMALL_SIZE {
            &self.small_buffers
        } else if size <= Self::MEDIUM_SIZE {
            &self.medium_buffers
        } else {
            &self.large_buffers
        };

        if let Some(mut buffer) = queue.pop() {
            if buffer.capacity() >= size {
                buffer.clear();
                buffer.resize(size, 0);
                self.update_stats(true);
                return buffer;
            }
        }

        // Create new buffer if none available or too small
        self.update_stats(false);
        vec![0; size]
    }

    /// Return a buffer to the pool
    pub fn return_buffer(&self, buffer: Vec<u8>) {
        let capacity = buffer.capacity();
        
        let queue = if capacity <= Self::SMALL_SIZE {
            &self.small_buffers
        } else if capacity <= Self::MEDIUM_SIZE {
            &self.medium_buffers
        } else {
            &self.large_buffers
        };

        // Only keep buffer if pool not full
        if queue.len() < Self::MAX_POOL_SIZE {
            queue.push(buffer);
        }
    }

    /// Update pool statistics
    fn update_stats(&self, hit: bool) {
        let mut stats = self.stats.lock();
        if hit {
            stats.hits += 1;
        } else {
            stats.allocations += 1;
        }
    }

    /// Get memory pool statistics
    pub fn stats(&self) -> MemoryPoolStats {
        let stats = self.stats.lock();
        MemoryPoolStats {
            small_buffers: self.small_buffers.len(),
            medium_buffers: self.medium_buffers.len(),
            large_buffers: self.large_buffers.len(),
            hits: stats.hits,
            allocations: stats.allocations,
            hit_ratio: if stats.hits + stats.allocations > 0 {
                stats.hits as f64 / (stats.hits + stats.allocations) as f64
            } else {
                0.0
            },
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct MemoryPoolStats {
    pub small_buffers: usize,
    pub medium_buffers: usize,
    pub large_buffers: usize,
    pub hits: u64,
    pub allocations: u64,
    pub hit_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_verification_cache() {
        let cache = VerificationCache::new(100, Duration::from_secs(1));
        
        let public_key = b"test_public_key";
        let message = b"test_message";
        let signature = b"test_signature";

        // Should return None initially
        assert!(cache.get_cached_result(public_key, message, signature).is_none());

        // Cache a result
        cache.cache_result(public_key, message, signature, true);
        
        // Should return cached result
        assert_eq!(cache.get_cached_result(public_key, message, signature), Some(true));

        // Wait for expiration
        sleep(Duration::from_secs(2)).await;
        
        // Should return None after expiration
        assert!(cache.get_cached_result(public_key, message, signature).is_none());
    }

    #[test]
    fn test_optimized_lru_cache() {
        let cache = OptimizedLruCache::new(2, Duration::from_millis(100));
        
        cache.insert("key1".to_string(), "value1".to_string());
        cache.insert("key2".to_string(), "value2".to_string());
        
        assert_eq!(cache.get(&"key1".to_string()), Some("value1".to_string()));
        assert_eq!(cache.get(&"key2".to_string()), Some("value2".to_string()));
        
        // Should evict oldest when inserting third item
        cache.insert("key3".to_string(), "value3".to_string());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_memory_pool() {
        let pool = OptimizedMemoryPool::new();
        
        // Get a small buffer
        let buffer1 = pool.get_buffer(512);
        assert_eq!(buffer1.len(), 512);
        
        // Return it
        pool.return_buffer(buffer1);
        
        // Get another buffer of same size (should reuse)
        let buffer2 = pool.get_buffer(512);
        assert_eq!(buffer2.len(), 512);
        
        let stats = pool.stats();
        assert!(stats.hits >= 1);
    }
}