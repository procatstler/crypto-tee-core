//! Performance optimized implementations for CryptoTEE

pub mod cache;

// Re-export optimized cache components
pub use cache::{
    MemoryPoolStats, OptimizedLruCache, OptimizedMemoryPool, OptimizedPublicKeyCache,
    PublicKeyCacheStats, VerificationCache, VerificationCacheStats,
};
