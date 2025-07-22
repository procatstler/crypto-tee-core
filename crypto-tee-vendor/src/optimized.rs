//! Performance optimized implementations for CryptoTEE

pub mod cache;

// Re-export optimized cache components
pub use cache::{
    OptimizedLruCache, VerificationCache, OptimizedPublicKeyCache, 
    OptimizedMemoryPool, VerificationCacheStats, PublicKeyCacheStats, 
    MemoryPoolStats
};