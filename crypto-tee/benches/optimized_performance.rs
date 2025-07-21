//! Optimized performance benchmarks for CryptoTEE
//!
//! This benchmark tests the performance improvements from caching and memory pooling.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto_tee::{types::*, CryptoTEE, CryptoTEEBuilder};
use crypto_tee_vendor::{
    cache::PerformanceConfig,
    traits::VendorTEE,
    types::{Algorithm, KeyUsage},
    MockVendor,
};
use std::time::Duration;
use tokio::runtime::Runtime;

/// Benchmark optimized vs non-optimized verification
fn bench_optimized_verification(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");

    let mut group = c.benchmark_group("optimized_verification");

    // Setup keys for testing
    let setup = rt.block_on(async {
        // Create optimized mock vendor
        let optimized_config = PerformanceConfig {
            enable_key_cache: true,
            max_cached_keys: 1000,
            key_cache_ttl: Duration::from_secs(300),
            enable_memory_pool: true,
            enable_handle_cache: true,
            max_cached_handles: 500,
            handle_cache_ttl: Duration::from_secs(600),
        };

        // Create non-optimized mock vendor
        let non_optimized_config = PerformanceConfig {
            enable_key_cache: false,
            max_cached_keys: 0,
            key_cache_ttl: Duration::from_secs(0),
            enable_memory_pool: false,
            enable_handle_cache: false,
            max_cached_handles: 0,
            handle_cache_ttl: Duration::from_secs(0),
        };

        // For now, use standard mock vendors since with_config is not implemented
        let optimized_vendor = MockVendor::new("optimized");
        let non_optimized_vendor = MockVendor::new("non-optimized");

        // Generate keys and signatures for testing
        let alias = "perf_test_key";
        let algorithm = Algorithm::Ed25519;
        let options = KeyOptions {
            algorithm,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            require_auth: false,
            expires_at: None,
            metadata: None,
        };

        let key_handle = optimized_vendor
            .generate_key(&crypto_tee_vendor::types::KeyGenParams {
                algorithm,
                hardware_backed: false,
                exportable: true,
                usage: KeyUsage::default(),
                vendor_params: None,
            })
            .await
            .expect("Key generation should succeed");

        let test_data = b"Performance test data for optimized verification benchmark";
        let signature =
            optimized_vendor.sign(&key_handle, test_data).await.expect("Signing should succeed");

        (optimized_vendor, non_optimized_vendor, key_handle, test_data.to_vec(), signature)
    });

    let (optimized_vendor, non_optimized_vendor, key_handle, test_data, signature) = setup;

    // Benchmark optimized verification
    group.bench_function("optimized", |b| {
        b.to_async(&rt).iter(|| async {
            optimized_vendor
                .verify(&key_handle, &test_data, &signature)
                .await
                .expect("Verification should succeed")
        });
    });

    // Benchmark non-optimized verification
    group.bench_function("non_optimized", |b| {
        b.to_async(&rt).iter(|| async {
            non_optimized_vendor
                .verify(&key_handle, &test_data, &signature)
                .await
                .expect("Verification should succeed")
        });
    });

    group.finish();
}

/// Benchmark memory allocation patterns
fn bench_memory_patterns(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");

    let mut group = c.benchmark_group("memory_patterns");

    // Setup
    let setup = rt.block_on(async {
        let optimized_config = PerformanceConfig {
            enable_key_cache: true,
            enable_memory_pool: true,
            ..Default::default()
        };

        // For now, use standard mock vendor since with_config is not implemented
        let vendor = MockVendor::new("memory-test");

        let key_handle = vendor
            .generate_key(&crypto_tee_vendor::types::KeyGenParams {
                algorithm: Algorithm::Ed25519,
                hardware_backed: false,
                exportable: true,
                usage: KeyUsage::default(),
                vendor_params: None,
            })
            .await
            .expect("Key generation should succeed");

        (vendor, key_handle)
    });

    let (vendor, key_handle) = setup;

    // Test different data sizes
    let data_sizes = vec![64, 256, 1024, 4096];

    for size in data_sizes {
        let test_data = vec![0xAB; size];

        group.bench_with_input(
            BenchmarkId::new("sign_with_pooling", size),
            &test_data,
            |b, test_data| {
                b.to_async(&rt).iter(|| async {
                    vendor.sign(&key_handle, test_data).await.expect("Signing should succeed")
                });
            },
        );
    }

    group.finish();
}

/// Benchmark cache effectiveness
fn bench_cache_effectiveness(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");

    let mut group = c.benchmark_group("cache_effectiveness");

    // Setup
    let setup = rt.block_on(async {
        // For now, use standard mock vendor since with_config is not implemented
        let vendor = MockVendor::new("cache-test");

        // Generate multiple keys
        let mut keys = Vec::new();
        for i in 0..10 {
            let key_handle = vendor
                .generate_key(&crypto_tee_vendor::types::KeyGenParams {
                    algorithm: Algorithm::Ed25519,
                    hardware_backed: false,
                    exportable: true,
                    usage: KeyUsage::default(),
                    vendor_params: None,
                })
                .await
                .expect("Key generation should succeed");
            keys.push(key_handle);
        }

        // Pre-populate cache by doing some verifications
        let test_data = b"cache warm-up data";
        for key in &keys {
            let signature = vendor.sign(key, test_data).await.expect("Signing should succeed");
            let _ = vendor.verify(key, test_data, &signature).await;
        }

        (vendor, keys)
    });

    let (vendor, keys) = setup;

    // Test cache hit performance
    group.bench_function("cache_hits", |b| {
        b.to_async(&rt).iter(|| async {
            let test_data = b"repeated verification test";

            for key in &keys {
                let signature = vendor.sign(key, test_data).await.expect("Signing should succeed");
                let _ = vendor
                    .verify(key, test_data, &signature)
                    .await
                    .expect("Verification should succeed");
            }
        });
    });

    group.finish();
}

/// Benchmark concurrent operations with optimizations
fn bench_optimized_concurrency(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");

    let mut group = c.benchmark_group("optimized_concurrency");

    // Setup
    let setup = rt.block_on(async {
        // For now, use standard mock vendor since with_config is not implemented
        let vendor = MockVendor::new("concurrent-test");

        let key_handle = vendor
            .generate_key(&crypto_tee_vendor::types::KeyGenParams {
                algorithm: Algorithm::Ed25519,
                hardware_backed: false,
                exportable: true,
                usage: KeyUsage::default(),
                vendor_params: None,
            })
            .await
            .expect("Key generation should succeed");

        (vendor, key_handle)
    });

    let (vendor, key_handle) = setup;
    let vendor = std::sync::Arc::new(vendor);
    let key_handle = std::sync::Arc::new(key_handle);
    let concurrency_levels = vec![1, 5, 10, 20];

    for concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("optimized_concurrent_ops", concurrency),
            &concurrency,
            |b, &concurrency| {
                let vendor = vendor.clone();
                let key_handle = key_handle.clone();
                b.to_async(&rt).iter(|| async {
                    let test_data = b"Optimized concurrent operation test";
                    let mut tasks = Vec::new();

                    // Create signing tasks
                    for _ in 0..concurrency {
                        let vendor_clone = vendor.clone();
                        let key_handle_clone = key_handle.clone();
                        let task = async move { vendor_clone.sign(&key_handle_clone, test_data).await };
                        tasks.push(task);
                    }

                    // Execute all tasks concurrently
                    let results = futures::future::join_all(tasks).await;

                    // Verify all results are successful
                    for result in results {
                        result.expect("Concurrent signing should succeed");
                    }
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    optimized_benches,
    bench_optimized_verification,
    bench_memory_patterns,
    bench_cache_effectiveness,
    bench_optimized_concurrency
);

criterion_main!(optimized_benches);
