//! Performance benchmarks comparing optimized vs standard cache implementations

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use crypto_tee_vendor::{
    mock::{optimized::OptimizedMockVendor, MockVendor},
    traits::VendorTEE,
    types::{Algorithm, KeyGenParams, KeyUsage},
};
use tokio::runtime::Runtime;

/// Benchmark standard mock vendor performance
fn bench_standard_vendor(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("standard_vendor_sign_verify", |b| {
        b.to_async(&rt).iter(|| async {
            let vendor = MockVendor::new("bench-standard");
            let params = KeyGenParams {
                algorithm: Algorithm::Ed25519,
                hardware_backed: false,
                exportable: false,
                usage: KeyUsage::default(),
                vendor_params: None,
            };

            let key_handle = vendor.generate_key(&params).await.unwrap();
            let test_data = black_box(b"benchmark test data for standard vendor");

            // Sign
            let signature = vendor.sign(&key_handle, test_data).await.unwrap();

            // Verify
            let result = vendor.verify(&key_handle, test_data, &signature).await.unwrap();
            assert!(result);
        });
    });
}

/// Benchmark optimized mock vendor performance
fn bench_optimized_vendor(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("optimized_vendor_sign_verify", |b| {
        b.to_async(&rt).iter(|| async {
            let vendor = OptimizedMockVendor::new("bench-optimized");
            let params = KeyGenParams {
                algorithm: Algorithm::Ed25519,
                hardware_backed: false,
                exportable: false,
                usage: KeyUsage::default(),
                vendor_params: None,
            };

            let key_handle = vendor.generate_key(&params).await.unwrap();
            let test_data = black_box(b"benchmark test data for optimized vendor");

            // Sign
            let signature = vendor.sign(&key_handle, test_data).await.unwrap();

            // Verify
            let result = vendor.verify(&key_handle, test_data, &signature).await.unwrap();
            assert!(result);
        });
    });
}

/// Benchmark repeated verification (cache benefits)
fn bench_repeated_verification(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("standard_vendor_repeated_verify", |b| {
        b.to_async(&rt).iter(|| async {
            let vendor = MockVendor::new("bench-standard-repeat");
            let params = KeyGenParams {
                algorithm: Algorithm::Ed25519,
                hardware_backed: false,
                exportable: false,
                usage: KeyUsage::default(),
                vendor_params: None,
            };

            let key_handle = vendor.generate_key(&params).await.unwrap();
            let test_data = black_box(b"repeated verification test data");
            let signature = vendor.sign(&key_handle, test_data).await.unwrap();

            // Perform multiple verifications
            for _ in 0..10 {
                let result = vendor.verify(&key_handle, test_data, &signature).await.unwrap();
                assert!(result);
            }
        });
    });

    c.bench_function("optimized_vendor_repeated_verify", |b| {
        b.to_async(&rt).iter(|| async {
            let vendor = OptimizedMockVendor::new("bench-optimized-repeat");
            let params = KeyGenParams {
                algorithm: Algorithm::Ed25519,
                hardware_backed: false,
                exportable: false,
                usage: KeyUsage::default(),
                vendor_params: None,
            };

            let key_handle = vendor.generate_key(&params).await.unwrap();
            let test_data = black_box(b"repeated verification test data");
            let signature = vendor.sign(&key_handle, test_data).await.unwrap();

            // Perform multiple verifications (should benefit from cache)
            for _ in 0..10 {
                let result = vendor.verify(&key_handle, test_data, &signature).await.unwrap();
                assert!(result);
            }
        });
    });
}

/// Benchmark concurrent operations
fn bench_concurrent_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("standard_vendor_concurrent", |b| {
        b.to_async(&rt).iter(|| async {
            let vendor = std::sync::Arc::new(MockVendor::new("bench-standard-concurrent"));
            let params = KeyGenParams {
                algorithm: Algorithm::Ed25519,
                hardware_backed: false,
                exportable: false,
                usage: KeyUsage::default(),
                vendor_params: None,
            };

            let key_handle = vendor.generate_key(&params).await.unwrap();
            let test_data = black_box(b"concurrent test data");
            let signature = vendor.sign(&key_handle, test_data).await.unwrap();

            // Perform concurrent verifications
            let mut handles = Vec::new();
            for _ in 0..5 {
                let vendor_clone = vendor.clone();
                let key_clone = key_handle.clone();
                let sig_clone = signature.clone();
                let handle = tokio::spawn(async move {
                    vendor_clone.verify(&key_clone, test_data, &sig_clone).await.unwrap()
                });
                handles.push(handle);
            }

            for handle in handles {
                let result = handle.await.unwrap();
                assert!(result);
            }
        });
    });

    c.bench_function("optimized_vendor_concurrent", |b| {
        b.to_async(&rt).iter(|| async {
            let vendor =
                std::sync::Arc::new(OptimizedMockVendor::new("bench-optimized-concurrent"));
            let params = KeyGenParams {
                algorithm: Algorithm::Ed25519,
                hardware_backed: false,
                exportable: false,
                usage: KeyUsage::default(),
                vendor_params: None,
            };

            let key_handle = vendor.generate_key(&params).await.unwrap();
            let test_data = black_box(b"concurrent test data");
            let signature = vendor.sign(&key_handle, test_data).await.unwrap();

            // Perform concurrent verifications (should benefit from lock-free caches)
            let mut handles = Vec::new();
            for _ in 0..5 {
                let vendor_clone = vendor.clone();
                let key_clone = key_handle.clone();
                let sig_clone = signature.clone();
                let handle = tokio::spawn(async move {
                    vendor_clone.verify(&key_clone, test_data, &sig_clone).await.unwrap()
                });
                handles.push(handle);
            }

            for handle in handles {
                let result = handle.await.unwrap();
                assert!(result);
            }
        });
    });
}

/// Benchmark memory pool efficiency
fn bench_memory_operations(c: &mut Criterion) {
    let rt = Runtime::new().unwrap();

    c.bench_function("standard_vendor_memory", |b| {
        b.to_async(&rt).iter(|| async {
            let vendor = MockVendor::new("bench-standard-memory");
            let params = KeyGenParams {
                algorithm: Algorithm::EcdsaP256,
                hardware_backed: false,
                exportable: false,
                usage: KeyUsage::default(),
                vendor_params: None,
            };

            let key_handle = vendor.generate_key(&params).await.unwrap();

            // Perform multiple signing operations (memory intensive)
            for i in 0..20 {
                let test_data = black_box(format!("memory test data {i}"));
                let _signature = vendor.sign(&key_handle, test_data.as_bytes()).await.unwrap();
            }
        });
    });

    c.bench_function("optimized_vendor_memory", |b| {
        b.to_async(&rt).iter(|| async {
            let vendor = OptimizedMockVendor::new("bench-optimized-memory");
            let params = KeyGenParams {
                algorithm: Algorithm::EcdsaP256,
                hardware_backed: false,
                exportable: false,
                usage: KeyUsage::default(),
                vendor_params: None,
            };

            let key_handle = vendor.generate_key(&params).await.unwrap();

            // Perform multiple signing operations (should benefit from memory pool)
            for i in 0..20 {
                let test_data = black_box(format!("memory test data {i}"));
                let _signature = vendor.sign(&key_handle, test_data.as_bytes()).await.unwrap();
            }
        });
    });
}

criterion_group!(
    cache_benches,
    bench_standard_vendor,
    bench_optimized_vendor,
    bench_repeated_verification,
    bench_concurrent_operations,
    bench_memory_operations
);

criterion_main!(cache_benches);
