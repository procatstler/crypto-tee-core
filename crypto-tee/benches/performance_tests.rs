//! Performance benchmarks for CryptoTEE

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use crypto_tee::{CryptoTEEBuilder, types::*};
use crypto_tee_vendor::types::{Algorithm, KeyUsage};
use tokio::runtime::Runtime;

/// Benchmark key generation performance
fn bench_key_generation(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");
    
    let mut group = c.benchmark_group("key_generation");
    
    let algorithms = vec![
        Algorithm::Ed25519,
        Algorithm::EcdsaP256,
        Algorithm::EcdsaP384,
    ];
    
    for algorithm in algorithms {
        group.bench_with_input(
            BenchmarkId::new("generate_key", format!("{:?}", algorithm)),
            &algorithm,
            |b, &algorithm| {
                b.to_async(&rt).iter(|| async {
                    let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Benchmark operation should succeed");
                    let alias = format!("bench_key_{:?}_{}", algorithm, rand::random::<u32>());
                    
                    let options = KeyOptions {
                        algorithm,
                        hardware_backed: false,
                        exportable: true,
                        usage: KeyUsage::default(),
                        metadata: None,
                    };
                    
                    let result = crypto_tee.generate_key(&alias, options).await;
                    
                    // Clean up
                    if result.is_ok() {
                        let _ = crypto_tee.delete_key(&alias).await;
                    }
                    
                    result
                });
            }
        );
    }
    
    group.finish();
}

/// Benchmark signing performance
fn bench_signing(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");
    
    let mut group = c.benchmark_group("signing");
    
    // Setup: Create keys for each algorithm
    let setup = rt.block_on(async {
        let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Benchmark operation should succeed");
        let mut keys = Vec::new();
        
        let algorithms = vec![
            Algorithm::Ed25519,
            Algorithm::EcdsaP256,
            Algorithm::EcdsaP384,
        ];
        
        for algorithm in algorithms {
            let alias = format!("sign_bench_key_{:?}", algorithm);
            let options = KeyOptions {
                algorithm,
                hardware_backed: false,
                exportable: true,
                usage: KeyUsage::default(),
                metadata: None,
            };
            
            crypto_tee.generate_key(&alias, options).await.expect("Benchmark operation should succeed");
            keys.push((alias, algorithm));
        }
        
        (crypto_tee, keys)
    });
    
    let (crypto_tee, keys) = setup;
    
    for (alias, algorithm) in &keys {
        group.bench_with_input(
            BenchmarkId::new("sign", format!("{:?}", algorithm)),
            &(alias.clone(), *algorithm),
            |b, (alias, _algorithm)| {
                b.to_async(&rt).iter(|| async {
                    let test_data = b"Performance test data for signing benchmark";
                    crypto_tee.sign(alias, test_data, None).await.expect("Benchmark operation should succeed")
                });
            }
        );
    }
    
    // Cleanup
    rt.block_on(async {
        for (alias, _) in keys {
            let _ = crypto_tee.delete_key(&alias).await;
        }
    });
    
    group.finish();
}

/// Benchmark verification performance
fn bench_verification(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");
    
    let mut group = c.benchmark_group("verification");
    
    // Setup: Create keys and signatures
    let setup = rt.block_on(async {
        let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Benchmark operation should succeed");
        let mut test_data = Vec::new();
        
        let algorithms = vec![
            Algorithm::Ed25519,
            Algorithm::EcdsaP256,
        ];
        
        for algorithm in algorithms {
            let alias = format!("verify_bench_key_{:?}", algorithm);
            let options = KeyOptions {
                algorithm,
                hardware_backed: false,
                exportable: true,
                usage: KeyUsage::default(),
                metadata: None,
            };
            
            crypto_tee.generate_key(&alias, options).await.expect("Benchmark operation should succeed");
            let message = b"Performance test data for verification benchmark";
            let signature = crypto_tee.sign(&alias, message, None).await.expect("Benchmark operation should succeed");
            
            test_data.push((alias, algorithm, message.to_vec(), signature));
        }
        
        (crypto_tee, test_data)
    });
    
    let (crypto_tee, test_data) = setup;
    
    for (alias, algorithm, message, signature) in &test_data {
        group.bench_with_input(
            BenchmarkId::new("verify", format!("{:?}", algorithm)),
            &(alias.clone(), message.clone(), signature.clone()),
            |b, (alias, message, signature)| {
                b.to_async(&rt).iter(|| async {
                    crypto_tee.verify(alias, message, signature, None).await.expect("Benchmark operation should succeed")
                });
            }
        );
    }
    
    // Cleanup
    rt.block_on(async {
        for (alias, _, _, _) in test_data {
            let _ = crypto_tee.delete_key(&alias).await;
        }
    });
    
    group.finish();
}

/// Benchmark concurrent operations
fn bench_concurrent_signing(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");
    
    let mut group = c.benchmark_group("concurrent_signing");
    
    // Setup
    let setup = rt.block_on(async {
        let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Benchmark operation should succeed");
        let alias = "concurrent_bench_key";
        let options = KeyOptions {
            algorithm: Algorithm::Ed25519, // Use fastest algorithm
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            metadata: None,
        };
        
        crypto_tee.generate_key(alias, options).await.expect("Benchmark operation should succeed");
        crypto_tee
    });
    
    let concurrency_levels = vec![1, 5, 10, 20];
    
    for concurrency in concurrency_levels {
        group.bench_with_input(
            BenchmarkId::new("concurrent_sign", concurrency),
            &concurrency,
            |b, &concurrency| {
                b.to_async(&rt).iter(|| async {
                    let test_data = b"Concurrent signing test data";
                    let mut tasks = Vec::new();
                    
                    for _ in 0..concurrency {
                        let crypto_tee = &setup;
                        let task = crypto_tee.sign("concurrent_bench_key", test_data, None);
                        tasks.push(task);
                    }
                    
                    futures::future::join_all(tasks).await
                });
            }
        );
    }
    
    // Cleanup
    rt.block_on(async {
        let _ = setup.delete_key("concurrent_bench_key").await;
    });
    
    group.finish();
}

/// Benchmark data size impact
fn bench_data_sizes(c: &mut Criterion) {
    let rt = Runtime::new().expect("Benchmark operation should succeed");
    
    let mut group = c.benchmark_group("data_sizes");
    
    // Setup
    let setup = rt.block_on(async {
        let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Benchmark operation should succeed");
        let alias = "size_bench_key";
        let options = KeyOptions {
            algorithm: Algorithm::Ed25519,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            metadata: None,
        };
        
        crypto_tee.generate_key(alias, options).await.expect("Benchmark operation should succeed");
        crypto_tee
    });
    
    let data_sizes = vec![64, 256, 1024, 4096, 16384]; // 64B to 16KB
    
    for size in data_sizes {
        let test_data = vec![0xAB; size];
        
        group.bench_with_input(
            BenchmarkId::new("sign_data_size", size),
            &test_data,
            |b, test_data| {
                b.to_async(&rt).iter(|| async {
                    setup.sign("size_bench_key", test_data, None).await.expect("Benchmark operation should succeed")
                });
            }
        );
    }
    
    // Cleanup
    rt.block_on(async {
        let _ = setup.delete_key("size_bench_key").await;
    });
    
    group.finish();
}

criterion_group!(
    benches,
    bench_key_generation,
    bench_signing,
    bench_verification,
    bench_concurrent_signing,
    bench_data_sizes
);

criterion_main!(benches);