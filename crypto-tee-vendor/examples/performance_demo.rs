//! Performance demonstration comparing standard and optimized mock vendors

#![allow(clippy::uninlined_format_args)]

use crypto_tee_vendor::{
    mock::{optimized::OptimizedMockVendor, MockVendor},
    traits::VendorTEE,
    types::{Algorithm, KeyGenParams, KeyUsage},
};
use std::time::Instant;

async fn benchmark_vendor<T: VendorTEE>(
    vendor: &T,
    vendor_name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Benchmarking {} ===", vendor_name);

    let params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: false,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    // Key generation benchmark
    let start = Instant::now();
    let key_handle = vendor.generate_key(&params).await?;
    let key_gen_time = start.elapsed();
    println!("Key generation: {:?}", key_gen_time);

    let test_data = b"Performance test data for benchmarking purposes";

    // Signing benchmark
    let start = Instant::now();
    let signature = vendor.sign(&key_handle, test_data).await?;
    let sign_time = start.elapsed();
    println!("Signing: {:?}", sign_time);

    // First verification (cache miss)
    let start = Instant::now();
    let result1 = vendor.verify(&key_handle, test_data, &signature).await?;
    let first_verify_time = start.elapsed();
    println!("First verification: {:?}", first_verify_time);
    assert!(result1);

    // Second verification (cache hit for optimized)
    let start = Instant::now();
    let result2 = vendor.verify(&key_handle, test_data, &signature).await?;
    let second_verify_time = start.elapsed();
    println!("Second verification: {:?}", second_verify_time);
    assert!(result2);

    // Multiple verifications benchmark
    let start = Instant::now();
    for _ in 0..100 {
        let result = vendor.verify(&key_handle, test_data, &signature).await?;
        assert!(result);
    }
    let batch_verify_time = start.elapsed();
    println!(
        "100 verifications: {:?} ({:?} per verification)",
        batch_verify_time,
        batch_verify_time / 100
    );

    println!();
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("CryptoTEE Performance Optimization Demo");
    println!("=====================================\n");

    // Benchmark standard mock vendor
    let standard_vendor = MockVendor::new("standard");
    benchmark_vendor(&standard_vendor, "Standard Mock Vendor").await?;

    // Benchmark optimized mock vendor
    let optimized_vendor = OptimizedMockVendor::new("optimized");
    benchmark_vendor(&optimized_vendor, "Optimized Mock Vendor").await?;

    // Show cache statistics for optimized vendor
    let cache_stats = optimized_vendor.get_cache_stats();
    println!("=== Optimized Vendor Cache Statistics ===");
    println!("Verification cache entries: {}", cache_stats.verification.total_entries);
    println!("Public key cache entries: {}", cache_stats.public_key.total_entries);
    println!("Public key cache hit ratio: {:.2}%", cache_stats.public_key.hit_ratio * 100.0);
    println!("Memory pool stats: {:?}", cache_stats.memory_pool);

    println!("\n=== Performance Comparison Summary ===");
    println!("The optimized vendor should show:");
    println!("1. Similar first-time operation performance");
    println!("2. Faster repeated verifications due to caching");
    println!("3. Better memory efficiency with buffer pooling");
    println!("4. Lower latency for concurrent operations");

    Ok(())
}
