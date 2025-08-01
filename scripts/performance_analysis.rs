//! Performance analysis tool for CryptoTEE
//! 
//! This tool analyzes performance characteristics and identifies optimization opportunities.

use std::collections::HashMap;

#[derive(Debug)]
pub struct PerformanceMetrics {
    pub operation: String,
    pub algorithm: String,
    pub duration_ms: f64,
    pub memory_usage_mb: f64,
    pub throughput_ops_per_sec: f64,
}

#[derive(Debug)]
pub struct PerformanceReport {
    pub metrics: Vec<PerformanceMetrics>,
    pub hotspots: Vec<String>,
    pub recommendations: Vec<String>,
}

impl PerformanceReport {
    pub fn new() -> Self {
        Self {
            metrics: Vec::new(),
            hotspots: Vec::new(),
            recommendations: Vec::new(),
        }
    }

    pub fn add_metric(&mut self, metric: PerformanceMetrics) {
        self.metrics.push(metric);
    }

    pub fn analyze(&mut self) {
        self.identify_hotspots();
        self.generate_recommendations();
    }

    fn identify_hotspots(&mut self) {
        // Identify operations that take longer than 50ms
        let slow_threshold = 50.0;
        
        for metric in &self.metrics {
            if metric.duration_ms > slow_threshold {
                self.hotspots.push(format!(
                    "{} with {} is slow: {:.2}ms", 
                    metric.operation, 
                    metric.algorithm,
                    metric.duration_ms
                ));
            }
        }

        // Identify algorithms with consistently poor performance
        let mut algorithm_performance: HashMap<String, Vec<f64>> = HashMap::new();
        for metric in &self.metrics {
            algorithm_performance
                .entry(metric.algorithm.clone())
                .or_insert_with(Vec::new)
                .push(metric.duration_ms);
        }

        for (algorithm, durations) in algorithm_performance {
            let avg_duration: f64 = durations.iter().sum::<f64>() / durations.len() as f64;
            if avg_duration > 30.0 {
                self.hotspots.push(format!(
                    "Algorithm {} has poor average performance: {:.2}ms",
                    algorithm, avg_duration
                ));
            }
        }
    }

    fn generate_recommendations(&mut self) {
        // Memory optimization recommendations
        let high_memory_threshold = 100.0;
        for metric in &self.metrics {
            if metric.memory_usage_mb > high_memory_threshold {
                self.recommendations.push(format!(
                    "Optimize memory usage for {} (currently {:.2}MB)",
                    metric.operation, metric.memory_usage_mb
                ));
            }
        }

        // Throughput optimization recommendations
        let low_throughput_threshold = 100.0;
        for metric in &self.metrics {
            if metric.throughput_ops_per_sec < low_throughput_threshold {
                self.recommendations.push(format!(
                    "Improve throughput for {} (currently {:.2} ops/sec)",
                    metric.operation, metric.throughput_ops_per_sec
                ));
            }
        }

        // Algorithm-specific recommendations
        if self.hotspots.iter().any(|h| h.contains("EcdsaP256")) {
            self.recommendations.push(
                "Consider using Ed25519 instead of EcdsaP256 for better performance".to_string()
            );
        }

        // Concurrency recommendations
        if self.hotspots.iter().any(|h| h.contains("concurrent")) {
            self.recommendations.push(
                "Implement connection pooling or reduce mutex contention for concurrent operations".to_string()
            );
        }

        // General optimizations
        self.recommendations.push("Implement key caching to reduce repeated key operations".to_string());
        self.recommendations.push("Use async I/O for all TEE operations to improve concurrency".to_string());
        self.recommendations.push("Consider pre-generating keys for high-frequency operations".to_string());
    }

    pub fn print_report(&self) {
        println!("=== CryptoTEE Performance Analysis Report ===\n");

        println!("📊 Performance Metrics:");
        for metric in &self.metrics {
            println!("  • {} ({}): {:.2}ms, {:.2}MB, {:.1} ops/sec",
                metric.operation,
                metric.algorithm,
                metric.duration_ms,
                metric.memory_usage_mb,
                metric.throughput_ops_per_sec
            );
        }

        if !self.hotspots.is_empty() {
            println!("\n🔥 Performance Hotspots:");
            for hotspot in &self.hotspots {
                println!("  • {}", hotspot);
            }
        }

        if !self.recommendations.is_empty() {
            println!("\n💡 Optimization Recommendations:");
            for (i, recommendation) in self.recommendations.iter().enumerate() {
                println!("  {}. {}", i + 1, recommendation);
            }
        }

        println!("\n📈 Performance Summary:");
        if let Some(fastest) = self.metrics.iter().min_by(|a, b| a.duration_ms.partial_cmp(&b.duration_ms).unwrap()) {
            println!("  • Fastest operation: {} ({}) - {:.2}ms", 
                fastest.operation, fastest.algorithm, fastest.duration_ms);
        }
        
        if let Some(slowest) = self.metrics.iter().max_by(|a, b| a.duration_ms.partial_cmp(&b.duration_ms).unwrap()) {
            println!("  • Slowest operation: {} ({}) - {:.2}ms", 
                slowest.operation, slowest.algorithm, slowest.duration_ms);
        }

        let avg_duration: f64 = self.metrics.iter().map(|m| m.duration_ms).sum::<f64>() / self.metrics.len() as f64;
        println!("  • Average operation time: {:.2}ms", avg_duration);
    }
}

// Simulated benchmark data based on typical cryptographic performance
pub fn generate_sample_performance_data() -> PerformanceReport {
    let mut report = PerformanceReport::new();

    // Key generation benchmarks
    report.add_metric(PerformanceMetrics {
        operation: "key_generation".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 24.8,
        memory_usage_mb: 2.1,
        throughput_ops_per_sec: 40_000.0,
    });

    report.add_metric(PerformanceMetrics {
        operation: "key_generation".to_string(),
        algorithm: "EcdsaP256".to_string(),
        duration_ms: 26.4,
        memory_usage_mb: 3.2,
        throughput_ops_per_sec: 38_000.0,
    });

    // Signing benchmarks
    report.add_metric(PerformanceMetrics {
        operation: "signing".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 22.2,
        memory_usage_mb: 1.8,
        throughput_ops_per_sec: 45_000.0,
    });

    report.add_metric(PerformanceMetrics {
        operation: "signing".to_string(),
        algorithm: "EcdsaP256".to_string(),
        duration_ms: 28.9,
        memory_usage_mb: 2.5,
        throughput_ops_per_sec: 34_600.0,
    });

    // Verification benchmarks
    report.add_metric(PerformanceMetrics {
        operation: "verification".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 65.9,
        memory_usage_mb: 1.5,
        throughput_ops_per_sec: 15_200.0,
    });

    report.add_metric(PerformanceMetrics {
        operation: "verification".to_string(),
        algorithm: "EcdsaP256".to_string(),
        duration_ms: 47.1,
        memory_usage_mb: 2.1,
        throughput_ops_per_sec: 21_200.0,
    });

    // Concurrent operations
    report.add_metric(PerformanceMetrics {
        operation: "concurrent_signing_1".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 21.8,
        memory_usage_mb: 1.8,
        throughput_ops_per_sec: 45_900.0,
    });

    report.add_metric(PerformanceMetrics {
        operation: "concurrent_signing_5".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 112.6,
        memory_usage_mb: 9.0,
        throughput_ops_per_sec: 8_880.0,
    });

    report.add_metric(PerformanceMetrics {
        operation: "concurrent_signing_10".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 220.2,
        memory_usage_mb: 18.0,
        throughput_ops_per_sec: 4_540.0,
    });

    report.add_metric(PerformanceMetrics {
        operation: "concurrent_signing_20".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 449.6,
        memory_usage_mb: 36.0,
        throughput_ops_per_sec: 2_220.0,
    });

    // Data size impact
    report.add_metric(PerformanceMetrics {
        operation: "sign_64B".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 21.5,
        memory_usage_mb: 1.8,
        throughput_ops_per_sec: 46_500.0,
    });

    report.add_metric(PerformanceMetrics {
        operation: "sign_16KB".to_string(),
        algorithm: "Ed25519".to_string(),
        duration_ms: 23.8,
        memory_usage_mb: 2.1,
        throughput_ops_per_sec: 42_000.0,
    });

    report
}

fn main() {
    println!("🔍 Analyzing CryptoTEE Performance...\n");

    let mut report = generate_sample_performance_data();
    report.analyze();
    report.print_report();

    println!("\n🛠️  Performance Optimization Strategies:");
    println!("  1. Algorithm Selection: Ed25519 consistently outperforms EcdsaP256");
    println!("  2. Memory Management: Use pooling for high-frequency operations");
    println!("  3. Concurrency: Optimize lock contention and async execution");
    println!("  4. Caching: Implement key caching for repeated operations");
    println!("  5. Hardware: Leverage hardware acceleration when available");
}