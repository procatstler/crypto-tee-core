//! Health Monitoring Demo
//!
//! This example demonstrates the health monitoring capabilities of CryptoTEE,
//! showing how to perform health checks and monitor TEE status.

use crypto_tee::{CryptoTEE, CryptoTEEBuilder, HealthConfig, HealthStatus};
use std::time::Duration;
use tracing::{info, warn, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("CryptoTEE Health Monitoring Demo");

    // Create CryptoTEE instance
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Perform initial health check
    info!("Performing initial health check...");
    let health_report = crypto_tee.health_check().await?;

    println!("\n=== Health Check Report ===");
    println!("Report ID: {}", health_report.report_id);
    println!("Overall Status: {:?}", health_report.overall_status);
    println!("Check Duration: {}ms", health_report.check_duration_ms);
    println!("Timestamp: {:?}", health_report.timestamp);

    // Display component health
    println!("\n=== Component Health ===");
    for component in &health_report.components {
        let status_icon = match component.status {
            HealthStatus::Healthy => "✅",
            HealthStatus::Degraded => "⚠️",
            HealthStatus::Unhealthy => "❌",
            HealthStatus::Critical => "🔴",
        };

        println!(
            "{} {}: {:?} ({}ms)",
            status_icon,
            component.component,
            component.status,
            component.response_time_ms.unwrap_or(0)
        );
        println!("   Message: {}", component.message);
    }

    // Display TEE health details
    println!("\n=== TEE Health Details ===");
    let tee_health = &health_report.tee_health;
    println!("Available: {}", tee_health.available);
    println!("Hardware Backed: {}", tee_health.hardware_backed);
    println!("Vendor: {} v{}", tee_health.vendor_info.name, tee_health.vendor_info.version);
    println!(
        "Platform: {} v{}",
        tee_health.platform_info.platform_type, tee_health.platform_info.platform_version
    );
    println!("Key Usage: {}/{} keys", tee_health.key_count, tee_health.max_keys);

    if let Some(memory_usage) = tee_health.memory_usage_percent {
        println!("Memory Usage: {memory_usage:.1}%");
    }

    // Display supported algorithms
    println!("\nSupported Algorithms:");
    for algorithm in &tee_health.vendor_info.algorithms {
        println!("  - {algorithm}");
    }

    // Display resource utilization
    println!("\n=== Resource Utilization ===");
    let resources = &health_report.resources;
    println!("CPU Usage: {:.1}%", resources.cpu_percent);

    let memory_percent =
        (resources.memory_used_bytes as f64 / resources.memory_total_bytes as f64) * 100.0;
    println!(
        "Memory Usage: {:.1}% ({} MB / {} MB)",
        memory_percent,
        resources.memory_used_bytes / (1024 * 1024),
        resources.memory_total_bytes / (1024 * 1024)
    );

    let disk_percent =
        (resources.disk_used_bytes as f64 / resources.disk_total_bytes as f64) * 100.0;
    println!(
        "Disk Usage: {:.1}% ({} MB / {} MB)",
        disk_percent,
        resources.disk_used_bytes / (1024 * 1024),
        resources.disk_total_bytes / (1024 * 1024)
    );

    println!("Network Active: {}", resources.network_active);

    // Display performance metrics
    println!("\n=== Performance Metrics ===");
    let perf = &health_report.performance;
    println!("Average Latency: {:.1}ms", perf.avg_latency_ms);
    println!("Operations/Second: {:.1}", perf.ops_per_second);
    println!("Error Rate: {:.2}%", perf.error_rate_percent);
    println!("Queue Depth: {}", perf.queue_depth);
    println!("Throughput: {} MB/s", perf.throughput_bps / (1024 * 1024));

    // Display recommendations
    if !health_report.recommendations.is_empty() {
        println!("\n=== Recommendations ===");
        for (i, recommendation) in health_report.recommendations.iter().enumerate() {
            println!("{}. {}", i + 1, recommendation);
        }
    }

    // Demonstrate health status analysis
    match health_report.overall_status {
        HealthStatus::Healthy => {
            info!("✅ All systems are operating normally");
        }
        HealthStatus::Degraded => {
            warn!("⚠️  Some systems are experiencing minor issues");
        }
        HealthStatus::Unhealthy => {
            warn!("❌ Critical issues detected - immediate attention required");
        }
        HealthStatus::Critical => {
            warn!("🔴 System is in critical state - emergency intervention needed");
        }
    }

    // Demonstrate periodic health monitoring
    println!("\n=== Periodic Health Monitoring ===");
    println!("Running health checks every 10 seconds for 30 seconds...");

    for i in 1..=3 {
        tokio::time::sleep(Duration::from_secs(10)).await;

        let periodic_report = crypto_tee.health_check().await?;
        println!(
            "Check {}: Status = {:?}, Duration = {}ms",
            i, periodic_report.overall_status, periodic_report.check_duration_ms
        );

        // Show any status changes
        if periodic_report.overall_status != health_report.overall_status {
            println!(
                "⚠️  Health status changed from {:?} to {:?}",
                health_report.overall_status, periodic_report.overall_status
            );
        }
    }

    println!("\n=== Health Monitoring Demo Complete ===");

    Ok(())
}

/// Example of custom health monitoring configuration
#[allow(dead_code)]
async fn custom_health_monitoring_example() -> Result<(), Box<dyn std::error::Error>> {
    // Create custom health configuration with stricter thresholds
    let _custom_config = HealthConfig {
        detailed_checks: true,
        check_timeout: Duration::from_secs(15),
        collect_performance_metrics: true,
        monitor_resources: true,
        check_attestation: false,
        warning_thresholds: crypto_tee::health::HealthThresholds {
            cpu_percent: 50.0,
            memory_percent: 60.0,
            disk_percent: 80.0,
            avg_latency_ms: 50.0,
            error_rate_percent: 0.5,
            response_time_ms: 500,
        },
        critical_thresholds: crypto_tee::health::HealthThresholds {
            cpu_percent: 80.0,
            memory_percent: 85.0,
            disk_percent: 95.0,
            avg_latency_ms: 200.0,
            error_rate_percent: 2.0,
            response_time_ms: 2000,
        },
    };

    // Note: In a real implementation, you would create a custom HealthMonitor
    // with this configuration and integrate it with your CryptoTEE instance

    Ok(())
}
