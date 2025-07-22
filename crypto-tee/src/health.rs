//! Health Check and Monitoring System
//!
//! This module provides comprehensive health monitoring capabilities for TEE status,
//! system resources, and operational metrics to ensure system reliability.

use crate::error::CryptoTEEResult;
use crypto_tee_platform::PlatformTEE;
use crypto_tee_vendor::VendorTEE;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant, SystemTime},
};
use tokio::sync::RwLock;
use tracing::{debug, info, warn};

/// Overall system health status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HealthStatus {
    /// All systems operational
    Healthy,
    /// Some non-critical issues detected
    Degraded,
    /// Critical issues detected
    Unhealthy,
    /// System unavailable
    Critical,
}

/// Component-specific health status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    /// Component name
    pub component: String,
    /// Health status
    pub status: HealthStatus,
    /// Last check timestamp
    pub last_check: SystemTime,
    /// Status message
    pub message: String,
    /// Response time in milliseconds
    pub response_time_ms: Option<u64>,
    /// Additional metrics
    pub metrics: HashMap<String, serde_json::Value>,
}

/// TEE-specific health information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeHealth {
    /// TEE availability
    pub available: bool,
    /// Hardware backing status
    pub hardware_backed: bool,
    /// Vendor information
    pub vendor_info: VendorInfo,
    /// Platform information
    pub platform_info: PlatformInfo,
    /// Current key count
    pub key_count: u32,
    /// Maximum supported keys
    pub max_keys: u32,
    /// Memory usage percentage
    pub memory_usage_percent: Option<f64>,
    /// Active sessions count
    pub active_sessions: u32,
    /// Last attestation time
    pub last_attestation: Option<SystemTime>,
    /// Attestation status
    pub attestation_valid: bool,
}

/// Vendor information for health monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorInfo {
    /// Vendor name
    pub name: String,
    /// Vendor version
    pub version: String,
    /// Supported algorithms
    pub algorithms: Vec<String>,
    /// Vendor-specific status
    pub status: String,
    /// Custom vendor metrics
    pub custom_metrics: HashMap<String, serde_json::Value>,
}

/// Platform information for health monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformInfo {
    /// Platform type (iOS, Android, Linux, etc.)
    pub platform_type: String,
    /// Platform version
    pub platform_version: String,
    /// TEE implementation details
    pub tee_implementation: String,
    /// Security level
    pub security_level: String,
    /// Platform-specific metrics
    pub custom_metrics: HashMap<String, serde_json::Value>,
}

/// System resource utilization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUtilization {
    /// CPU usage percentage
    pub cpu_percent: f64,
    /// Memory usage in bytes
    pub memory_used_bytes: u64,
    /// Total memory in bytes
    pub memory_total_bytes: u64,
    /// Disk usage in bytes
    pub disk_used_bytes: u64,
    /// Total disk space in bytes
    pub disk_total_bytes: u64,
    /// Network activity
    pub network_active: bool,
}

/// Performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Average operation latency
    pub avg_latency_ms: f64,
    /// Operations per second
    pub ops_per_second: f64,
    /// Error rate percentage
    pub error_rate_percent: f64,
    /// Queue depth
    pub queue_depth: u32,
    /// Throughput in bytes per second
    pub throughput_bps: u64,
}

/// Comprehensive health report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    /// Overall system status
    pub overall_status: HealthStatus,
    /// Report timestamp
    pub timestamp: SystemTime,
    /// Report ID
    pub report_id: String,
    /// Individual component health
    pub components: Vec<ComponentHealth>,
    /// TEE-specific health
    pub tee_health: TeeHealth,
    /// Resource utilization
    pub resources: ResourceUtilization,
    /// Performance metrics
    pub performance: PerformanceMetrics,
    /// Health check duration
    pub check_duration_ms: u64,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Health check configuration
#[derive(Debug, Clone)]
pub struct HealthConfig {
    /// Enable detailed component checks
    pub detailed_checks: bool,
    /// Check timeout
    pub check_timeout: Duration,
    /// Performance metrics collection
    pub collect_performance_metrics: bool,
    /// Resource monitoring
    pub monitor_resources: bool,
    /// Enable attestation checks
    pub check_attestation: bool,
    /// Warning thresholds
    pub warning_thresholds: HealthThresholds,
    /// Critical thresholds
    pub critical_thresholds: HealthThresholds,
}

/// Health monitoring thresholds
#[derive(Debug, Clone)]
pub struct HealthThresholds {
    /// CPU usage threshold (percentage)
    pub cpu_percent: f64,
    /// Memory usage threshold (percentage)
    pub memory_percent: f64,
    /// Disk usage threshold (percentage)
    pub disk_percent: f64,
    /// Average latency threshold (ms)
    pub avg_latency_ms: f64,
    /// Error rate threshold (percentage)
    pub error_rate_percent: f64,
    /// Response time threshold (ms)
    pub response_time_ms: u64,
}

/// Health monitoring manager
pub struct HealthMonitor {
    /// Platform TEE reference
    platform: Arc<RwLock<Box<dyn PlatformTEE>>>,
    /// Vendor TEE reference
    vendor: Arc<RwLock<Box<dyn VendorTEE>>>,
    /// Health configuration
    config: HealthConfig,
    /// Performance metrics history
    metrics_history: Arc<RwLock<Vec<PerformanceMetrics>>>,
    /// Last health report
    last_report: Arc<RwLock<Option<HealthReport>>>,
}

impl HealthMonitor {
    /// Create new health monitor
    pub fn new(
        platform: Arc<RwLock<Box<dyn PlatformTEE>>>,
        vendor: Arc<RwLock<Box<dyn VendorTEE>>>,
        config: HealthConfig,
    ) -> Self {
        Self {
            platform,
            vendor,
            config,
            metrics_history: Arc::new(RwLock::new(Vec::new())),
            last_report: Arc::new(RwLock::new(None)),
        }
    }

    /// Perform comprehensive health check
    pub async fn check_health(&self) -> CryptoTEEResult<HealthReport> {
        let start_time = Instant::now();
        info!("Starting comprehensive health check");

        let mut components = Vec::new();
        let mut recommendations = Vec::new();

        // Check TEE health
        let tee_health = self.check_tee_health().await?;
        components.push(ComponentHealth {
            component: "TEE".to_string(),
            status: if tee_health.available {
                HealthStatus::Healthy
            } else {
                HealthStatus::Critical
            },
            last_check: SystemTime::now(),
            message: if tee_health.available {
                "TEE is operational".to_string()
            } else {
                "TEE is unavailable".to_string()
            },
            response_time_ms: None,
            metrics: HashMap::new(),
        });

        // Check platform health
        let platform_component = self.check_platform_health().await?;
        components.push(platform_component);

        // Check vendor health
        let vendor_component = self.check_vendor_health().await?;
        components.push(vendor_component);

        // Check resource utilization
        let resources = if self.config.monitor_resources {
            self.check_resource_utilization().await
        } else {
            ResourceUtilization {
                cpu_percent: 0.0,
                memory_used_bytes: 0,
                memory_total_bytes: 0,
                disk_used_bytes: 0,
                disk_total_bytes: 0,
                network_active: false,
            }
        };

        // Check performance metrics
        let performance = if self.config.collect_performance_metrics {
            self.collect_performance_metrics().await
        } else {
            PerformanceMetrics {
                avg_latency_ms: 0.0,
                ops_per_second: 0.0,
                error_rate_percent: 0.0,
                queue_depth: 0,
                throughput_bps: 0,
            }
        };

        // Analyze overall health status
        let overall_status = self.determine_overall_status(&components, &resources, &performance);

        // Generate recommendations
        if resources.cpu_percent > self.config.warning_thresholds.cpu_percent {
            recommendations.push("High CPU usage detected - consider reducing workload".to_string());
        }
        if (resources.memory_used_bytes as f64 / resources.memory_total_bytes as f64) * 100.0
            > self.config.warning_thresholds.memory_percent
        {
            recommendations.push("High memory usage detected - monitor for memory leaks".to_string());
        }
        if performance.error_rate_percent > self.config.warning_thresholds.error_rate_percent {
            recommendations.push("High error rate detected - check system logs".to_string());
        }
        if tee_health.key_count as f64 / tee_health.max_keys as f64 > 0.8 {
            recommendations.push("Key storage approaching capacity - consider cleanup".to_string());
        }

        let check_duration_ms = start_time.elapsed().as_millis() as u64;

        let report = HealthReport {
            overall_status,
            timestamp: SystemTime::now(),
            report_id: self.generate_report_id(),
            components,
            tee_health,
            resources,
            performance,
            check_duration_ms,
            recommendations,
        };

        // Store report
        *self.last_report.write().await = Some(report.clone());

        info!(
            "Health check completed in {}ms with status: {:?}",
            check_duration_ms, overall_status
        );

        Ok(report)
    }

    /// Get last health report
    pub async fn get_last_report(&self) -> Option<HealthReport> {
        self.last_report.read().await.clone()
    }

    /// Check TEE-specific health
    async fn check_tee_health(&self) -> CryptoTEEResult<TeeHealth> {
        debug!("Checking TEE health");

        let platform = self.platform.read().await;
        let vendor = self.vendor.read().await;

        // Probe vendor capabilities
        let vendor_caps = vendor.probe().await.unwrap_or_else(|_| {
            warn!("Failed to probe vendor capabilities");
            crypto_tee_vendor::types::VendorCapabilities {
                name: "Unknown".to_string(),
                version: "Unknown".to_string(),
                algorithms: vec![],
                max_keys: 0,
                hardware_backed: false,
                attestation: false,
                features: crypto_tee_vendor::types::VendorFeatures {
                    hardware_backed: false,
                    secure_key_import: false,
                    secure_key_export: false,
                    attestation: false,
                    strongbox: false,
                    biometric_bound: false,
                    secure_deletion: false,
                },
            }
        });

        // Get basic platform information
        let platform_name = platform.name();
        let platform_version = platform.version();

        let available = vendor_caps.max_keys > 0;

        Ok(TeeHealth {
            available,
            hardware_backed: vendor_caps.hardware_backed,
            vendor_info: VendorInfo {
                name: vendor_caps.name,
                version: vendor_caps.version,
                algorithms: vendor_caps.algorithms.iter().map(|a| format!("{:?}", a)).collect(),
                status: if available { "Available" } else { "Unavailable" }.to_string(),
                custom_metrics: HashMap::new(),
            },
            platform_info: PlatformInfo {
                platform_type: platform_name.to_string(),
                platform_version: platform_version.to_string(),
                tee_implementation: "Generic".to_string(),
                security_level: "Standard".to_string(),
                custom_metrics: HashMap::new(),
            },
            key_count: 0, // TODO: Get actual key count from key manager
            max_keys: vendor_caps.max_keys,
            memory_usage_percent: None, // TODO: Implement memory usage tracking
            active_sessions: 0,         // TODO: Track active sessions
            last_attestation: None,     // TODO: Implement attestation tracking
            attestation_valid: vendor_caps.attestation,
        })
    }

    /// Check platform component health
    async fn check_platform_health(&self) -> CryptoTEEResult<ComponentHealth> {
        let check_start = Instant::now();
        debug!("Checking platform health");

        let platform = self.platform.read().await;
        let mut metrics = HashMap::new();

        // Check platform health using available methods
        let platform_name = platform.name();
        let platform_version = platform.version();
        let requires_auth = platform.requires_authentication().await;
        
        metrics.insert("platform_name".to_string(), serde_json::json!(platform_name));
        metrics.insert("platform_version".to_string(), serde_json::json!(platform_version));
        metrics.insert("requires_authentication".to_string(), serde_json::json!(requires_auth));

        let (status, message) = (
            HealthStatus::Healthy,
            format!("Platform {} v{} is operational", platform_name, platform_version)
        );

        let response_time_ms = check_start.elapsed().as_millis() as u64;

        Ok(ComponentHealth {
            component: "Platform".to_string(),
            status,
            last_check: SystemTime::now(),
            message,
            response_time_ms: Some(response_time_ms),
            metrics,
        })
    }

    /// Check vendor component health
    async fn check_vendor_health(&self) -> CryptoTEEResult<ComponentHealth> {
        let check_start = Instant::now();
        debug!("Checking vendor health");

        let vendor = self.vendor.read().await;
        let mut metrics = HashMap::new();

        let (status, message) = match vendor.probe().await {
            Ok(caps) => {
                metrics.insert("max_keys".to_string(), serde_json::json!(caps.max_keys));
                metrics.insert("hardware_backed".to_string(), serde_json::json!(caps.hardware_backed));
                metrics.insert("algorithm_count".to_string(), serde_json::json!(caps.algorithms.len()));

                (HealthStatus::Healthy, format!("Vendor {} is operational", caps.name))
            }
            Err(e) => {
                (HealthStatus::Critical, format!("Vendor health check failed: {}", e))
            }
        };

        let response_time_ms = check_start.elapsed().as_millis() as u64;

        Ok(ComponentHealth {
            component: "Vendor".to_string(),
            status,
            last_check: SystemTime::now(),
            message,
            response_time_ms: Some(response_time_ms),
            metrics,
        })
    }

    /// Check resource utilization (simplified implementation)
    async fn check_resource_utilization(&self) -> ResourceUtilization {
        debug!("Checking resource utilization");

        // TODO: Implement actual resource monitoring
        // This is a placeholder implementation
        ResourceUtilization {
            cpu_percent: 15.0,   // Mock data
            memory_used_bytes: 1024 * 1024 * 100, // 100MB
            memory_total_bytes: 1024 * 1024 * 1024, // 1GB
            disk_used_bytes: 1024 * 1024 * 500,   // 500MB
            disk_total_bytes: 1024 * 1024 * 1024 * 10, // 10GB
            network_active: true,
        }
    }

    /// Collect performance metrics
    async fn collect_performance_metrics(&self) -> PerformanceMetrics {
        debug!("Collecting performance metrics");

        // TODO: Implement actual performance metrics collection
        // This is a placeholder implementation
        PerformanceMetrics {
            avg_latency_ms: 5.2,
            ops_per_second: 150.0,
            error_rate_percent: 0.1,
            queue_depth: 2,
            throughput_bps: 1024 * 1024, // 1MB/s
        }
    }

    /// Determine overall health status
    fn determine_overall_status(
        &self,
        components: &[ComponentHealth],
        resources: &ResourceUtilization,
        performance: &PerformanceMetrics,
    ) -> HealthStatus {
        // Check for critical component failures
        if components.iter().any(|c| c.status == HealthStatus::Critical) {
            return HealthStatus::Critical;
        }

        // Check resource thresholds
        let memory_percent = (resources.memory_used_bytes as f64 / resources.memory_total_bytes as f64) * 100.0;
        let disk_percent = (resources.disk_used_bytes as f64 / resources.disk_total_bytes as f64) * 100.0;

        if resources.cpu_percent > self.config.critical_thresholds.cpu_percent
            || memory_percent > self.config.critical_thresholds.memory_percent
            || disk_percent > self.config.critical_thresholds.disk_percent
            || performance.error_rate_percent > self.config.critical_thresholds.error_rate_percent
        {
            return HealthStatus::Critical;
        }

        // Check for degraded conditions
        if components.iter().any(|c| c.status == HealthStatus::Unhealthy)
            || resources.cpu_percent > self.config.warning_thresholds.cpu_percent
            || memory_percent > self.config.warning_thresholds.memory_percent
            || disk_percent > self.config.warning_thresholds.disk_percent
            || performance.error_rate_percent > self.config.warning_thresholds.error_rate_percent
        {
            return HealthStatus::Degraded;
        }

        // Check for minor issues
        if components.iter().any(|c| c.status == HealthStatus::Degraded) {
            return HealthStatus::Degraded;
        }

        HealthStatus::Healthy
    }

    /// Generate unique report ID
    fn generate_report_id(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        format!("health_report_{}_{:x}", timestamp, rand::random::<u32>())
    }
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            detailed_checks: true,
            check_timeout: Duration::from_secs(30),
            collect_performance_metrics: true,
            monitor_resources: true,
            check_attestation: false,
            warning_thresholds: HealthThresholds {
                cpu_percent: 70.0,
                memory_percent: 80.0,
                disk_percent: 90.0,
                avg_latency_ms: 100.0,
                error_rate_percent: 1.0,
                response_time_ms: 1000,
            },
            critical_thresholds: HealthThresholds {
                cpu_percent: 90.0,
                memory_percent: 95.0,
                disk_percent: 98.0,
                avg_latency_ms: 500.0,
                error_rate_percent: 5.0,
                response_time_ms: 5000,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // Mock TEE implementations for testing
    struct MockPlatformTEE;
    struct MockVendorTEE;

    #[async_trait::async_trait]
    impl PlatformTEE for MockPlatformTEE {
        fn name(&self) -> &str {
            "MockPlatform"
        }

        fn version(&self) -> &str {
            "1.0.0"
        }

        async fn detect_vendors(&self) -> Vec<Box<dyn VendorTEE>> {
            vec![Box::new(MockVendorTEE)]
        }

        async fn select_best_vendor(&self) -> Result<Box<dyn VendorTEE>, crypto_tee_platform::error::PlatformError> {
            Ok(Box::new(MockVendorTEE))
        }

        async fn get_vendor(&self, _name: &str) -> Result<Box<dyn VendorTEE>, crypto_tee_platform::error::PlatformError> {
            Ok(Box::new(MockVendorTEE))
        }

        async fn authenticate(&self, _challenge: &[u8]) -> Result<crypto_tee_platform::types::AuthResult, crypto_tee_platform::error::PlatformError> {
            Ok(crypto_tee_platform::types::AuthResult {
                success: true,
                method: crypto_tee_platform::types::AuthMethod::None,
                session_token: Some(b"mock_token".to_vec()),
                valid_until: None,
            })
        }

        async fn requires_authentication(&self) -> bool {
            false
        }

        async fn configure(&mut self, _config: crypto_tee_platform::types::PlatformConfig) -> Result<(), crypto_tee_platform::error::PlatformError> {
            Ok(())
        }

        fn get_config(&self) -> &crypto_tee_platform::types::PlatformConfig {
            use std::sync::OnceLock;
            static CONFIG: OnceLock<crypto_tee_platform::types::PlatformConfig> = OnceLock::new();
            CONFIG.get_or_init(crypto_tee_platform::types::PlatformConfig::default)
        }

        async fn wrap_key_handle(&self, vendor_handle: crypto_tee_vendor::types::VendorKeyHandle) -> Result<crypto_tee_platform::traits::PlatformKeyHandle, crypto_tee_platform::error::PlatformError> {
            Ok(crypto_tee_platform::traits::PlatformKeyHandle {
                vendor_handle,
                platform: "MockPlatform".to_string(),
                requires_auth: false,
                created_at: std::time::SystemTime::now(),
                last_used: None,
                metadata: None,
            })
        }

        async fn unwrap_key_handle(&self, platform_handle: &crypto_tee_platform::traits::PlatformKeyHandle) -> Result<crypto_tee_vendor::types::VendorKeyHandle, crypto_tee_platform::error::PlatformError> {
            Ok(platform_handle.vendor_handle.clone())
        }
    }

    #[async_trait::async_trait]
    impl VendorTEE for MockVendorTEE {
        async fn probe(&self) -> Result<crypto_tee_vendor::types::VendorCapabilities, crypto_tee_vendor::error::VendorError> {
            Ok(crypto_tee_vendor::types::VendorCapabilities {
                name: "MockVendor".to_string(),
                version: "1.0.0".to_string(),
                algorithms: vec![crypto_tee_vendor::types::Algorithm::Ed25519],
                max_keys: 100,
                hardware_backed: true,
                attestation: true,
                features: crypto_tee_vendor::types::VendorFeatures {
                    hardware_backed: true,
                    secure_key_import: true,
                    secure_key_export: true,
                    attestation: true,
                    strongbox: false,
                    biometric_bound: false,
                    secure_deletion: true,
                },
            })
        }

        async fn generate_key(&self, _params: &crypto_tee_vendor::types::KeyGenParams) -> Result<crypto_tee_vendor::types::VendorKeyHandle, crypto_tee_vendor::error::VendorError> {
            Ok(crypto_tee_vendor::types::VendorKeyHandle {
                id: "test_key".to_string(),
                algorithm: crypto_tee_vendor::types::Algorithm::Ed25519,
                vendor: "MockVendor".to_string(),
                hardware_backed: true,
                vendor_data: None,
            })
        }

        async fn import_key(&self, _key_data: &[u8], _params: &crypto_tee_vendor::types::KeyGenParams) -> Result<crypto_tee_vendor::types::VendorKeyHandle, crypto_tee_vendor::error::VendorError> {
            Ok(crypto_tee_vendor::types::VendorKeyHandle {
                id: "imported_key".to_string(),
                algorithm: crypto_tee_vendor::types::Algorithm::Ed25519,
                vendor: "MockVendor".to_string(),
                hardware_backed: true,
                vendor_data: None,
            })
        }

        async fn delete_key(&self, _handle: &crypto_tee_vendor::types::VendorKeyHandle) -> Result<(), crypto_tee_vendor::error::VendorError> {
            Ok(())
        }

        async fn sign(&self, _handle: &crypto_tee_vendor::types::VendorKeyHandle, _data: &[u8]) -> Result<crypto_tee_vendor::types::Signature, crypto_tee_vendor::error::VendorError> {
            Ok(crypto_tee_vendor::types::Signature {
                algorithm: crypto_tee_vendor::types::Algorithm::Ed25519,
                data: b"mock_signature".to_vec(),
            })
        }

        async fn verify(&self, _handle: &crypto_tee_vendor::types::VendorKeyHandle, _data: &[u8], _signature: &crypto_tee_vendor::types::Signature) -> Result<bool, crypto_tee_vendor::error::VendorError> {
            Ok(true)
        }

        async fn export_key(&self, _handle: &crypto_tee_vendor::types::VendorKeyHandle) -> Result<Vec<u8>, crypto_tee_vendor::error::VendorError> {
            Ok(b"mock_key_data".to_vec())
        }

        async fn get_attestation(&self) -> Result<crypto_tee_vendor::types::Attestation, crypto_tee_vendor::error::VendorError> {
            Ok(crypto_tee_vendor::types::Attestation {
                format: crypto_tee_vendor::types::AttestationFormat::Custom("MockAttestation".to_string()),
                data: b"mock_attestation_data".to_vec(),
                certificates: vec![],
            })
        }

        async fn get_key_attestation(&self, _handle: &crypto_tee_vendor::types::VendorKeyHandle) -> Result<crypto_tee_vendor::types::Attestation, crypto_tee_vendor::error::VendorError> {
            Ok(crypto_tee_vendor::types::Attestation {
                format: crypto_tee_vendor::types::AttestationFormat::Custom("MockKeyAttestation".to_string()),
                data: b"mock_key_attestation_data".to_vec(),
                certificates: vec![],
            })
        }

        async fn list_keys(&self) -> Result<Vec<crypto_tee_vendor::types::VendorKeyHandle>, crypto_tee_vendor::error::VendorError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_health_check() {
        let platform: Arc<RwLock<Box<dyn PlatformTEE>>> = Arc::new(RwLock::new(Box::new(MockPlatformTEE)));
        let vendor: Arc<RwLock<Box<dyn VendorTEE>>> = Arc::new(RwLock::new(Box::new(MockVendorTEE)));
        let config = HealthConfig::default();

        let health_monitor = HealthMonitor::new(platform, vendor, config);
        let report = health_monitor.check_health().await.unwrap();

        assert_eq!(report.overall_status, HealthStatus::Healthy);
        assert!(report.components.len() >= 3); // TEE, Platform, Vendor
        assert!(report.tee_health.available);
        assert!(report.check_duration_ms > 0);
    }

    #[tokio::test]
    async fn test_health_status_determination() {
        let platform: Arc<RwLock<Box<dyn PlatformTEE>>> = Arc::new(RwLock::new(Box::new(MockPlatformTEE)));
        let vendor: Arc<RwLock<Box<dyn VendorTEE>>> = Arc::new(RwLock::new(Box::new(MockVendorTEE)));
        let config = HealthConfig::default();

        let health_monitor = HealthMonitor::new(platform, vendor, config);

        // Test healthy status
        let components = vec![ComponentHealth {
            component: "Test".to_string(),
            status: HealthStatus::Healthy,
            last_check: SystemTime::now(),
            message: "OK".to_string(),
            response_time_ms: Some(10),
            metrics: HashMap::new(),
        }];

        let resources = ResourceUtilization {
            cpu_percent: 50.0,
            memory_used_bytes: 1024,
            memory_total_bytes: 2048,
            disk_used_bytes: 1024,
            disk_total_bytes: 4096,
            network_active: true,
        };

        let performance = PerformanceMetrics {
            avg_latency_ms: 10.0,
            ops_per_second: 100.0,
            error_rate_percent: 0.1,
            queue_depth: 1,
            throughput_bps: 1024,
        };

        let status = health_monitor.determine_overall_status(&components, &resources, &performance);
        assert_eq!(status, HealthStatus::Healthy);
    }
}