//! Plugin development example
//!
//! This example demonstrates how to create custom plugins to extend
//! CryptoTEE functionality with logging, auditing, key rotation, and more.

use async_trait::async_trait;
use crypto_tee::{
    plugins::CryptoPlugin, Algorithm, CryptoTEE, CryptoTEEBuilder, CryptoTEEError,
    CryptoTEEResult, KeyHandle, KeyOptions, KeyUsage,
};
use std::collections::HashMap;
use std::error::Error;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// Audit log entry
#[derive(Debug, Clone)]
struct AuditEntry {
    timestamp: SystemTime,
    operation: String,
    key_alias: String,
    success: bool,
    details: String,
}

/// Audit logging plugin
///
/// Tracks all key operations for compliance and security monitoring
struct AuditPlugin {
    logs: Arc<Mutex<Vec<AuditEntry>>>,
}

impl AuditPlugin {
    fn new() -> Self {
        Self {
            logs: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn add_entry(&self, operation: &str, key_alias: &str, success: bool, details: &str) {
        let entry = AuditEntry {
            timestamp: SystemTime::now(),
            operation: operation.to_string(),
            key_alias: key_alias.to_string(),
            success,
            details: details.to_string(),
        };

        self.logs.lock().unwrap().push(entry);
    }

    fn get_logs(&self) -> Vec<AuditEntry> {
        self.logs.lock().unwrap().clone()
    }
}

#[async_trait]
impl CryptoPlugin for AuditPlugin {
    async fn on_key_generated(&self, alias: &str, _handle: &KeyHandle) -> CryptoTEEResult<()> {
        self.add_entry("key_generated", alias, true, "New key created");
        Ok(())
    }

    async fn on_key_deleted(&self, alias: &str) -> CryptoTEEResult<()> {
        self.add_entry("key_deleted", alias, true, "Key removed");
        Ok(())
    }

    async fn on_sign(&self, alias: &str, data_len: usize) -> CryptoTEEResult<()> {
        self.add_entry(
            "sign",
            alias,
            true,
            &format!("Signed {} bytes", data_len),
        );
        Ok(())
    }

    async fn on_verify(&self, alias: &str, _data_len: usize, verified: bool) -> CryptoTEEResult<()> {
        self.add_entry(
            "verify",
            alias,
            true,
            &format!("Verification result: {}", verified),
        );
        Ok(())
    }
}

/// Key rotation plugin
///
/// Automatically rotates keys based on age or usage count
struct KeyRotationPlugin {
    max_age: Duration,
    max_operations: u64,
    rotation_callback: Box<dyn Fn(&str) + Send + Sync>,
}

impl KeyRotationPlugin {
    fn new<F>(max_age: Duration, max_operations: u64, callback: F) -> Self
    where
        F: Fn(&str) + Send + Sync + 'static,
    {
        Self {
            max_age,
            max_operations,
            rotation_callback: Box::new(callback),
        }
    }

    fn check_rotation_needed(&self, handle: &KeyHandle) -> bool {
        // Check age
        if let Ok(age) = SystemTime::now().duration_since(handle.metadata.created_at) {
            if age > self.max_age {
                return true;
            }
        }

        // Check usage count
        if handle.metadata.usage_count > self.max_operations {
            return true;
        }

        false
    }
}

#[async_trait]
impl CryptoPlugin for KeyRotationPlugin {
    async fn on_sign(&self, alias: &str, _data_len: usize) -> CryptoTEEResult<()> {
        // In a real implementation, we'd check the key and trigger rotation if needed
        // For this example, we'll just demonstrate the concept
        println!("[Rotation Plugin] Checking key {} for rotation", alias);
        Ok(())
    }
}

/// Rate limiting plugin
///
/// Prevents abuse by limiting operations per key
struct RateLimitPlugin {
    limits: Arc<Mutex<HashMap<String, Vec<SystemTime>>>>,
    max_ops_per_minute: usize,
}

impl RateLimitPlugin {
    fn new(max_ops_per_minute: usize) -> Self {
        Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
            max_ops_per_minute,
        }
    }

    fn check_rate_limit(&self, alias: &str) -> CryptoTEEResult<()> {
        let mut limits = self.limits.lock().unwrap();
        let now = SystemTime::now();
        let one_minute_ago = now - Duration::from_secs(60);

        // Get or create entry
        let operations = limits.entry(alias.to_string()).or_insert_with(Vec::new);

        // Remove old entries
        operations.retain(|&time| time > one_minute_ago);

        // Check limit
        if operations.len() >= self.max_ops_per_minute {
            return Err(CryptoTEEError::OperationError(
                "Rate limit exceeded".to_string(),
            ));
        }

        // Record this operation
        operations.push(now);
        Ok(())
    }
}

#[async_trait]
impl CryptoPlugin for RateLimitPlugin {
    async fn on_sign(&self, alias: &str, _data_len: usize) -> CryptoTEEResult<()> {
        self.check_rate_limit(alias)
    }

    async fn on_verify(&self, alias: &str, _data_len: usize, _verified: bool) -> CryptoTEEResult<()> {
        self.check_rate_limit(alias)
    }
}

/// Metrics collection plugin
///
/// Collects performance and usage metrics
struct MetricsPlugin {
    metrics: Arc<Mutex<HashMap<String, u64>>>,
}

impl MetricsPlugin {
    fn new() -> Self {
        Self {
            metrics: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn increment(&self, metric: &str) {
        let mut metrics = self.metrics.lock().unwrap();
        *metrics.entry(metric.to_string()).or_insert(0) += 1;
    }

    fn get_metrics(&self) -> HashMap<String, u64> {
        self.metrics.lock().unwrap().clone()
    }
}

#[async_trait]
impl CryptoPlugin for MetricsPlugin {
    async fn on_key_generated(&self, _alias: &str, handle: &KeyHandle) -> CryptoTEEResult<()> {
        self.increment("keys_generated");
        self.increment(&format!("keys_generated_{:?}", handle.metadata.algorithm));
        Ok(())
    }

    async fn on_sign(&self, _alias: &str, data_len: usize) -> CryptoTEEResult<()> {
        self.increment("signatures_created");
        self.increment(&format!("bytes_signed_{}", data_len / 1000)); // KB buckets
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    println!("CryptoTEE Plugin Development Example\n");

    // Create CryptoTEE instance
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Create and register plugins
    let audit_plugin = Arc::new(AuditPlugin::new());
    let metrics_plugin = Arc::new(MetricsPlugin::new());
    let rate_limit_plugin = Arc::new(RateLimitPlugin::new(10)); // 10 ops/minute

    crypto_tee.register_plugin(audit_plugin.clone()).await;
    crypto_tee.register_plugin(metrics_plugin.clone()).await;
    crypto_tee.register_plugin(rate_limit_plugin.clone()).await;

    // Also register a rotation plugin
    let rotation_plugin = Arc::new(KeyRotationPlugin::new(
        Duration::from_secs(3600), // 1 hour
        1000,                      // 1000 operations
        |alias| println!("⚠️  Key {} needs rotation!", alias),
    ));
    crypto_tee.register_plugin(rotation_plugin).await;

    println!("✓ Registered 4 plugins\n");

    // Generate test keys
    println!("Generating test keys...");
    for i in 1..=3 {
        let key = crypto_tee
            .generate_key(
                &format!("test-key-{}", i),
                KeyOptions {
                    algorithm: if i % 2 == 0 {
                        Algorithm::EcdsaP256
                    } else {
                        Algorithm::Ed25519
                    },
                    usage: KeyUsage::SIGN_VERIFY,
                    extractable: false,
                    hardware_backed: true,
                    require_auth: false,
                    expires_at: None,
                },
            )
            .await?;
        println!("  ✓ Generated {}", key.alias);
    }

    // Perform operations
    println!("\nPerforming operations...");
    let data = b"Test data for signing";
    
    // Normal operations
    for i in 1..=3 {
        let alias = format!("test-key-{}", i);
        let signature = crypto_tee.sign(&alias, data, None).await?;
        let valid = crypto_tee.verify(&alias, data, &signature, None).await?;
        println!("  ✓ Key {} - Signed and verified: {}", alias, valid);
    }

    // Test rate limiting
    println!("\nTesting rate limiting...");
    for i in 1..=12 {
        match crypto_tee.sign("test-key-1", data, None).await {
            Ok(_) => println!("  ✓ Operation {} succeeded", i),
            Err(e) => println!("  ✗ Operation {} blocked: {}", i, e),
        }
    }

    // Display audit logs
    println!("\nAudit Log:");
    for entry in audit_plugin.get_logs().iter().take(10) {
        println!(
            "  [{:?}] {} on {} - Success: {} - {}",
            entry.timestamp.duration_since(SystemTime::UNIX_EPOCH)?.as_secs(),
            entry.operation,
            entry.key_alias,
            entry.success,
            entry.details
        );
    }

    // Display metrics
    println!("\nMetrics:");
    for (metric, count) in metrics_plugin.get_metrics() {
        println!("  {}: {}", metric, count);
    }

    // Clean up
    println!("\nCleaning up...");
    for i in 1..=3 {
        crypto_tee.delete_key(&format!("test-key-{}", i)).await?;
    }

    println!("\nExample completed successfully!");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_audit_plugin() {
        let plugin = AuditPlugin::new();
        
        // Simulate operations
        plugin.on_key_generated("test", &KeyHandle {
            alias: "test".to_string(),
            platform_handle: Default::default(),
            metadata: Default::default(),
        }).await.unwrap();

        // Check logs
        let logs = plugin.get_logs();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].operation, "key_generated");
    }

    #[tokio::test]
    async fn test_rate_limit_plugin() {
        let plugin = RateLimitPlugin::new(2);

        // Should allow first two operations
        assert!(plugin.on_sign("test", 100).await.is_ok());
        assert!(plugin.on_sign("test", 100).await.is_ok());

        // Should block third operation
        assert!(plugin.on_sign("test", 100).await.is_err());
    }
}