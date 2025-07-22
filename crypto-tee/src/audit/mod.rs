//! Audit logging system for CryptoTEE
//!
//! This module provides comprehensive audit logging for all key operations,
//! ensuring compliance with security standards and regulations.

use crate::error::CryptoTEEResult;
use chrono::{DateTime, Utc};
use crypto_tee_vendor::Algorithm;
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, warn};

pub mod logger;
pub mod storage;

pub use logger::{AuditLogger, AuditLoggerConfig, ConsoleAuditLogger, FileAuditLogger, LogFormat, MultiAuditLogger};
pub use storage::{AuditStorage, FileAuditStorage, MemoryAuditStorage};

/// Audit event types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditEventType {
    /// Key generation event
    KeyGenerated,
    /// Key deletion event
    KeyDeleted,
    /// Key access event
    KeyAccessed,
    /// Key export event
    KeyExported,
    /// Key import event
    KeyImported,
    /// Signing operation
    SignOperation,
    /// Verification operation
    VerifyOperation,
    /// Encryption operation
    EncryptOperation,
    /// Decryption operation
    DecryptOperation,
    /// Key rotation event
    KeyRotated,
    /// Authentication event
    AuthenticationSuccess,
    /// Authentication failure
    AuthenticationFailure,
    /// Access denied event
    AccessDenied,
    /// System initialization
    SystemInitialized,
    /// System shutdown
    SystemShutdown,
    /// Configuration change
    ConfigurationChanged,
    /// Error event
    ErrorOccurred,
}

/// Severity levels for audit events
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditSeverity {
    /// Informational events
    Info,
    /// Warning events
    Warning,
    /// Error events
    Error,
    /// Critical security events
    Critical,
}

/// Audit event structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unique event ID
    pub id: String,
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Type of audit event
    pub event_type: AuditEventType,
    /// Severity level
    pub severity: AuditSeverity,
    /// User or system that triggered the event
    pub actor: String,
    /// Target resource (e.g., key alias)
    pub target: Option<String>,
    /// Operation result
    pub success: bool,
    /// Error message if operation failed
    pub error_message: Option<String>,
    /// Additional context
    pub metadata: HashMap<String, serde_json::Value>,
    /// Hash of previous event for chain integrity
    pub previous_hash: Option<String>,
    /// Hash of this event
    pub hash: String,
}

impl AuditEvent {
    /// Create a new audit event
    pub fn new(
        event_type: AuditEventType,
        severity: AuditSeverity,
        actor: String,
        target: Option<String>,
        success: bool,
    ) -> Self {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let metadata = HashMap::new();
        
        let event = Self {
            id,
            timestamp,
            event_type,
            severity,
            actor,
            target,
            success,
            error_message: None,
            metadata,
            previous_hash: None,
            hash: String::new(),
        };
        
        // Calculate hash will be called after setting previous_hash
        event
    }
    
    /// Add metadata to the event
    pub fn with_metadata(mut self, key: String, value: serde_json::Value) -> Self {
        self.metadata.insert(key, value);
        self
    }
    
    /// Set error message
    pub fn with_error(mut self, error: String) -> Self {
        self.error_message = Some(error);
        self.success = false;
        self
    }
    
    /// Set previous event hash for chain integrity
    pub fn with_previous_hash(mut self, hash: String) -> Self {
        self.previous_hash = Some(hash);
        self
    }
    
    /// Calculate hash of the event
    pub fn calculate_hash(&mut self) {
        let data = format!(
            "{}:{}:{}:{:?}:{}:{}:{:?}:{:?}:{:?}:{:?}",
            self.id,
            self.timestamp.to_rfc3339(),
            format!("{:?}", self.event_type),
            self.severity,
            self.actor,
            self.target.as_deref().unwrap_or(""),
            self.success,
            self.error_message,
            self.metadata,
            self.previous_hash
        );
        
        let hash = digest(&SHA256, data.as_bytes());
        self.hash = hex::encode(hash.as_ref());
    }
    
    /// Verify the event hash
    pub fn verify_hash(&self) -> bool {
        let data = format!(
            "{}:{}:{}:{:?}:{}:{}:{:?}:{:?}:{:?}:{:?}",
            self.id,
            self.timestamp.to_rfc3339(),
            format!("{:?}", self.event_type),
            self.severity,
            self.actor,
            self.target.as_deref().unwrap_or(""),
            self.success,
            self.error_message,
            self.metadata,
            self.previous_hash
        );
        
        let calculated_hash = digest(&SHA256, data.as_bytes());
        let calculated_hash_hex = hex::encode(calculated_hash.as_ref());
        
        calculated_hash_hex == self.hash
    }
}

impl std::fmt::Display for AuditEventType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuditSeverity::Info => write!(f, "INFO"),
            AuditSeverity::Warning => write!(f, "WARNING"),
            AuditSeverity::Error => write!(f, "ERROR"),
            AuditSeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Audit context for tracking operation details
#[derive(Debug, Clone)]
pub struct AuditContext {
    /// Current actor (user/system)
    pub actor: String,
    /// Session ID for correlation
    pub session_id: Option<String>,
    /// Request ID for tracing
    pub request_id: Option<String>,
    /// Client IP address
    pub client_ip: Option<String>,
    /// Additional context
    pub attributes: HashMap<String, String>,
}

impl AuditContext {
    /// Create a new audit context
    pub fn new(actor: String) -> Self {
        Self {
            actor,
            session_id: None,
            request_id: None,
            client_ip: None,
            attributes: HashMap::new(),
        }
    }
    
    /// Create a system audit context
    pub fn system() -> Self {
        Self::new("system".to_string())
    }
    
    /// Add session ID
    pub fn with_session_id(mut self, session_id: String) -> Self {
        self.session_id = Some(session_id);
        self
    }
    
    /// Add request ID
    pub fn with_request_id(mut self, request_id: String) -> Self {
        self.request_id = Some(request_id);
        self
    }
    
    /// Add client IP
    pub fn with_client_ip(mut self, client_ip: String) -> Self {
        self.client_ip = Some(client_ip);
        self
    }
    
    /// Add custom attribute
    pub fn with_attribute(mut self, key: String, value: String) -> Self {
        self.attributes.insert(key, value);
        self
    }
}

/// Audit manager for coordinating audit logging
pub struct AuditManager {
    logger: Arc<RwLock<Box<dyn AuditLogger>>>,
    storage: Arc<RwLock<Box<dyn AuditStorage>>>,
    config: AuditConfig,
    last_event_hash: Arc<RwLock<Option<String>>>,
}

/// Audit system configuration
#[derive(Debug, Clone)]
pub struct AuditConfig {
    /// Enable audit logging
    pub enabled: bool,
    /// Minimum severity level to log
    pub min_severity: AuditSeverity,
    /// Enable chain integrity verification
    pub enable_chain_integrity: bool,
    /// Retention period in days
    pub retention_days: u32,
    /// Maximum events in memory
    pub max_memory_events: usize,
    /// Enable real-time alerts
    pub enable_alerts: bool,
    /// Alert webhook URL
    pub alert_webhook: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_severity: AuditSeverity::Info,
            enable_chain_integrity: true,
            retention_days: 365,
            max_memory_events: 10000,
            enable_alerts: true,
            alert_webhook: None,
        }
    }
}

impl AuditManager {
    /// Create a new audit manager
    pub fn new(
        logger: Box<dyn AuditLogger>,
        storage: Box<dyn AuditStorage>,
        config: AuditConfig,
    ) -> Self {
        Self {
            logger: Arc::new(RwLock::new(logger)),
            storage: Arc::new(RwLock::new(storage)),
            config,
            last_event_hash: Arc::new(RwLock::new(None)),
        }
    }
    
    /// Log an audit event
    pub async fn log_event(&self, mut event: AuditEvent) -> CryptoTEEResult<()> {
        if !self.config.enabled {
            return Ok(());
        }
        
        // Check severity threshold
        if event.severity < self.config.min_severity {
            return Ok(());
        }
        
        // Add chain integrity if enabled
        if self.config.enable_chain_integrity {
            let last_hash = self.last_event_hash.read().await.clone();
            if let Some(hash) = last_hash {
                event = event.with_previous_hash(hash);
            }
        }
        
        // Calculate event hash
        event.calculate_hash();
        
        // Log the event
        self.logger.write().await.log(&event).await?;
        
        // Store the event
        self.storage.write().await.store(&event).await?;
        
        // Update last event hash
        if self.config.enable_chain_integrity {
            *self.last_event_hash.write().await = Some(event.hash.clone());
        }
        
        // Send alerts for critical events
        if self.config.enable_alerts && event.severity >= AuditSeverity::Critical {
            self.send_alert(&event).await;
        }
        
        Ok(())
    }
    
    /// Log a key generation event
    pub async fn log_key_generated(
        &self,
        context: &AuditContext,
        key_alias: &str,
        algorithm: Algorithm,
        success: bool,
        error: Option<String>,
    ) -> CryptoTEEResult<()> {
        let mut event = AuditEvent::new(
            AuditEventType::KeyGenerated,
            if success { AuditSeverity::Info } else { AuditSeverity::Error },
            context.actor.clone(),
            Some(key_alias.to_string()),
            success,
        );
        
        event = event.with_metadata("algorithm".to_string(), serde_json::json!(algorithm));
        
        if let Some(session_id) = &context.session_id {
            event = event.with_metadata("session_id".to_string(), serde_json::json!(session_id));
        }
        
        if let Some(err) = error {
            event = event.with_error(err);
        }
        
        self.log_event(event).await
    }
    
    /// Log a signing operation
    pub async fn log_sign_operation(
        &self,
        context: &AuditContext,
        key_alias: &str,
        data_size: usize,
        success: bool,
        error: Option<String>,
    ) -> CryptoTEEResult<()> {
        let mut event = AuditEvent::new(
            AuditEventType::SignOperation,
            if success { AuditSeverity::Info } else { AuditSeverity::Warning },
            context.actor.clone(),
            Some(key_alias.to_string()),
            success,
        );
        
        event = event.with_metadata("data_size".to_string(), serde_json::json!(data_size));
        
        if let Some(err) = error {
            event = event.with_error(err);
        }
        
        self.log_event(event).await
    }
    
    /// Query audit events
    pub async fn query_events(
        &self,
        filter: AuditFilter,
    ) -> CryptoTEEResult<Vec<AuditEvent>> {
        self.storage.read().await.query(filter).await
    }
    
    /// Verify audit chain integrity
    pub async fn verify_chain_integrity(
        &self,
        start_time: Option<DateTime<Utc>>,
        end_time: Option<DateTime<Utc>>,
    ) -> CryptoTEEResult<bool> {
        let filter = AuditFilter {
            start_time,
            end_time,
            ..Default::default()
        };
        
        let events = self.storage.read().await.query(filter).await?;
        
        if events.is_empty() {
            return Ok(true);
        }
        
        // Verify first event has no previous hash
        if events[0].previous_hash.is_some() {
            warn!("First event in chain has previous hash");
            return Ok(false);
        }
        
        // Verify each event's hash and chain
        for i in 0..events.len() {
            if !events[i].verify_hash() {
                error!("Event {} has invalid hash", events[i].id);
                return Ok(false);
            }
            
            if i > 0 {
                if events[i].previous_hash.as_ref() != Some(&events[i-1].hash) {
                    error!("Chain broken between events {} and {}", events[i-1].id, events[i].id);
                    return Ok(false);
                }
            }
        }
        
        Ok(true)
    }
    
    /// Send alert for critical events
    async fn send_alert(&self, event: &AuditEvent) {
        if let Some(_webhook_url) = &self.config.alert_webhook {
            // In a real implementation, this would send an HTTP request
            warn!(
                "ALERT: Critical audit event - Type: {:?}, Actor: {}, Target: {:?}",
                event.event_type, event.actor, event.target
            );
        }
    }
}

/// Filter for querying audit events
#[derive(Debug, Default)]
pub struct AuditFilter {
    /// Start time (inclusive)
    pub start_time: Option<DateTime<Utc>>,
    /// End time (exclusive)
    pub end_time: Option<DateTime<Utc>>,
    /// Filter by event types
    pub event_types: Option<Vec<AuditEventType>>,
    /// Filter by severity
    pub min_severity: Option<AuditSeverity>,
    /// Filter by actor
    pub actor: Option<String>,
    /// Filter by target
    pub target: Option<String>,
    /// Filter by success/failure
    pub success: Option<bool>,
    /// Maximum number of results
    pub limit: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_audit_event_hash() {
        let mut event = AuditEvent::new(
            AuditEventType::KeyGenerated,
            AuditSeverity::Info,
            "test_user".to_string(),
            Some("test_key".to_string()),
            true,
        );
        
        event.calculate_hash();
        assert!(!event.hash.is_empty());
        assert!(event.verify_hash());
        
        // Modify event and verify hash fails
        event.actor = "modified_user".to_string();
        assert!(!event.verify_hash());
    }
    
    #[test]
    fn test_audit_context() {
        let context = AuditContext::new("user123".to_string())
            .with_session_id("session456".to_string())
            .with_request_id("req789".to_string())
            .with_client_ip("192.168.1.1".to_string())
            .with_attribute("department".to_string(), "security".to_string());
        
        assert_eq!(context.actor, "user123");
        assert_eq!(context.session_id.unwrap(), "session456");
        assert_eq!(context.request_id.unwrap(), "req789");
        assert_eq!(context.client_ip.unwrap(), "192.168.1.1");
        assert_eq!(context.attributes.get("department").unwrap(), "security");
    }
}