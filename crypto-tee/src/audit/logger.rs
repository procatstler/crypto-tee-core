//! Audit logger implementations

use super::{AuditEvent, AuditSeverity};
use crate::error::CryptoTEEResult;
use async_trait::async_trait;
use std::io::Write;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;
use tracing::error;

/// Trait for audit loggers
#[async_trait]
pub trait AuditLogger: Send + Sync {
    /// Log an audit event
    async fn log(&mut self, event: &AuditEvent) -> CryptoTEEResult<()>;
    
    /// Flush any buffered events
    async fn flush(&mut self) -> CryptoTEEResult<()>;
}

/// Configuration for audit logger
#[derive(Debug, Clone)]
pub struct AuditLoggerConfig {
    /// Output format
    pub format: LogFormat,
    /// Include metadata in output
    pub include_metadata: bool,
    /// Pretty print JSON
    pub pretty_json: bool,
    /// Buffer size for batching
    pub buffer_size: usize,
}

impl Default for AuditLoggerConfig {
    fn default() -> Self {
        Self {
            format: LogFormat::Json,
            include_metadata: true,
            pretty_json: false,
            buffer_size: 100,
        }
    }
}

/// Log output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogFormat {
    /// JSON format
    Json,
    /// Common Event Format (CEF)
    Cef,
    /// Syslog format
    Syslog,
    /// Human-readable text
    Text,
}

/// Console audit logger
pub struct ConsoleAuditLogger {
    config: AuditLoggerConfig,
}

impl ConsoleAuditLogger {
    /// Create a new console logger
    pub fn new(config: AuditLoggerConfig) -> Self {
        Self { config }
    }
    
    /// Format event based on configuration
    fn format_event(&self, event: &AuditEvent) -> String {
        match self.config.format {
            LogFormat::Json => {
                if self.config.pretty_json {
                    serde_json::to_string_pretty(event).unwrap_or_else(|e| {
                        error!("Failed to serialize audit event: {}", e);
                        format!("{{\"error\": \"serialization failed: {}\"}}", e)
                    })
                } else {
                    serde_json::to_string(event).unwrap_or_else(|e| {
                        error!("Failed to serialize audit event: {}", e);
                        format!("{{\"error\": \"serialization failed: {}\"}}", e)
                    })
                }
            }
            LogFormat::Text => {
                format!(
                    "[{}] {} {} - Actor: {}, Target: {:?}, Success: {}, Error: {:?}",
                    event.timestamp.to_rfc3339(),
                    event.severity,
                    event.event_type,
                    event.actor,
                    event.target,
                    event.success,
                    event.error_message
                )
            }
            LogFormat::Cef => {
                // CEF format: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
                format!(
                    "CEF:0|CryptoTEE|CryptoTEE|1.0|{}|{}|{}|msg={} src={} dst={} outcome={}",
                    event.event_type,
                    event.event_type,
                    match event.severity {
                        AuditSeverity::Info => "3",
                        AuditSeverity::Warning => "5",
                        AuditSeverity::Error => "7",
                        AuditSeverity::Critical => "10",
                    },
                    event.error_message.as_deref().unwrap_or("Success"),
                    event.actor,
                    event.target.as_deref().unwrap_or("N/A"),
                    if event.success { "success" } else { "failure" }
                )
            }
            LogFormat::Syslog => {
                // Simplified syslog format
                let facility = 16; // Local0
                let severity = match event.severity {
                    AuditSeverity::Info => 6,
                    AuditSeverity::Warning => 4,
                    AuditSeverity::Error => 3,
                    AuditSeverity::Critical => 2,
                };
                let priority = facility * 8 + severity;
                
                format!(
                    "<{}>{} {} CryptoTEE[{}]: {} - Actor: {}, Target: {:?}, Success: {}",
                    priority,
                    event.timestamp.format("%b %d %H:%M:%S"),
                    "localhost",
                    std::process::id(),
                    event.event_type,
                    event.actor,
                    event.target,
                    event.success
                )
            }
        }
    }
}

#[async_trait]
impl AuditLogger for ConsoleAuditLogger {
    async fn log(&mut self, event: &AuditEvent) -> CryptoTEEResult<()> {
        let formatted = self.format_event(event);
        println!("{}", formatted);
        Ok(())
    }
    
    async fn flush(&mut self) -> CryptoTEEResult<()> {
        std::io::stdout().flush().map_err(|e| {
            crate::error::CryptoTEEError::IoError(e.to_string())
        })
    }
}

/// File-based audit logger
pub struct FileAuditLogger {
    config: AuditLoggerConfig,
    path: PathBuf,
    buffer: Vec<String>,
}

impl FileAuditLogger {
    /// Create a new file logger
    pub fn new(path: PathBuf, config: AuditLoggerConfig) -> Self {
        Self {
            config,
            path,
            buffer: Vec::new(),
        }
    }
    
    /// Format event based on configuration
    fn format_event(&self, event: &AuditEvent) -> String {
        match self.config.format {
            LogFormat::Json => {
                if self.config.pretty_json {
                    serde_json::to_string_pretty(event).unwrap_or_else(|e| {
                        error!("Failed to serialize audit event: {}", e);
                        format!("{{\"error\": \"serialization failed: {}\"}}", e)
                    })
                } else {
                    serde_json::to_string(event).unwrap_or_else(|e| {
                        error!("Failed to serialize audit event: {}", e);
                        format!("{{\"error\": \"serialization failed: {}\"}}", e)
                    })
                }
            }
            _ => {
                // For other formats, reuse console logger formatting
                let console_logger = ConsoleAuditLogger::new(self.config.clone());
                console_logger.format_event(event)
            }
        }
    }
    
    /// Write buffer to file
    async fn write_buffer(&mut self) -> CryptoTEEResult<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .await
            .map_err(|e| crate::error::CryptoTEEError::IoError(e.to_string()))?;
        
        for line in &self.buffer {
            file.write_all(line.as_bytes()).await
                .map_err(|e| crate::error::CryptoTEEError::IoError(e.to_string()))?;
            file.write_all(b"\n").await
                .map_err(|e| crate::error::CryptoTEEError::IoError(e.to_string()))?;
        }
        
        file.flush().await
            .map_err(|e| crate::error::CryptoTEEError::IoError(e.to_string()))?;
        
        self.buffer.clear();
        Ok(())
    }
}

#[async_trait]
impl AuditLogger for FileAuditLogger {
    async fn log(&mut self, event: &AuditEvent) -> CryptoTEEResult<()> {
        let formatted = self.format_event(event);
        self.buffer.push(formatted);
        
        if self.buffer.len() >= self.config.buffer_size {
            self.write_buffer().await?;
        }
        
        Ok(())
    }
    
    async fn flush(&mut self) -> CryptoTEEResult<()> {
        self.write_buffer().await
    }
}

/// Multi-logger that writes to multiple destinations
pub struct MultiAuditLogger {
    loggers: Vec<Box<dyn AuditLogger>>,
}

impl MultiAuditLogger {
    /// Create a new multi-logger
    pub fn new(loggers: Vec<Box<dyn AuditLogger>>) -> Self {
        Self { loggers }
    }
    
    /// Add a logger
    pub fn add_logger(&mut self, logger: Box<dyn AuditLogger>) {
        self.loggers.push(logger);
    }
}

#[async_trait]
impl AuditLogger for MultiAuditLogger {
    async fn log(&mut self, event: &AuditEvent) -> CryptoTEEResult<()> {
        let mut last_error = None;
        
        for logger in &mut self.loggers {
            if let Err(e) = logger.log(event).await {
                error!("Audit logger failed: {}", e);
                last_error = Some(e);
            }
        }
        
        if let Some(e) = last_error {
            return Err(e);
        }
        
        Ok(())
    }
    
    async fn flush(&mut self) -> CryptoTEEResult<()> {
        let mut last_error = None;
        
        for logger in &mut self.loggers {
            if let Err(e) = logger.flush().await {
                error!("Audit logger flush failed: {}", e);
                last_error = Some(e);
            }
        }
        
        if let Some(e) = last_error {
            return Err(e);
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditEventType;
    
    #[tokio::test]
    async fn test_console_logger() {
        let config = AuditLoggerConfig::default();
        let mut logger = ConsoleAuditLogger::new(config);
        
        let event = AuditEvent::new(
            AuditEventType::KeyGenerated,
            AuditSeverity::Info,
            "test_user".to_string(),
            Some("test_key".to_string()),
            true,
        );
        
        assert!(logger.log(&event).await.is_ok());
        assert!(logger.flush().await.is_ok());
    }
    
    #[tokio::test]
    async fn test_file_logger() {
        use tempfile::tempdir;
        
        let dir = tempdir().unwrap();
        let log_path = dir.path().join("audit.log");
        
        let config = AuditLoggerConfig {
            buffer_size: 2,
            ..Default::default()
        };
        
        let mut logger = FileAuditLogger::new(log_path.clone(), config);
        
        // Log multiple events
        for i in 0..5 {
            let event = AuditEvent::new(
                AuditEventType::SignOperation,
                AuditSeverity::Info,
                format!("user_{}", i),
                Some(format!("key_{}", i)),
                true,
            );
            logger.log(&event).await.unwrap();
        }
        
        // Flush remaining
        logger.flush().await.unwrap();
        
        // Verify file exists and has content
        let content = tokio::fs::read_to_string(&log_path).await.unwrap();
        assert!(!content.is_empty());
        assert_eq!(content.lines().count(), 5);
    }
    
    #[tokio::test]
    async fn test_multi_logger() {
        let console_logger = Box::new(ConsoleAuditLogger::new(AuditLoggerConfig::default()));
        let memory_logger = Box::new(ConsoleAuditLogger::new(AuditLoggerConfig {
            format: LogFormat::Text,
            ..Default::default()
        }));
        
        let mut multi_logger = MultiAuditLogger::new(vec![console_logger, memory_logger]);
        
        let event = AuditEvent::new(
            AuditEventType::VerifyOperation,
            AuditSeverity::Warning,
            "system".to_string(),
            None,
            false,
        );
        
        assert!(multi_logger.log(&event).await.is_ok());
        assert!(multi_logger.flush().await.is_ok());
    }
}