//! Core CryptoTEE API implementation

use std::sync::Arc;

use async_trait::async_trait;
use crypto_tee_platform::{load_platform, PlatformConfig, PlatformTEE};
use crypto_tee_vendor::types::Signature;
use crypto_tee_vendor::VendorTEE;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::{
    audit::{AuditConfig, AuditContext, AuditEvent, AuditEventType, AuditManager, AuditSeverity, 
            ConsoleAuditLogger, FileAuditLogger, AuditLoggerConfig, LogFormat,
            MemoryAuditStorage, MultiAuditLogger},
    core::manager::KeyManager,
    error::{CryptoTEEError, CryptoTEEResult},
    plugins::PluginManager,
    types::*,
};

/// Main CryptoTEE API interface
#[async_trait]
pub trait CryptoTEE: Send + Sync {
    /// List available capabilities
    async fn list_capabilities(&self) -> CryptoTEEResult<Vec<String>>;

    /// Generate a new key
    async fn generate_key(&self, alias: &str, options: KeyOptions) -> CryptoTEEResult<KeyHandle>;

    /// Import a key
    async fn import_key(
        &self,
        alias: &str,
        key_data: &[u8],
        options: KeyOptions,
    ) -> CryptoTEEResult<KeyHandle>;

    /// Delete a key
    async fn delete_key(&self, alias: &str) -> CryptoTEEResult<()>;

    /// Sign data with a key
    async fn sign(
        &self,
        alias: &str,
        data: &[u8],
        options: Option<SignOptions>,
    ) -> CryptoTEEResult<Vec<u8>>;

    /// Verify a signature
    async fn verify(
        &self,
        alias: &str,
        data: &[u8],
        signature: &[u8],
        options: Option<SignOptions>,
    ) -> CryptoTEEResult<bool>;

    /// List all keys
    async fn list_keys(&self) -> CryptoTEEResult<Vec<KeyInfo>>;

    /// Get key information
    async fn get_key_info(&self, alias: &str) -> CryptoTEEResult<KeyInfo>;
}

/// CryptoTEE implementation
pub struct CryptoTEEImpl {
    platform: Arc<RwLock<Box<dyn PlatformTEE>>>,
    vendor: Arc<RwLock<Box<dyn VendorTEE>>>,
    key_manager: Arc<RwLock<KeyManager>>,
    plugin_manager: Arc<RwLock<PluginManager>>,
    audit_manager: Arc<RwLock<AuditManager>>,
}

impl CryptoTEEImpl {
    /// Create a new CryptoTEE instance
    pub async fn new() -> CryptoTEEResult<Self> {
        let platform = load_platform();
        let vendor = platform
            .select_best_vendor()
            .await
            .map_err(|e| CryptoTEEError::InitError(format!("Failed to select vendor: {}", e)))?;

        // Setup audit logging
        let audit_manager = Self::setup_default_audit_manager().await?;

        let instance = Self {
            platform: Arc::new(RwLock::new(platform)),
            vendor: Arc::new(RwLock::new(vendor)),
            key_manager: Arc::new(RwLock::new(KeyManager::new())),
            plugin_manager: Arc::new(RwLock::new(PluginManager::new())),
            audit_manager: Arc::new(RwLock::new(audit_manager)),
        };

        // Log system initialization
        instance.audit_manager.read().await.log_event(
            crate::audit::AuditEvent::new(
                AuditEventType::SystemInitialized,
                AuditSeverity::Info,
                AuditContext::system().actor,
                None,
                true,
            )
        ).await?;

        Ok(instance)
    }

    /// Setup default audit manager
    async fn setup_default_audit_manager() -> CryptoTEEResult<AuditManager> {
        // Create console logger
        let console_logger = Box::new(ConsoleAuditLogger::new(AuditLoggerConfig {
            format: LogFormat::Text,
            ..Default::default()
        }));

        // Create file logger
        let log_dir = std::env::current_dir()
            .map_err(|e| CryptoTEEError::IoError(e.to_string()))?
            .join("audit_logs");
        let file_logger = Box::new(FileAuditLogger::new(
            log_dir.join("crypto-tee-audit.jsonl"),
            AuditLoggerConfig::default(),
        ));

        // Combine loggers
        let multi_logger = Box::new(MultiAuditLogger::new(vec![console_logger, file_logger]));

        // Create storage
        let storage = Box::new(MemoryAuditStorage::new(10000));

        // Create audit manager
        let audit_manager = AuditManager::new(
            multi_logger,
            storage,
            AuditConfig::default(),
        );

        Ok(audit_manager)
    }

    /// Register a plugin
    pub async fn register_plugin(&self, plugin: Box<dyn crate::plugins::CryptoPlugin>) {
        self.plugin_manager.write().await.register(plugin);
    }
}

#[async_trait]
impl CryptoTEE for CryptoTEEImpl {
    async fn list_capabilities(&self) -> CryptoTEEResult<Vec<String>> {
        let vendor = self.vendor.read().await;
        let caps = vendor.probe().await?;

        let mut capabilities = vec![
            format!("vendor: {}", caps.name),
            format!("version: {}", caps.version),
            format!("max_keys: {}", caps.max_keys),
        ];

        for algo in &caps.algorithms {
            capabilities.push(format!("algorithm: {:?}", algo));
        }

        if caps.hardware_backed {
            capabilities.push("feature: hardware-backed".to_string());
        }
        if caps.attestation {
            capabilities.push("feature: attestation".to_string());
        }

        Ok(capabilities)
    }

    async fn generate_key(&self, alias: &str, options: KeyOptions) -> CryptoTEEResult<KeyHandle> {
        info!("Generating key with alias: {}", alias);
        let context = AuditContext::system(); // TODO: Get from request context

        // Check if alias already exists
        if self.key_manager.read().await.exists(alias) {
            let error = format!("Key with alias '{}' already exists", alias);
            self.audit_manager.read().await.log_key_generated(
                &context,
                alias,
                options.algorithm,
                false,
                Some(error.clone()),
            ).await?;
            return Err(CryptoTEEError::InvalidKeyAlias(error));
        }

        // Generate key through vendor
        let vendor = self.vendor.read().await;
        let key_params = crypto_tee_vendor::types::KeyGenParams {
            algorithm: options.algorithm,
            hardware_backed: options.hardware_backed,
            exportable: options.exportable,
            usage: options.usage,
            vendor_params: None,
        };

        let vendor_handle = match vendor.generate_key(&key_params).await {
            Ok(handle) => handle,
            Err(e) => {
                self.audit_manager.read().await.log_key_generated(
                    &context,
                    alias,
                    options.algorithm,
                    false,
                    Some(e.to_string()),
                ).await?;
                return Err(e.into());
            }
        };

        // Wrap with platform handle
        let platform = self.platform.read().await;
        let platform_handle = match platform.wrap_key_handle(vendor_handle).await {
            Ok(handle) => handle,
            Err(e) => {
                self.audit_manager.read().await.log_key_generated(
                    &context,
                    alias,
                    options.algorithm,
                    false,
                    Some(e.to_string()),
                ).await?;
                return Err(e.into());
            }
        };

        // Create key handle
        let key_handle = KeyHandle {
            alias: alias.to_string(),
            platform_handle: platform_handle.clone(),
            metadata: KeyMetadata {
                algorithm: options.algorithm,
                created_at: std::time::SystemTime::now(),
                last_used: None,
                usage_count: 0,
                hardware_backed: platform_handle.vendor_handle.hardware_backed,
                custom: options.metadata,
            },
        };

        // Store in key manager
        if let Err(e) = self.key_manager.write().await.add_key(alias, key_handle.clone()) {
            self.audit_manager.read().await.log_key_generated(
                &context,
                alias,
                options.algorithm,
                false,
                Some(e.to_string()),
            ).await?;
            return Err(e);
        }

        // Log successful key generation
        self.audit_manager.read().await.log_key_generated(
            &context,
            alias,
            options.algorithm,
            true,
            None,
        ).await?;

        Ok(key_handle)
    }

    async fn import_key(
        &self,
        alias: &str,
        key_data: &[u8],
        options: KeyOptions,
    ) -> CryptoTEEResult<KeyHandle> {
        info!("Importing key with alias: {}", alias);
        let context = AuditContext::system(); // TODO: Get from request context

        if self.key_manager.read().await.exists(alias) {
            let error = format!("Key with alias '{}' already exists", alias);
            self.audit_manager.read().await.log_event(
                AuditEvent::new(
                    AuditEventType::KeyImported,
                    AuditSeverity::Error,
                    context.actor,
                    Some(alias.to_string()),
                    false,
                ).with_error(error.clone())
                .with_metadata("algorithm".to_string(), serde_json::json!(options.algorithm))
            ).await?;
            return Err(CryptoTEEError::InvalidKeyAlias(error));
        }

        let vendor = self.vendor.read().await;
        let key_params = crypto_tee_vendor::types::KeyGenParams {
            algorithm: options.algorithm,
            hardware_backed: options.hardware_backed,
            exportable: options.exportable,
            usage: options.usage,
            vendor_params: None,
        };

        let vendor_handle = match vendor.import_key(key_data, &key_params).await {
            Ok(handle) => handle,
            Err(e) => {
                self.audit_manager.read().await.log_event(
                    AuditEvent::new(
                        AuditEventType::KeyImported,
                        AuditSeverity::Error,
                        context.actor,
                        Some(alias.to_string()),
                        false,
                    ).with_error(e.to_string())
                    .with_metadata("algorithm".to_string(), serde_json::json!(options.algorithm))
                ).await?;
                return Err(e.into());
            }
        };

        let platform = self.platform.read().await;
        let platform_handle = match platform.wrap_key_handle(vendor_handle).await {
            Ok(handle) => handle,
            Err(e) => {
                self.audit_manager.read().await.log_event(
                    AuditEvent::new(
                        AuditEventType::KeyImported,
                        AuditSeverity::Error,
                        context.actor,
                        Some(alias.to_string()),
                        false,
                    ).with_error(e.to_string())
                    .with_metadata("algorithm".to_string(), serde_json::json!(options.algorithm))
                ).await?;
                return Err(e.into());
            }
        };

        let key_handle = KeyHandle {
            alias: alias.to_string(),
            platform_handle: platform_handle.clone(),
            metadata: KeyMetadata {
                algorithm: options.algorithm,
                created_at: std::time::SystemTime::now(),
                last_used: None,
                usage_count: 0,
                hardware_backed: platform_handle.vendor_handle.hardware_backed,
                custom: options.metadata,
            },
        };

        if let Err(e) = self.key_manager.write().await.add_key(alias, key_handle.clone()) {
            self.audit_manager.read().await.log_event(
                AuditEvent::new(
                    AuditEventType::KeyImported,
                    AuditSeverity::Error,
                    context.actor,
                    Some(alias.to_string()),
                    false,
                ).with_error(e.to_string())
                .with_metadata("algorithm".to_string(), serde_json::json!(options.algorithm))
            ).await?;
            return Err(e);
        }

        // Log successful import
        self.audit_manager.read().await.log_event(
            AuditEvent::new(
                AuditEventType::KeyImported,
                AuditSeverity::Info,
                context.actor,
                Some(alias.to_string()),
                true,
            ).with_metadata("algorithm".to_string(), serde_json::json!(options.algorithm))
            .with_metadata("hardware_backed".to_string(), serde_json::json!(key_handle.metadata.hardware_backed))
        ).await?;

        Ok(key_handle)
    }

    async fn delete_key(&self, alias: &str) -> CryptoTEEResult<()> {
        info!("Deleting key with alias: {}", alias);
        let context = AuditContext::system(); // TODO: Get from request context

        let mut key_manager = self.key_manager.write().await;
        let key_handle = match key_manager.get_key(alias) {
            Ok(handle) => handle,
            Err(e) => {
                self.audit_manager.read().await.log_event(
                    AuditEvent::new(
                        AuditEventType::KeyDeleted,
                        AuditSeverity::Error,
                        context.actor,
                        Some(alias.to_string()),
                        false,
                    ).with_error(e.to_string())
                ).await?;
                return Err(e);
            }
        };

        // Delete from vendor
        let vendor = self.vendor.read().await;
        if let Err(e) = vendor.delete_key(&key_handle.platform_handle.vendor_handle).await {
            self.audit_manager.read().await.log_event(
                AuditEvent::new(
                    AuditEventType::KeyDeleted,
                    AuditSeverity::Error,
                    context.actor,
                    Some(alias.to_string()),
                    false,
                ).with_error(e.to_string())
            ).await?;
            return Err(e.into());
        }

        // Remove from key manager
        if let Err(e) = key_manager.remove_key(alias) {
            self.audit_manager.read().await.log_event(
                AuditEvent::new(
                    AuditEventType::KeyDeleted,
                    AuditSeverity::Error,
                    context.actor,
                    Some(alias.to_string()),
                    false,
                ).with_error(e.to_string())
            ).await?;
            return Err(e);
        }

        // Log successful deletion
        self.audit_manager.read().await.log_event(
            AuditEvent::new(
                AuditEventType::KeyDeleted,
                AuditSeverity::Info,
                context.actor,
                Some(alias.to_string()),
                true,
            )
        ).await?;

        Ok(())
    }

    async fn sign(
        &self,
        alias: &str,
        data: &[u8],
        _options: Option<SignOptions>,
    ) -> CryptoTEEResult<Vec<u8>> {
        debug!("Signing data with key: [REDACTED]");
        let context = AuditContext::system(); // TODO: Get from request context

        let mut key_manager = self.key_manager.write().await;
        let key_handle = match key_manager.get_key_mut(alias) {
            Ok(handle) => handle,
            Err(e) => {
                self.audit_manager.read().await.log_sign_operation(
                    &context,
                    alias,
                    data.len(),
                    false,
                    Some(e.to_string()),
                ).await?;
                return Err(e);
            }
        };

        // Update usage statistics
        key_handle.metadata.last_used = Some(std::time::SystemTime::now());
        key_handle.metadata.usage_count += 1;

        // Sign through vendor
        let vendor = self.vendor.read().await;
        let signature = match vendor.sign(&key_handle.platform_handle.vendor_handle, data).await {
            Ok(sig) => sig,
            Err(e) => {
                self.audit_manager.read().await.log_sign_operation(
                    &context,
                    alias,
                    data.len(),
                    false,
                    Some(e.to_string()),
                ).await?;
                return Err(e.into());
            }
        };

        // Log successful signing
        self.audit_manager.read().await.log_sign_operation(
            &context,
            alias,
            data.len(),
            true,
            None,
        ).await?;

        Ok(signature.into_bytes())
    }

    async fn verify(
        &self,
        alias: &str,
        data: &[u8],
        signature: &[u8],
        _options: Option<SignOptions>,
    ) -> CryptoTEEResult<bool> {
        debug!("Verifying signature with key: [REDACTED]");
        let context = AuditContext::system(); // TODO: Get from request context

        let key_manager = self.key_manager.read().await;
        let key_handle = match key_manager.get_key(alias) {
            Ok(handle) => handle,
            Err(e) => {
                self.audit_manager.read().await.log_event(
                    AuditEvent::new(
                        AuditEventType::VerifyOperation,
                        AuditSeverity::Error,
                        context.actor,
                        Some(alias.to_string()),
                        false,
                    ).with_error(e.to_string())
                    .with_metadata("data_size".to_string(), serde_json::json!(data.len()))
                ).await?;
                return Err(e);
            }
        };

        let vendor = self.vendor.read().await;
        let sig = Signature { algorithm: key_handle.metadata.algorithm, data: signature.to_vec() };

        let result = match vendor.verify(&key_handle.platform_handle.vendor_handle, data, &sig).await {
            Ok(res) => res,
            Err(e) => {
                self.audit_manager.read().await.log_event(
                    AuditEvent::new(
                        AuditEventType::VerifyOperation,
                        AuditSeverity::Warning,
                        context.actor,
                        Some(alias.to_string()),
                        false,
                    ).with_error(e.to_string())
                    .with_metadata("data_size".to_string(), serde_json::json!(data.len()))
                ).await?;
                return Err(e.into());
            }
        };

        // Log verification operation
        self.audit_manager.read().await.log_event(
            AuditEvent::new(
                AuditEventType::VerifyOperation,
                AuditSeverity::Info,
                context.actor,
                Some(alias.to_string()),
                true,
            ).with_metadata("data_size".to_string(), serde_json::json!(data.len()))
            .with_metadata("verification_result".to_string(), serde_json::json!(result))
        ).await?;

        Ok(result)
    }

    async fn list_keys(&self) -> CryptoTEEResult<Vec<KeyInfo>> {
        let key_manager = self.key_manager.read().await;
        Ok(key_manager.list_keys())
    }

    async fn get_key_info(&self, alias: &str) -> CryptoTEEResult<KeyInfo> {
        let context = AuditContext::system(); // TODO: Get from request context
        
        let key_manager = self.key_manager.read().await;
        let key_handle = match key_manager.get_key(alias) {
            Ok(handle) => handle,
            Err(e) => {
                self.audit_manager.read().await.log_event(
                    AuditEvent::new(
                        AuditEventType::KeyAccessed,
                        AuditSeverity::Warning,
                        context.actor,
                        Some(alias.to_string()),
                        false,
                    ).with_error(e.to_string())
                ).await?;
                return Err(e);
            }
        };

        // Log successful key access
        self.audit_manager.read().await.log_event(
            AuditEvent::new(
                AuditEventType::KeyAccessed,
                AuditSeverity::Info,
                context.actor,
                Some(alias.to_string()),
                true,
            ).with_metadata("operation".to_string(), serde_json::json!("get_info"))
        ).await?;

        Ok(KeyInfo {
            alias: key_handle.alias.clone(),
            algorithm: key_handle.metadata.algorithm,
            created_at: key_handle.metadata.created_at,
            hardware_backed: key_handle.metadata.hardware_backed,
            requires_auth: key_handle.platform_handle.requires_auth,
        })
    }
}

/// Builder for CryptoTEE instances
pub struct CryptoTEEBuilder {
    platform_config: Option<PlatformConfig>,
    vendor_name: Option<String>,
}

impl CryptoTEEBuilder {
    pub fn new() -> Self {
        Self { platform_config: None, vendor_name: None }
    }

    pub fn with_platform_config(mut self, config: PlatformConfig) -> Self {
        self.platform_config = Some(config);
        self
    }

    pub fn with_vendor(mut self, vendor_name: String) -> Self {
        self.vendor_name = Some(vendor_name);
        self
    }

    pub async fn build(self) -> CryptoTEEResult<CryptoTEEImpl> {
        let mut platform = load_platform();

        if let Some(config) = self.platform_config {
            platform.configure(config).await?;
        }

        let vendor = if let Some(vendor_name) = self.vendor_name {
            platform.get_vendor(&vendor_name).await?
        } else {
            platform.select_best_vendor().await?
        };

        // Setup audit logging
        let audit_manager = CryptoTEEImpl::setup_default_audit_manager().await?;

        let instance = CryptoTEEImpl {
            platform: Arc::new(RwLock::new(platform)),
            vendor: Arc::new(RwLock::new(vendor)),
            key_manager: Arc::new(RwLock::new(KeyManager::new())),
            plugin_manager: Arc::new(RwLock::new(PluginManager::new())),
            audit_manager: Arc::new(RwLock::new(audit_manager)),
        };

        // Log system initialization
        instance.audit_manager.read().await.log_event(
            AuditEvent::new(
                AuditEventType::SystemInitialized,
                AuditSeverity::Info,
                AuditContext::system().actor,
                None,
                true,
            )
        ).await?;

        Ok(instance)
    }
}

impl Default for CryptoTEEBuilder {
    fn default() -> Self {
        Self::new()
    }
}
