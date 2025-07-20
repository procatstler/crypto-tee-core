//! Core CryptoTEE API implementation

use std::sync::Arc;

use async_trait::async_trait;
use crypto_tee_platform::{load_platform, PlatformConfig, PlatformTEE};
use crypto_tee_vendor::VendorTEE;
use crypto_tee_vendor::types::Signature;
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::{
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
}

impl CryptoTEEImpl {
    /// Create a new CryptoTEE instance
    pub async fn new() -> CryptoTEEResult<Self> {
        let platform = load_platform();
        let vendor = platform
            .select_best_vendor()
            .await
            .map_err(|e| CryptoTEEError::InitError(format!("Failed to select vendor: {}", e)))?;

        Ok(Self {
            platform: Arc::new(RwLock::new(platform)),
            vendor: Arc::new(RwLock::new(vendor)),
            key_manager: Arc::new(RwLock::new(KeyManager::new())),
            plugin_manager: Arc::new(RwLock::new(PluginManager::new())),
        })
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

        // Check if alias already exists
        if self.key_manager.read().await.exists(alias) {
            return Err(CryptoTEEError::InvalidKeyAlias(format!(
                "Key with alias '{}' already exists",
                alias
            )));
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

        let vendor_handle = vendor.generate_key(&key_params).await?;

        // Wrap with platform handle
        let platform = self.platform.read().await;
        let platform_handle = platform.wrap_key_handle(vendor_handle).await?;

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
        self.key_manager
            .write()
            .await
            .add_key(alias, key_handle.clone())?;

        Ok(key_handle)
    }

    async fn import_key(
        &self,
        alias: &str,
        key_data: &[u8],
        options: KeyOptions,
    ) -> CryptoTEEResult<KeyHandle> {
        info!("Importing key with alias: {}", alias);

        if self.key_manager.read().await.exists(alias) {
            return Err(CryptoTEEError::InvalidKeyAlias(format!(
                "Key with alias '{}' already exists",
                alias
            )));
        }

        let vendor = self.vendor.read().await;
        let key_params = crypto_tee_vendor::types::KeyGenParams {
            algorithm: options.algorithm,
            hardware_backed: options.hardware_backed,
            exportable: options.exportable,
            usage: options.usage,
            vendor_params: None,
        };

        let vendor_handle = vendor.import_key(key_data, &key_params).await?;

        let platform = self.platform.read().await;
        let platform_handle = platform.wrap_key_handle(vendor_handle).await?;

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

        self.key_manager
            .write()
            .await
            .add_key(alias, key_handle.clone())?;

        Ok(key_handle)
    }

    async fn delete_key(&self, alias: &str) -> CryptoTEEResult<()> {
        info!("Deleting key with alias: {}", alias);

        let mut key_manager = self.key_manager.write().await;
        let key_handle = key_manager.get_key(alias)?;

        // Delete from vendor
        let vendor = self.vendor.read().await;
        vendor
            .delete_key(&key_handle.platform_handle.vendor_handle)
            .await?;

        // Remove from key manager
        key_manager.remove_key(alias)?;

        Ok(())
    }

    async fn sign(
        &self,
        alias: &str,
        data: &[u8],
        _options: Option<SignOptions>,
    ) -> CryptoTEEResult<Vec<u8>> {
        debug!("Signing data with key: [REDACTED]");

        let mut key_manager = self.key_manager.write().await;
        let key_handle = key_manager.get_key_mut(alias)?;

        // Update usage statistics
        key_handle.metadata.last_used = Some(std::time::SystemTime::now());
        key_handle.metadata.usage_count += 1;

        // Sign through vendor
        let vendor = self.vendor.read().await;
        let signature = vendor
            .sign(&key_handle.platform_handle.vendor_handle, data)
            .await?;

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

        let key_manager = self.key_manager.read().await;
        let key_handle = key_manager.get_key(alias)?;

        let vendor = self.vendor.read().await;
        let sig = Signature {
            algorithm: key_handle.metadata.algorithm,
            data: signature.to_vec(),
        };

        let result = vendor
            .verify(&key_handle.platform_handle.vendor_handle, data, &sig)
            .await?;

        Ok(result)
    }

    async fn list_keys(&self) -> CryptoTEEResult<Vec<KeyInfo>> {
        let key_manager = self.key_manager.read().await;
        Ok(key_manager.list_keys())
    }

    async fn get_key_info(&self, alias: &str) -> CryptoTEEResult<KeyInfo> {
        let key_manager = self.key_manager.read().await;
        let key_handle = key_manager.get_key(alias)?;

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
        Self {
            platform_config: None,
            vendor_name: None,
        }
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

        Ok(CryptoTEEImpl {
            platform: Arc::new(RwLock::new(platform)),
            vendor: Arc::new(RwLock::new(vendor)),
            key_manager: Arc::new(RwLock::new(KeyManager::new())),
            plugin_manager: Arc::new(RwLock::new(PluginManager::new())),
        })
    }
}

impl Default for CryptoTEEBuilder {
    fn default() -> Self {
        Self::new()
    }
}