//! Core platform trait definitions

use async_trait::async_trait;
use crypto_tee_vendor::{VendorKeyHandle, VendorTEE};

use crate::{
    error::PlatformResult,
    types::{AuthResult, PlatformConfig},
};

/// Core trait for platform-specific TEE implementations
#[async_trait]
pub trait PlatformTEE: Send + Sync {
    /// Get the platform name
    fn name(&self) -> &str;

    /// Get the platform version
    fn version(&self) -> &str;

    /// Detect available vendors on this platform
    async fn detect_vendors(&self) -> Vec<Box<dyn VendorTEE>>;

    /// Select the best available vendor for this platform
    async fn select_best_vendor(&self) -> PlatformResult<Box<dyn VendorTEE>>;

    /// Get a specific vendor by name
    async fn get_vendor(&self, name: &str) -> PlatformResult<Box<dyn VendorTEE>>;

    /// Handle platform-specific authentication
    async fn authenticate(&self, challenge: &[u8]) -> PlatformResult<AuthResult>;

    /// Check if user authentication is required for key operations
    async fn requires_authentication(&self) -> bool;

    /// Configure platform-specific settings
    async fn configure(&mut self, config: PlatformConfig) -> PlatformResult<()>;

    /// Get current platform configuration
    fn get_config(&self) -> &PlatformConfig;

    /// Platform-specific key handle wrapping
    async fn wrap_key_handle(
        &self,
        vendor_handle: VendorKeyHandle,
    ) -> PlatformResult<PlatformKeyHandle>;

    /// Platform-specific key handle unwrapping
    async fn unwrap_key_handle(
        &self,
        platform_handle: &PlatformKeyHandle,
    ) -> PlatformResult<VendorKeyHandle>;
}

/// Platform-wrapped key handle with additional metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlatformKeyHandle {
    /// Original vendor key handle
    pub vendor_handle: VendorKeyHandle,

    /// Platform that created this handle
    pub platform: String,

    /// Whether authentication is required for this key
    pub requires_auth: bool,

    /// Key creation timestamp
    pub created_at: std::time::SystemTime,

    /// Last used timestamp
    pub last_used: Option<std::time::SystemTime>,

    /// Platform-specific metadata
    pub metadata: Option<serde_json::Value>,
}
