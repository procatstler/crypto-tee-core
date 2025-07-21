//! Fallback platform implementation using software crypto

use async_trait::async_trait;
use crypto_tee_vendor::mock::MockVendor;
use crypto_tee_vendor::{VendorKeyHandle, VendorTEE};
use tracing::{debug, info};

use crate::{
    error::{PlatformError, PlatformResult},
    traits::{PlatformKeyHandle, PlatformTEE},
    types::{AuthMethod, AuthResult, PlatformConfig},
};

/// Fallback platform implementation for unsupported platforms
pub struct FallbackPlatform {
    config: PlatformConfig,
}

impl FallbackPlatform {
    pub fn new() -> Self {
        info!("Initializing fallback platform");
        Self { config: PlatformConfig::default() }
    }
}

impl Default for FallbackPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl PlatformTEE for FallbackPlatform {
    fn name(&self) -> &str {
        "fallback"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    async fn detect_vendors(&self) -> Vec<Box<dyn VendorTEE>> {
        debug!("Detecting vendors for fallback platform");
        vec![Box::new(MockVendor::new("fallback-mock")) as Box<dyn VendorTEE>]
    }

    async fn select_best_vendor(&self) -> PlatformResult<Box<dyn VendorTEE>> {
        debug!("Selecting best vendor for fallback platform");
        Ok(Box::new(MockVendor::new("fallback-mock")))
    }

    async fn get_vendor(&self, name: &str) -> PlatformResult<Box<dyn VendorTEE>> {
        debug!("Getting vendor {} for fallback platform", name);
        if name == "fallback-mock" || name == "mock" {
            Ok(Box::new(MockVendor::new(name)))
        } else {
            Err(PlatformError::NotSupported(format!(
                "Vendor '{}' not available on fallback platform",
                name
            )))
        }
    }

    async fn authenticate(&self, _challenge: &[u8]) -> PlatformResult<AuthResult> {
        debug!("Authenticating on fallback platform");
        Ok(AuthResult {
            success: true,
            method: AuthMethod::None,
            session_token: None,
            valid_until: None,
        })
    }

    async fn requires_authentication(&self) -> bool {
        self.config.require_auth
    }

    async fn configure(&mut self, config: PlatformConfig) -> PlatformResult<()> {
        debug!("Configuring fallback platform");
        self.config = config;
        Ok(())
    }

    fn get_config(&self) -> &PlatformConfig {
        &self.config
    }

    async fn wrap_key_handle(
        &self,
        vendor_handle: VendorKeyHandle,
    ) -> PlatformResult<PlatformKeyHandle> {
        Ok(PlatformKeyHandle {
            vendor_handle,
            platform: self.name().to_string(),
            requires_auth: self.config.require_auth,
            created_at: std::time::SystemTime::now(),
            last_used: None,
            metadata: None,
        })
    }

    async fn unwrap_key_handle(
        &self,
        platform_handle: &PlatformKeyHandle,
    ) -> PlatformResult<VendorKeyHandle> {
        Ok(platform_handle.vendor_handle.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fallback_platform() {
        let platform = FallbackPlatform::new();
        assert_eq!(platform.name(), "fallback");

        let vendors = platform.detect_vendors().await;
        assert_eq!(vendors.len(), 1);

        let best_vendor = platform.select_best_vendor().await.unwrap();
        assert!(best_vendor.is_available().await);
    }

    #[tokio::test]
    async fn test_fallback_authentication() {
        let platform = FallbackPlatform::new();
        let result = platform.authenticate(b"challenge").await.unwrap();
        assert!(result.success);
        assert_eq!(result.method, AuthMethod::None);
    }

    #[tokio::test]
    async fn test_fallback_configuration() {
        let mut platform = FallbackPlatform::new();
        assert!(!platform.requires_authentication().await);

        let mut config = PlatformConfig::default();
        config.require_auth = true;
        platform.configure(config).await.unwrap();

        assert!(platform.requires_authentication().await);
    }
}
