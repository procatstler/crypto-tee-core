//! iOS platform implementation
//!
//! This module provides integration with iOS Keychain Services and
//! Secure Enclave through platform APIs.

mod local_authentication;
mod system_info;

use async_trait::async_trait;
use crypto_tee_vendor::{VendorKeyHandle, VendorTEE};

use crate::{
    error::{PlatformError, PlatformResult},
    traits::{PlatformKeyHandle, PlatformTEE},
    types::{AuthResult, PlatformConfig},
};

use self::local_authentication::{LAConfig, LAContext, LAPolicy};
use self::system_info::{detect_tee_vendors, get_ios_version};

pub struct IOSPlatform {
    config: PlatformConfig,
}

impl IOSPlatform {
    pub fn new() -> Self {
        Self { config: PlatformConfig::default() }
    }
}

#[async_trait]
impl PlatformTEE for IOSPlatform {
    fn name(&self) -> &str {
        "ios"
    }

    fn version(&self) -> &str {
        // Get actual iOS version
        match get_ios_version() {
            Ok(version) => Box::leak(Box::new(format!("ios-{}.{}", version.major, version.minor))),
            Err(_) => "ios-unknown",
        }
    }

    async fn detect_vendors(&self) -> Vec<Box<dyn VendorTEE>> {
        // Detect Secure Enclave availability
        let mut vendors: Vec<Box<dyn VendorTEE>> = vec![];

        // Check if Secure Enclave vendors are available
        let tee_vendors = detect_tee_vendors().unwrap_or_default();
        if tee_vendors.iter().any(|v| v.name == "apple_secure_enclave" && v.available) {
            // In real implementation, load Apple Secure Enclave vendor from separate crate
            // For now, use mock vendor
            vendors.push(Box::new(crypto_tee_vendor::MockVendor::new("apple_secure_enclave")));
        }

        // Always provide software fallback through Keychain
        vendors.push(Box::new(crypto_tee_vendor::MockVendor::new("ios_keychain")));

        vendors
    }

    async fn select_best_vendor(&self) -> PlatformResult<Box<dyn VendorTEE>> {
        // Select Secure Enclave if available
        let mut vendors = self.detect_vendors().await;

        if vendors.is_empty() {
            return Err(PlatformError::NotSupported("No vendors available on iOS".to_string()));
        }

        // Prefer Secure Enclave over Keychain
        for i in (0..vendors.len()).rev() {
            match vendors[i].probe().await {
                Ok(caps) if caps.name.contains("secure_enclave") => {
                    return Ok(vendors.swap_remove(i));
                }
                _ => continue,
            }
        }

        // Fallback to first available (Keychain)
        Ok(vendors.into_iter().next().unwrap())
    }

    async fn get_vendor(&self, name: &str) -> PlatformResult<Box<dyn VendorTEE>> {
        // Get specific vendor
        let vendors = self.detect_vendors().await;

        for vendor in vendors {
            let caps = vendor.probe().await?;
            if caps.name.to_lowercase().contains(&name.to_lowercase()) {
                return Ok(vendor);
            }
        }

        Err(PlatformError::NotSupported(format!("Vendor '{}' not available on iOS", name)))
    }

    async fn authenticate(&self, challenge: &[u8]) -> PlatformResult<AuthResult> {
        // Implement LAContext biometric authentication
        let config = LAConfig {
            fallback_to_passcode: !self.config.require_strong_biometric,
            biometry_only: self.config.require_strong_biometric,
        };

        let _policy = if self.config.require_strong_biometric {
            LAPolicy::BiometryOnly
        } else {
            LAPolicy::BiometryOrPasscode
        };

        let context = LAContext::new(config);
        let result = context.evaluate_policy(_policy, Some(challenge)).await?;

        Ok(result)
    }

    async fn requires_authentication(&self) -> bool {
        self.config.require_auth
    }

    async fn configure(&mut self, config: PlatformConfig) -> PlatformResult<()> {
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

// Platform-specific implementations will be added here
// - Keychain Services integration
// - LAContext for biometric authentication
// - Secure Enclave access through SecKey
// - iOS-specific access control
