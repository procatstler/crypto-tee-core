//! Android platform implementation
//!
//! This module provides integration with Android Keystore and
//! platform-specific security features.

mod biometric;
mod system_properties;

use async_trait::async_trait;
use crypto_tee_vendor::{VendorKeyHandle, VendorTEE};

use crate::{
    error::{PlatformError, PlatformResult},
    traits::{PlatformKeyHandle, PlatformTEE},
    types::{AuthResult, PlatformConfig},
};

use self::biometric::{BiometricPromptBuilder, is_biometric_available};
use self::system_properties::{get_android_version, detect_tee_vendors, get_security_level};

pub struct AndroidPlatform {
    config: PlatformConfig,
}

impl AndroidPlatform {
    pub fn new() -> Self {
        Self { config: PlatformConfig::default() }
    }
}

#[async_trait]
impl PlatformTEE for AndroidPlatform {
    fn name(&self) -> &str {
        "android"
    }

    fn version(&self) -> &str {
        // Get actual Android version
        match get_android_version() {
            Ok(version) => Box::leak(Box::new(format!("android-api-{}", version.api_level))),
            Err(_) => "android-unknown",
        }
    }

    async fn detect_vendors(&self) -> Vec<Box<dyn VendorTEE>> {
        // Detect available TEE vendors
        let mut vendors: Vec<Box<dyn VendorTEE>> = vec![];
        
        match detect_tee_vendors() {
            Ok(vendor_infos) => {
                for vendor_info in vendor_infos {
                    if vendor_info.available {
                        match vendor_info.name.as_str() {
                            "samsung_knox" => {
                                // In real implementation, load samsung vendor from separate crate
                                // For now, use mock vendor
                                vendors.push(Box::new(crypto_tee_vendor::MockVendor::new("samsung_knox")));
                            }
                            "android_trustzone" => {
                                // Default Android Keystore with TrustZone
                                vendors.push(Box::new(crypto_tee_vendor::MockVendor::new("android_trustzone")));
                            }
                            "android_strongbox" => {
                                // StrongBox Keymaster
                                vendors.push(Box::new(crypto_tee_vendor::MockVendor::new("android_strongbox")));
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to detect TEE vendors: {}", e);
            }
        }
        
        // Always provide software fallback
        if vendors.is_empty() {
            vendors.push(Box::new(crypto_tee_vendor::MockVendor::new("android_software")));
        }
        
        vendors
    }

    async fn select_best_vendor(&self) -> PlatformResult<Box<dyn VendorTEE>> {
        // Select best available vendor based on device capabilities
        let vendors = self.detect_vendors().await;
        
        if vendors.is_empty() {
            return Err(PlatformError::NotSupported(
                "No TEE vendors available on this device".to_string(),
            ));
        }
        
        // Priority order: StrongBox > Knox > TrustZone > Software
        let security_level = get_security_level()
            .unwrap_or(system_properties::SecurityLevel::Software);
            
        match security_level {
            system_properties::SecurityLevel::StrongBox => {
                // Prefer StrongBox if available
                for vendor in vendors {
                    let caps = vendor.probe().await?;
                    if caps.name.contains("strongbox") {
                        return Ok(vendor);
                    }
                }
            }
            system_properties::SecurityLevel::Knox => {
                // Prefer Knox on Samsung devices
                for vendor in vendors {
                    let caps = vendor.probe().await?;
                    if caps.name.contains("knox") {
                        return Ok(vendor);
                    }
                }
            }
            _ => {}
        }
        
        // Default to first hardware-backed vendor
        for vendor in vendors {
            let caps = vendor.probe().await?;
            if caps.hardware_backed {
                return Ok(vendor);
            }
        }
        
        // Fallback to first available vendor
        Ok(vendors.into_iter().next().unwrap())
    }

    async fn get_vendor(&self, name: &str) -> PlatformResult<Box<dyn VendorTEE>> {
        // Get specific vendor implementation
        let vendors = self.detect_vendors().await;
        
        for vendor in vendors {
            let caps = vendor.probe().await?;
            if caps.name.to_lowercase().contains(&name.to_lowercase()) {
                return Ok(vendor);
            }
        }
        
        Err(PlatformError::NotSupported(format!("Vendor '{}' not available on this device", name)))
    }

    async fn authenticate(&self, challenge: &[u8]) -> PlatformResult<AuthResult> {
        // Implement BiometricPrompt integration
        if !is_biometric_available()? {
            return Err(PlatformError::AuthFailed("Biometric authentication not available".to_string()));
        }
        
        let result = BiometricPromptBuilder::new("Authenticate to access secure key")
            .subtitle("Your biometric is required to use this key")
            .allow_device_credential(self.config.allow_device_credential)
            .authenticate(Some(challenge))
            .await?;
            
        Ok(result.into())
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
// - JNI bindings for Android Keystore
// - BiometricPrompt integration
// - StrongBox detection
// - Android-specific key management
