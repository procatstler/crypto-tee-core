//! Linux platform implementation
//!
//! This module provides integration with Linux keyring and
//! OP-TEE where available.

mod system_info;

use async_trait::async_trait;
use crypto_tee_vendor::{VendorKeyHandle, VendorTEE};

use crate::{
    error::{PlatformError, PlatformResult},
    traits::{PlatformKeyHandle, PlatformTEE},
    types::{AuthResult, AuthMethod, PlatformConfig},
};

use self::system_info::{detect_tee_implementations, get_linux_distro, get_security_level};

pub struct LinuxPlatform {
    config: PlatformConfig,
}

impl LinuxPlatform {
    pub fn new() -> Self {
        Self { config: PlatformConfig::default() }
    }
}

#[async_trait]
impl PlatformTEE for LinuxPlatform {
    fn name(&self) -> &str {
        "linux"
    }

    fn version(&self) -> &str {
        // Get kernel version
        match get_linux_distro() {
            Ok(distro) => Box::leak(Box::new(format!("{}-{}", distro.name, distro.kernel_version))),
            Err(_) => "linux-unknown",
        }
    }

    async fn detect_vendors(&self) -> Vec<Box<dyn VendorTEE>> {
        // Detect available TEE implementations
        let mut vendors: Vec<Box<dyn VendorTEE>> = vec![];

        match detect_tee_implementations() {
            Ok(tee_infos) => {
                for tee_info in tee_infos {
                    if tee_info.available {
                        match tee_info.name.as_str() {
                            "OP-TEE" => {
                                // In real implementation, load OP-TEE client from separate crate
                                // For now, use mock vendor
                                vendors.push(Box::new(crypto_tee_vendor::MockVendor::new(
                                    "linux_op_tee",
                                )));
                            }
                            "Intel SGX" => {
                                vendors.push(Box::new(crypto_tee_vendor::MockVendor::new(
                                    "intel_sgx",
                                )));
                            }
                            "AMD SEV" => {
                                vendors
                                    .push(Box::new(crypto_tee_vendor::MockVendor::new("amd_sev")));
                            }
                            "Software TPM" => {
                                vendors.push(Box::new(crypto_tee_vendor::MockVendor::new(
                                    "software_tpm",
                                )));
                            }
                            _ => {}
                        }
                    }
                }
            }
            Err(e) => {
                tracing::warn!("Failed to detect TEE implementations: {}", e);
            }
        }

        // Always provide software fallback
        if vendors.is_empty() {
            vendors.push(Box::new(crypto_tee_vendor::MockVendor::new("linux_software")));
        }

        vendors
    }

    async fn select_best_vendor(&self) -> PlatformResult<Box<dyn VendorTEE>> {
        // Select best available vendor based on security level
        let mut vendors = self.detect_vendors().await;

        if vendors.is_empty() {
            return Err(PlatformError::NotSupported(
                "No TEE vendors available on Linux".to_string(),
            ));
        }

        // Priority order: OP-TEE > Intel SGX > AMD SEV > TPM > Software
        let priority_order = ["op_tee", "intel_sgx", "amd_sev", "tpm", "software"];

        for priority_name in &priority_order {
            for i in (0..vendors.len()).rev() {
                match vendors[i].probe().await {
                    Ok(caps) if caps.name.to_lowercase().contains(priority_name) && caps.hardware_backed => {
                        return Ok(vendors.swap_remove(i));
                    }
                    _ => continue,
                }
            }
        }

        // Fallback to first available vendor
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

        Err(PlatformError::NotSupported(format!("Vendor '{}' not available on Linux", name)))
    }

    async fn authenticate(&self, _challenge: &[u8]) -> PlatformResult<AuthResult> {
        // Linux typically doesn't have built-in biometric auth
        // Could integrate with PAM or PolicyKit
        Ok(AuthResult {
            success: true,
            method: AuthMethod::Password,
            session_token: None,
            valid_until: Some(std::time::SystemTime::now() + std::time::Duration::from_secs(3600)),
        })
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
// - Linux keyring integration
// - OP-TEE client library bindings
// - TPM 2.0 integration (optional)
// - systemd integration for secure storage
