//! Samsung Knox TEE Implementation
//!
//! This module provides the actual implementation for Samsung Knox TEE,
//! integrating with Samsung's Knox SDK through JNI on Android devices.

#[cfg(target_os = "android")]
pub mod knox;

#[cfg(target_os = "android")]
pub mod jni_bridge;

#[cfg(target_os = "android")]
pub mod knox_vault;

#[cfg(target_os = "android")]
pub mod trustzone;

#[cfg(not(target_os = "android"))]
pub mod stub;

use crate::error::VendorResult;
use crate::traits::VendorTEE;
use crate::types::*;

/// Get Samsung Knox TEE implementation
pub fn get_samsung_tee() -> VendorResult<Box<dyn VendorTEE>> {
    #[cfg(target_os = "android")]
    {
        // Check if Knox is available on the device
        if knox::is_knox_available()? {
            Ok(Box::new(knox::SamsungKnoxTEE::new()?))
        } else {
            Err(crate::error::VendorError::NotSupported(
                "Samsung Knox is not available on this device".to_string(),
            ))
        }
    }

    #[cfg(not(target_os = "android"))]
    {
        // Return stub implementation for non-Android platforms
        Ok(Box::new(stub::SamsungKnoxStub::new()))
    }
}

/// Samsung Knox specific vendor parameters
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnoxParams {
    /// Use Knox Vault for key storage
    pub use_knox_vault: bool,

    /// Require user authentication for key usage
    pub require_user_auth: bool,

    /// User authentication validity duration in seconds
    pub auth_validity_seconds: Option<u32>,

    /// Use TrustZone for cryptographic operations
    pub use_trustzone: bool,

    /// Enable Knox attestation
    pub enable_attestation: bool,

    /// Knox container ID (if using Knox workspace)
    pub container_id: Option<u32>,
}

impl Default for KnoxParams {
    fn default() -> Self {
        Self {
            use_knox_vault: true,
            require_user_auth: false,
            auth_validity_seconds: None,
            use_trustzone: true,
            enable_attestation: true,
            container_id: None,
        }
    }
}
