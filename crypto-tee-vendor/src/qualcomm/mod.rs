//! Qualcomm QSEE (Qualcomm Secure Execution Environment) implementation
//!
//! This module provides integration with Qualcomm's QSEE for secure cryptographic
//! operations on Qualcomm Snapdragon processors.

use crate::error::{VendorError, VendorResult};
use crate::traits::VendorTEE;
use crate::types::*;
// use async_trait::async_trait;
// use std::collections::HashMap;
use std::sync::Arc;
// use std::sync::Mutex;

#[cfg(not(target_os = "android"))]
mod stub;
#[cfg(not(target_os = "android"))]
pub use stub::QualcommStubTEE as QualcommQSEE;

#[cfg(target_os = "android")]
mod qsee;
#[cfg(target_os = "android")]
pub use qsee::QualcommQSEE;

#[cfg(target_os = "android")]
mod jni_bridge;
#[cfg(target_os = "android")]
mod qsee_comm;
#[cfg(target_os = "android")]
mod secure_channel;
#[cfg(target_os = "android")]
mod trustzone;

/// Get Qualcomm QSEE instance
pub fn get_qualcomm_tee() -> VendorResult<Arc<dyn VendorTEE>> {
    Ok(Arc::new(QualcommQSEE::new()?))
}

/// QSEE-specific parameters
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QSEEParams {
    /// Use hardware-backed keystore
    pub use_hardware_keystore: bool,

    /// Use secure channel for communication
    pub use_secure_channel: bool,

    /// TrustZone app name (if custom)
    pub trustzone_app_name: Option<String>,

    /// Key protection level
    pub protection_level: ProtectionLevel,

    /// Require user authentication
    pub require_auth: bool,

    /// Authentication validity duration in seconds
    pub auth_validity_duration: Option<u32>,

    /// Use StrongBox if available (Pixel 3+)
    pub use_strongbox: bool,
}

impl Default for QSEEParams {
    fn default() -> Self {
        Self {
            use_hardware_keystore: true,
            use_secure_channel: true,
            trustzone_app_name: None,
            protection_level: ProtectionLevel::Hardware,
            require_auth: false,
            auth_validity_duration: None,
            use_strongbox: false,
        }
    }
}

/// QSEE key protection levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProtectionLevel {
    /// Software-based protection
    Software,

    /// Hardware-backed protection (TEE)
    Hardware,

    /// StrongBox protection (dedicated secure element)
    StrongBox,
}

/// QSEE capabilities
#[derive(Debug, Clone)]
pub struct QSEECapabilities {
    /// Hardware crypto support
    pub hardware_crypto: bool,

    /// Secure storage available
    pub secure_storage: bool,

    /// Attestation support
    pub attestation: bool,

    /// StrongBox available
    pub strongbox: bool,

    /// Supported algorithms
    pub algorithms: Vec<Algorithm>,

    /// Maximum key size
    pub max_key_size: usize,
}

impl QSEECapabilities {
    /// Check if QSEE is available on device
    pub fn is_available() -> bool {
        #[cfg(target_os = "android")]
        {
            // Check for QSEE by looking for specific system properties
            qsee::check_qsee_availability()
        }

        #[cfg(not(target_os = "android"))]
        {
            false
        }
    }

    /// Get device capabilities
    pub fn get_capabilities() -> VendorResult<Self> {
        #[cfg(target_os = "android")]
        {
            qsee::query_capabilities()
        }

        #[cfg(not(target_os = "android"))]
        {
            Err(VendorError::NotSupported(
                "QSEE is only available on Android with Qualcomm chipsets".to_string(),
            ))
        }
    }
}
