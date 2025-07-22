//! Apple Secure Enclave Implementation
//!
//! This module provides the actual implementation for Apple Secure Enclave,
//! integrating with iOS/macOS Security Framework and CryptoKit.

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod secure_enclave;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod keychain;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod biometric;

#[cfg(any(target_os = "ios", target_os = "macos"))]
pub mod cryptokit_bridge;

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
pub mod stub;

use crate::error::VendorResult;
use crate::traits::VendorTEE;
use crate::types::*;

/// Get Apple Secure Enclave implementation
pub fn get_apple_tee() -> VendorResult<Box<dyn VendorTEE>> {
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    {
        // Check if Secure Enclave is available
        if secure_enclave::AppleSecureEnclave::is_secure_enclave_available()? {
            Ok(Box::new(secure_enclave::AppleSecureEnclave::new()?))
        } else {
            Err(crate::error::VendorError::NotSupported(
                "Secure Enclave is not available on this device".to_string(),
            ))
        }
    }

    #[cfg(not(any(target_os = "ios", target_os = "macos")))]
    {
        // Return stub implementation for non-Apple platforms
        Ok(Box::new(stub::AppleSecureEnclaveStub::new()))
    }
}

/// Apple Secure Enclave specific parameters
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SecureEnclaveParams {
    /// Use Secure Enclave for key operations
    pub use_secure_enclave: bool,

    /// Require Touch ID or Face ID for key usage
    pub require_biometric: bool,

    /// Require device passcode for key usage
    pub require_passcode: bool,

    /// Access control flags
    pub access_control: Option<AccessControl>,

    /// Keychain access group
    pub access_group: Option<String>,

    /// Key label in keychain
    pub label: Option<String>,

    /// Application tag for the key
    pub application_tag: Option<Vec<u8>>,
}

/// Access control options for Secure Enclave keys
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AccessControl {
    /// Require user presence (any authentication)
    pub user_presence: bool,

    /// Require biometric authentication
    pub biometry_any: bool,

    /// Require current biometric set
    pub biometry_current_set: bool,

    /// Require device passcode
    pub device_passcode: bool,

    /// Key usage constraints
    pub constraints: Vec<AccessConstraint>,
}

/// Access constraints for key usage
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AccessConstraint {
    /// Key can only be used while device is unlocked
    DeviceUnlocked,

    /// Key can only be used after first unlock
    AfterFirstUnlock,

    /// Key is always accessible
    Always,

    /// Key requires authentication for each use
    UserAuthentication,
}

impl Default for SecureEnclaveParams {
    fn default() -> Self {
        Self {
            use_secure_enclave: true,
            require_biometric: false,
            require_passcode: false,
            access_control: None,
            access_group: None,
            label: None,
            application_tag: None,
        }
    }
}

impl Default for AccessControl {
    fn default() -> Self {
        Self {
            user_presence: false,
            biometry_any: false,
            biometry_current_set: false,
            device_passcode: false,
            constraints: vec![AccessConstraint::DeviceUnlocked],
        }
    }
}
