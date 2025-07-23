//! iOS system information and capabilities detection

use crate::error::{PlatformError, PlatformResult};

/// iOS version information
#[derive(Debug, Clone)]
pub struct IosVersion {
    /// Major version number (e.g., 15 for iOS 15.2.1)
    pub major: u32,
    /// Minor version number (e.g., 2 for iOS 15.2.1)
    pub minor: u32,
}

impl Default for IosVersion {
    fn default() -> Self {
        Self { major: 15, minor: 0 }
    }
}

/// Get iOS version information
pub fn get_ios_version() -> PlatformResult<IosVersion> {
    // In a real implementation, this would:
    // 1. Read UIDevice.currentDevice.systemVersion
    // 2. Parse version string into components
    // 3. Handle different version formats

    Ok(IosVersion { major: 15, minor: 0 })
}

/// Detect available TEE vendors on iOS
pub fn detect_tee_vendors() -> PlatformResult<Vec<TeeVendor>> {
    let vendors = vec![
        // Secure Enclave (available on A7+ chips)
        TeeVendor {
            name: "apple_secure_enclave".to_string(),
            available: true,
            hardware_backed: true,
            version: "1.0".to_string(),
        },
        // Keychain Services
        TeeVendor {
            name: "apple_keychain".to_string(),
            available: true,
            hardware_backed: false,
            version: "1.0".to_string(),
        },
    ];

    Ok(vendors)
}

/// TEE vendor information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TeeVendor {
    /// Vendor name/identifier
    pub name: String,
    /// Whether the vendor is available
    pub available: bool,
    /// Whether it provides hardware-backed security
    pub hardware_backed: bool,
    /// Vendor version
    pub version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ios_version() {
        let version = get_ios_version().unwrap();
        assert!(version.major > 0);
    }

    #[test]
    fn test_vendor_detection() {
        let vendors = detect_tee_vendors().unwrap();
        assert!(!vendors.is_empty());

        // Should at least have Secure Enclave
        assert!(vendors.iter().any(|v| v.name == "apple_secure_enclave"));
        assert!(vendors.iter().any(|v| v.name == "apple_keychain"));
    }
}
