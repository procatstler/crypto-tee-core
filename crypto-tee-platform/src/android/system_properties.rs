//! Android system properties access
//!
//! This module provides functions to detect Android version,
//! available TEE vendors, and device capabilities.

use crate::error::PlatformResult;

/// Android version information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AndroidVersion {
    /// API level (e.g., 30 for Android 11)
    pub api_level: u32,
    /// Release version (e.g., "11", "12")
    pub release: String,
    /// Build ID
    pub build_id: String,
    /// Device manufacturer
    pub manufacturer: String,
    /// Device model
    pub model: String,
}

/// TEE vendor availability
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TeeVendorInfo {
    /// Vendor name
    pub name: String,
    /// Is available on this device
    pub available: bool,
    /// Version if available
    pub version: Option<String>,
    /// Hardware-backed
    pub hardware_backed: bool,
}

/// Get Android version information
pub fn get_android_version() -> PlatformResult<AndroidVersion> {
    // In a real implementation, this would use JNI to call:
    // - android.os.Build.VERSION.SDK_INT
    // - android.os.Build.VERSION.RELEASE
    // - android.os.Build.ID
    // - android.os.Build.MANUFACTURER
    // - android.os.Build.MODEL

    // For now, return mock data for development
    Ok(AndroidVersion {
        api_level: 31, // Android 12
        release: "12".to_string(),
        build_id: "SP1A.210812.016".to_string(),
        manufacturer: "samsung".to_string(),
        model: "SM-G991B".to_string(),
    })
}

/// Detect available TEE vendors on this device
pub fn detect_tee_vendors() -> PlatformResult<Vec<TeeVendorInfo>> {
    let mut vendors = Vec::new();

    // Check for Samsung Knox
    if is_samsung_knox_available()? {
        vendors.push(TeeVendorInfo {
            name: "samsung_knox".to_string(),
            available: true,
            version: get_knox_version()?,
            hardware_backed: true,
        });
    }

    // Check for default Android Keystore with TrustZone
    if is_trustzone_available()? {
        vendors.push(TeeVendorInfo {
            name: "android_trustzone".to_string(),
            available: true,
            version: Some("default".to_string()),
            hardware_backed: true,
        });
    }

    // Check for StrongBox
    if is_strongbox_available()? {
        vendors.push(TeeVendorInfo {
            name: "android_strongbox".to_string(),
            available: true,
            version: Some("1.0".to_string()),
            hardware_backed: true,
        });
    }

    Ok(vendors)
}

/// Check if Samsung Knox is available
fn is_samsung_knox_available() -> PlatformResult<bool> {
    // In a real implementation, this would check:
    // - Device manufacturer is Samsung
    // - Knox SDK is available
    // - Knox attestation is supported

    let version = get_android_version()?;
    Ok(version.manufacturer.to_lowercase() == "samsung" && version.api_level >= 28)
}

/// Get Knox version if available
fn get_knox_version() -> PlatformResult<Option<String>> {
    // In a real implementation, this would use Knox SDK to get version
    // For now, return mock version
    Ok(Some("3.7.1".to_string()))
}

/// Check if TrustZone is available
fn is_trustzone_available() -> PlatformResult<bool> {
    // Most Android devices have TrustZone
    // In a real implementation, this would check hardware capabilities
    Ok(true)
}

/// Check if StrongBox is available
fn is_strongbox_available() -> PlatformResult<bool> {
    // StrongBox is available on Android 9+ with hardware support
    // In a real implementation, this would check:
    // - PackageManager.FEATURE_STRONGBOX_KEYSTORE

    let version = get_android_version()?;
    Ok(version.api_level >= 28) // Android 9+
}

/// Get device security level
pub fn get_security_level() -> PlatformResult<SecurityLevel> {
    let _version = get_android_version()?;
    let vendors = detect_tee_vendors()?;

    if vendors.iter().any(|v| v.name == "android_strongbox" && v.available) {
        Ok(SecurityLevel::StrongBox)
    } else if vendors.iter().any(|v| v.name == "samsung_knox" && v.available) {
        Ok(SecurityLevel::Knox)
    } else if vendors.iter().any(|v| v.hardware_backed) {
        Ok(SecurityLevel::TrustedExecution)
    } else {
        Ok(SecurityLevel::Software)
    }
}

/// Device security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Software-only security
    Software,
    /// TEE-backed security
    TrustedExecution,
    /// Samsung Knox security
    Knox,
    /// StrongBox security (dedicated secure element)
    StrongBox,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_android_version() {
        let version = get_android_version().unwrap();
        assert!(version.api_level > 0);
        assert!(!version.release.is_empty());
    }

    #[test]
    fn test_vendor_detection() {
        let vendors = detect_tee_vendors().unwrap();
        assert!(!vendors.is_empty());

        // Should at least have TrustZone
        assert!(vendors.iter().any(|v| v.name == "android_trustzone"));
    }

    #[test]
    fn test_security_level() {
        let level = get_security_level().unwrap();
        // Should at least have TEE
        assert!(level as u32 >= SecurityLevel::TrustedExecution as u32);
    }
}
