//! iOS system information and capability detection
//!
//! This module provides functions to detect iOS version,
//! Secure Enclave availability, and device capabilities.

use crate::error::PlatformResult;

/// iOS version information
#[derive(Debug, Clone)]
pub struct IosVersion {
    /// Major version (e.g., 15)
    pub major: u32,
    /// Minor version (e.g., 0)
    pub minor: u32,
    /// Patch version (e.g., 1)
    pub patch: u32,
    /// Build number
    pub build: String,
    /// Device model (e.g., "iPhone13,2")
    pub model: String,
    /// Device name (e.g., "iPhone 12")
    pub device_name: String,
}

/// Get iOS version information
pub fn get_ios_version() -> PlatformResult<IosVersion> {
    // In a real implementation, this would use:
    // - UIDevice.current.systemVersion
    // - UIDevice.current.model
    // - sysctl for hardware model
    
    // For now, return mock data for development
    Ok(IosVersion {
        major: 16,
        minor: 2,
        patch: 0,
        build: "20C65".to_string(),
        model: "iPhone14,2".to_string(),
        device_name: "iPhone 13 Pro".to_string(),
    })
}

/// Check if Secure Enclave is available
pub fn is_secure_enclave_available() -> PlatformResult<bool> {
    // Secure Enclave is available on:
    // - iPhone 5s and later
    // - iPad Air and later
    // - All Apple Silicon Macs
    
    let version = get_ios_version()?;
    
    // Check device model
    if version.model.starts_with("iPhone") {
        // Extract model number
        if let Some(model_num) = version.model
            .strip_prefix("iPhone")
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.parse::<u32>().ok())
        {
            // iPhone 5s is iPhone6,1 and iPhone6,2
            return Ok(model_num >= 6);
        }
    }
    
    // For development, assume Secure Enclave is available
    Ok(true)
}

/// Check if Face ID is available
pub fn is_face_id_available() -> PlatformResult<bool> {
    let version = get_ios_version()?;
    
    // Face ID devices start with iPhone X (iPhone10,3 and iPhone10,6)
    if version.model.starts_with("iPhone") {
        if let Some(model_num) = version.model
            .strip_prefix("iPhone")
            .and_then(|s| s.split(',').next())
            .and_then(|s| s.parse::<u32>().ok())
        {
            return Ok(model_num >= 10);
        }
    }
    
    Ok(false)
}

/// Check if Touch ID is available
pub fn is_touch_id_available() -> PlatformResult<bool> {
    // Touch ID is available on devices with Secure Enclave but not Face ID
    Ok(is_secure_enclave_available()? && !is_face_id_available()?)
}

/// Get device security capabilities
#[derive(Debug, Clone)]
pub struct SecurityCapabilities {
    /// Secure Enclave available
    pub secure_enclave: bool,
    /// Face ID available
    pub face_id: bool,
    /// Touch ID available
    pub touch_id: bool,
    /// Device passcode set
    pub passcode_set: bool,
    /// Biometric enrolled
    pub biometric_enrolled: bool,
}

/// Get device security capabilities
pub fn get_security_capabilities() -> PlatformResult<SecurityCapabilities> {
    Ok(SecurityCapabilities {
        secure_enclave: is_secure_enclave_available()?,
        face_id: is_face_id_available()?,
        touch_id: is_touch_id_available()?,
        passcode_set: true, // In real implementation, check LAContext
        biometric_enrolled: true, // In real implementation, check LAContext
    })
}

/// Device security level
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// No hardware security
    None,
    /// Secure Enclave with passcode
    SecureEnclavePasscode,
    /// Secure Enclave with Touch ID
    SecureEnclaveTouchId,
    /// Secure Enclave with Face ID
    SecureEnclaveFaceId,
}

/// Get device security level
pub fn get_security_level() -> PlatformResult<SecurityLevel> {
    let caps = get_security_capabilities()?;
    
    if !caps.secure_enclave {
        return Ok(SecurityLevel::None);
    }
    
    if caps.face_id && caps.biometric_enrolled {
        Ok(SecurityLevel::SecureEnclaveFaceId)
    } else if caps.touch_id && caps.biometric_enrolled {
        Ok(SecurityLevel::SecureEnclaveTouchId)
    } else if caps.passcode_set {
        Ok(SecurityLevel::SecureEnclavePasscode)
    } else {
        Ok(SecurityLevel::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ios_version() {
        let version = get_ios_version().unwrap();
        assert!(version.major > 0);
        assert!(!version.build.is_empty());
    }

    #[test]
    fn test_secure_enclave_detection() {
        assert!(is_secure_enclave_available().unwrap());
    }

    #[test]
    fn test_security_capabilities() {
        let caps = get_security_capabilities().unwrap();
        assert!(caps.secure_enclave);
        assert!(caps.face_id || caps.touch_id);
    }
}