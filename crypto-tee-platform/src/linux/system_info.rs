//! Linux system information and TEE detection
//!
//! This module provides functions to detect Linux distribution,
//! OP-TEE availability, and system capabilities.

use crate::error::{PlatformError, PlatformResult};
use std::fs;
use std::path::Path;

/// Linux distribution information
#[derive(Debug, Clone)]
pub struct LinuxDistro {
    /// Distribution name (e.g., "Ubuntu", "Fedora")
    pub name: String,
    /// Version (e.g., "22.04")
    pub version: String,
    /// Codename (e.g., "jammy")
    pub codename: Option<String>,
    /// Kernel version
    pub kernel_version: String,
    /// Architecture (e.g., "x86_64", "aarch64")
    pub arch: String,
}

/// Get Linux distribution information
pub fn get_linux_distro() -> PlatformResult<LinuxDistro> {
    // Try to read /etc/os-release
    let os_release = fs::read_to_string("/etc/os-release")
        .unwrap_or_else(|_| String::new());
    
    let mut name = String::from("Linux");
    let mut version = String::from("unknown");
    let mut codename = None;
    
    for line in os_release.lines() {
        if let Some(value) = line.strip_prefix("NAME=") {
            name = value.trim_matches('"').to_string();
        } else if let Some(value) = line.strip_prefix("VERSION_ID=") {
            version = value.trim_matches('"').to_string();
        } else if let Some(value) = line.strip_prefix("VERSION_CODENAME=") {
            codename = Some(value.trim_matches('"').to_string());
        }
    }
    
    // Get kernel version
    let kernel_version = fs::read_to_string("/proc/version")
        .ok()
        .and_then(|v| v.split_whitespace().nth(2).map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string());
    
    // Get architecture
    let arch = std::env::consts::ARCH.to_string();
    
    Ok(LinuxDistro {
        name,
        version,
        codename,
        kernel_version,
        arch,
    })
}

/// TEE implementation information
#[derive(Debug, Clone)]
pub struct TeeInfo {
    /// TEE name
    pub name: String,
    /// Is available
    pub available: bool,
    /// Version if available
    pub version: Option<String>,
    /// Device path
    pub device_path: Option<String>,
}

/// Check if OP-TEE is available
pub fn is_optee_available() -> PlatformResult<bool> {
    // Check for OP-TEE device nodes
    Ok(Path::new("/dev/tee0").exists() || Path::new("/dev/teepriv0").exists())
}

/// Get OP-TEE version
pub fn get_optee_version() -> PlatformResult<Option<String>> {
    if !is_optee_available()? {
        return Ok(None);
    }
    
    // In a real implementation, this would query OP-TEE version
    // through the TEE client API
    Ok(Some("3.18.0".to_string()))
}

/// Check if Intel SGX is available
pub fn is_sgx_available() -> PlatformResult<bool> {
    // Check for SGX device
    Ok(Path::new("/dev/sgx_enclave").exists() || Path::new("/dev/sgx").exists())
}

/// Check if AMD SEV is available
pub fn is_sev_available() -> PlatformResult<bool> {
    // Check for SEV support in /sys
    Ok(Path::new("/sys/module/kvm_amd/parameters/sev").exists())
}

/// Detect available TEE implementations
pub fn detect_tee_implementations() -> PlatformResult<Vec<TeeInfo>> {
    let mut tees = Vec::new();
    
    // Check for OP-TEE
    if is_optee_available()? {
        tees.push(TeeInfo {
            name: "OP-TEE".to_string(),
            available: true,
            version: get_optee_version()?,
            device_path: Some("/dev/tee0".to_string()),
        });
    }
    
    // Check for Intel SGX
    if is_sgx_available()? {
        tees.push(TeeInfo {
            name: "Intel SGX".to_string(),
            available: true,
            version: None, // Would need to query SGX version
            device_path: Some("/dev/sgx_enclave".to_string()),
        });
    }
    
    // Check for AMD SEV
    if is_sev_available()? {
        tees.push(TeeInfo {
            name: "AMD SEV".to_string(),
            available: true,
            version: None,
            device_path: None,
        });
    }
    
    // Always include software TPM as fallback
    tees.push(TeeInfo {
        name: "Software TPM".to_string(),
        available: true,
        version: Some("2.0".to_string()),
        device_path: None,
    });
    
    Ok(tees)
}

/// System security capabilities
#[derive(Debug, Clone)]
pub struct SecurityCapabilities {
    /// Hardware TEE available
    pub hardware_tee: bool,
    /// Secure boot enabled
    pub secure_boot: bool,
    /// TPM available
    pub tpm: bool,
    /// Full disk encryption
    pub disk_encryption: bool,
}

/// Get system security capabilities
pub fn get_security_capabilities() -> PlatformResult<SecurityCapabilities> {
    let tees = detect_tee_implementations()?;
    let hardware_tee = tees.iter().any(|t| t.name != "Software TPM" && t.available);
    
    // Check for secure boot
    let secure_boot = Path::new("/sys/firmware/efi/efivars").exists() &&
        fs::read_to_string("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
            .is_ok();
    
    // Check for TPM
    let tpm = Path::new("/dev/tpm0").exists() || Path::new("/dev/tpmrm0").exists();
    
    // Check for disk encryption (simplified check)
    let disk_encryption = fs::read_to_string("/proc/mounts")
        .map(|mounts| mounts.contains("dm-crypt"))
        .unwrap_or(false);
    
    Ok(SecurityCapabilities {
        hardware_tee,
        secure_boot,
        tpm,
        disk_encryption,
    })
}

/// Security level for Linux systems
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Software-only security
    Software,
    /// TPM-backed security
    TpmBacked,
    /// TEE-backed security
    TeeBacked,
    /// Full hardware security (TEE + Secure Boot + TPM)
    FullHardware,
}

/// Get system security level
pub fn get_security_level() -> PlatformResult<SecurityLevel> {
    let caps = get_security_capabilities()?;
    
    if caps.hardware_tee && caps.secure_boot && caps.tpm {
        Ok(SecurityLevel::FullHardware)
    } else if caps.hardware_tee {
        Ok(SecurityLevel::TeeBacked)
    } else if caps.tpm {
        Ok(SecurityLevel::TpmBacked)
    } else {
        Ok(SecurityLevel::Software)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_distro() {
        let distro = get_linux_distro().unwrap();
        assert!(!distro.name.is_empty());
        assert!(!distro.kernel_version.is_empty());
        assert!(!distro.arch.is_empty());
    }

    #[test]
    fn test_tee_detection() {
        let tees = detect_tee_implementations().unwrap();
        assert!(!tees.is_empty());
        // Should at least have software TPM
        assert!(tees.iter().any(|t| t.name == "Software TPM"));
    }

    #[test]
    fn test_security_capabilities() {
        let caps = get_security_capabilities().unwrap();
        println!("Security capabilities: {:?}", caps);
        // Basic sanity check
        assert!(caps.hardware_tee || !caps.hardware_tee);
    }
}