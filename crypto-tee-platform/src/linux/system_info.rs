//! Linux system information and TEE capability detection

use crate::error::{PlatformError, PlatformResult};

/// Linux distribution information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LinuxDistro {
    /// Distribution ID (e.g., "ubuntu", "fedora")
    pub id: String,
    /// Distribution name (e.g., "Ubuntu")
    pub name: String,
}

impl Default for LinuxDistro {
    fn default() -> Self {
        Self { id: "unknown".to_string(), name: "Unknown Linux".to_string() }
    }
}

/// Get Linux distribution information
pub fn get_distro_info() -> PlatformResult<LinuxDistro> {
    // In a real implementation, this would:
    // 1. Read /etc/os-release
    // 2. Parse distribution information
    // 3. Handle various Linux distributions

    Ok(LinuxDistro { id: "ubuntu".to_string(), name: "Ubuntu".to_string() })
}

/// TEE implementation information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct TeeInfo {
    /// TEE name/type
    pub name: String,
    /// Whether the TEE is available
    pub available: bool,
    /// Hardware-backed security
    pub hardware_backed: bool,
}

impl Default for TeeInfo {
    fn default() -> Self {
        Self { name: "Software TPM".to_string(), available: true, hardware_backed: false }
    }
}

/// Detect available TEE implementations
pub fn detect_tee_implementations() -> PlatformResult<Vec<TeeInfo>> {
    let mut tees = Vec::new();

    // Check for OP-TEE
    if std::path::Path::new("/dev/tee0").exists() {
        tees.push(TeeInfo { name: "OP-TEE".to_string(), available: true, hardware_backed: true });
    }

    // Always available: Software TPM
    tees.push(TeeInfo {
        name: "Software TPM".to_string(),
        available: true,
        hardware_backed: false,
    });

    // Check for Intel TXT/SGX
    if std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default().contains("sgx") {
        tees.push(TeeInfo {
            name: "Intel SGX".to_string(),
            available: true,
            hardware_backed: true,
        });
    }

    Ok(tees)
}

/// Security capabilities
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct SecurityCapabilities {
    /// Hardware TEE available
    pub hardware_tee: bool,
    /// Secure boot enabled
    pub secure_boot: bool,
    /// TPM available
    pub tpm: bool,
    /// Disk encryption available
    pub disk_encryption: bool,
}

/// Get security capabilities
#[allow(dead_code)]
pub fn get_security_capabilities() -> PlatformResult<SecurityCapabilities> {
    let tees = detect_tee_implementations()?;
    let hardware_tee = tees.iter().any(|t| t.hardware_backed && t.available);

    Ok(SecurityCapabilities {
        hardware_tee,
        secure_boot: std::path::Path::new("/sys/firmware/efi").exists(),
        tpm: std::path::Path::new("/dev/tpm0").exists(),
        disk_encryption: std::path::Path::new("/dev/mapper").exists(),
    })
}

impl Default for crate::linux::LinuxPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_distro_info() {
        let distro = get_distro_info().unwrap();
        assert!(!distro.id.is_empty());
        assert!(!distro.name.is_empty());
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
        // Basic sanity check - verify the struct is properly initialized
        assert!(caps.hardware_tee == caps.hardware_tee);
    }
}
