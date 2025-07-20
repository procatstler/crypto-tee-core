//! Platform-specific types and data structures

use serde::{Deserialize, Serialize};

/// Platform authentication result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    /// Whether authentication was successful
    pub success: bool,
    
    /// Authentication method used
    pub method: AuthMethod,
    
    /// Optional session token
    pub session_token: Option<Vec<u8>>,
    
    /// Time until re-authentication is required
    pub valid_until: Option<std::time::SystemTime>,
}

/// Authentication methods supported by platforms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMethod {
    None,
    Password,
    Biometric,
    BiometricStrong,
    DeviceCredential,
    TrustedDevice,
}

/// Platform-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlatformConfig {
    /// Require user authentication for key usage
    pub require_auth: bool,
    
    /// Authentication validity duration in seconds
    pub auth_validity_seconds: Option<u32>,
    
    /// Allow biometric authentication
    pub allow_biometric: bool,
    
    /// Require strong biometric (e.g., Face ID vs Touch ID)
    pub require_strong_biometric: bool,
    
    /// Platform-specific options
    pub platform_options: Option<PlatformOptions>,
}

impl Default for PlatformConfig {
    fn default() -> Self {
        Self {
            require_auth: false,
            auth_validity_seconds: None,
            allow_biometric: true,
            require_strong_biometric: false,
            platform_options: None,
        }
    }
}

/// Platform-specific options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PlatformOptions {
    Android(AndroidOptions),
    IOS(IOSOptions),
    Linux(LinuxOptions),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidOptions {
    /// Use Android Keystore
    pub use_keystore: bool,
    
    /// Require unlocked device
    pub require_unlocked: bool,
    
    /// Use StrongBox if available
    pub prefer_strongbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IOSOptions {
    /// Use Keychain Services
    pub use_keychain: bool,
    
    /// Keychain access group
    pub access_group: Option<String>,
    
    /// Require device passcode
    pub require_passcode: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinuxOptions {
    /// Use system keyring
    pub use_keyring: bool,
    
    /// Keyring backend
    pub keyring_backend: Option<String>,
}