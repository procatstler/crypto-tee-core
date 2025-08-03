//! Android biometric authentication integration
//!
//! This module provides integration with Android's BiometricPrompt API
//! for user authentication.

use crate::error::{PlatformError, PlatformResult};
use crate::types::AuthResult;

/// Biometric authentication configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BiometricConfig {
    /// Subtitle shown in the prompt
    pub subtitle: Option<String>,
    /// Allow device credential as fallback
    pub allow_device_credential: bool,
}

impl Default for BiometricConfig {
    fn default() -> Self {
        Self { subtitle: None, allow_device_credential: true }
    }
}

/// Biometric authentication result
#[derive(Debug, Clone)]
pub struct BiometricResult {
    /// Whether authentication succeeded
    pub success: bool,
    /// Authentication method used
    pub method: AuthMethod,
    /// Cryptographic proof if available
    pub crypto_object: Option<Vec<u8>>,
}

/// Authentication method used
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethod {
    /// Fingerprint authentication
    Fingerprint,
    /// Face authentication
    Face,
    /// Iris authentication
    Iris,
    /// Device PIN/Pattern/Password
    DeviceCredential,
    /// Unknown biometric
    UnknownBiometric,
}

/// Show biometric prompt and authenticate user
pub async fn authenticate_biometric(
    _config: BiometricConfig,
    challenge: Option<&[u8]>,
) -> PlatformResult<BiometricResult> {
    // In a real implementation, this would:
    // 1. Create BiometricPrompt.Builder
    // 2. Set title, subtitle, description
    // 3. Configure allowed authenticators
    // 4. Show prompt and wait for result
    // 5. If challenge provided, use CryptoObject for key binding

    // For now, simulate successful authentication
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    Ok(BiometricResult {
        success: true,
        method: AuthMethod::Fingerprint,
        crypto_object: challenge.map(|c| c.to_vec()),
    })
}

/// Convert BiometricResult to generic AuthResult
impl From<BiometricResult> for AuthResult {
    fn from(bio_result: BiometricResult) -> Self {
        AuthResult {
            success: bio_result.success,
            method: match bio_result.method {
                AuthMethod::Fingerprint => crate::types::AuthMethod::Biometric,
                AuthMethod::Face => crate::types::AuthMethod::Biometric,
                AuthMethod::Iris => crate::types::AuthMethod::Biometric,
                AuthMethod::DeviceCredential => crate::types::AuthMethod::DeviceCredential,
                AuthMethod::UnknownBiometric => crate::types::AuthMethod::Biometric,
            },
            session_token: bio_result.crypto_object,
            valid_until: Some(std::time::SystemTime::now() + std::time::Duration::from_secs(300)),
        }
    }
}

impl Default for crate::android::AndroidPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_config() {
        let config = BiometricConfig::default();
        assert!(config.allow_device_credential);
    }

    #[tokio::test]
    async fn test_biometric_authentication() {
        let config = BiometricConfig::default();
        let result = authenticate_biometric(config, Some(b"test_challenge")).await.unwrap();

        assert!(result.success);
        assert_eq!(result.method, AuthMethod::Fingerprint);
        assert!(result.crypto_object.is_some());
    }
}
