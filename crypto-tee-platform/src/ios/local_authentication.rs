//! iOS Local Authentication Framework integration
//!
//! This module provides integration with iOS's LocalAuthentication framework
//! for biometric and passcode authentication.

use crate::error::{PlatformError, PlatformResult};
use crate::types::{AuthMethod, AuthResult};

/// Local authentication configuration
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct LAConfig {
    /// Allow fallback to passcode
    pub fallback_to_passcode: bool,
    /// Require biometric (no passcode fallback in UI)
    pub biometry_only: bool,
}

impl Default for LAConfig {
    fn default() -> Self {
        Self { fallback_to_passcode: true, biometry_only: false }
    }
}

/// Biometry type available on device
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub enum BiometryType {
    /// No biometry available
    None,
    /// Touch ID
    TouchId,
    /// Face ID
    FaceId,
}

/// Authentication policy
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LAPolicy {
    /// Biometry only
    BiometryOnly,
    /// Biometry or passcode
    BiometryOrPasscode,
}

/// Local authentication context
pub struct LAContext {
    #[allow(dead_code)]
    config: LAConfig,
}

impl LAContext {
    /// Create new authentication context
    pub fn new(config: LAConfig) -> Self {
        Self { config }
    }

    /// Evaluate authentication policy
    pub async fn evaluate_policy(
        &self,
        _policy: LAPolicy,
        challenge: Option<&[u8]>,
    ) -> PlatformResult<AuthResult> {
        // In a real implementation, this would:
        // 1. Create LAContext
        // 2. Check canEvaluatePolicy
        // 3. Call evaluatePolicy with completion handler
        // 4. If challenge provided, use it for domain state

        // Simulate authentication delay
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // For development, simulate successful authentication
        let _method = match self.biometry_type()? {
            BiometryType::FaceId => "face_id",
            BiometryType::TouchId => "touch_id",
            BiometryType::None => "passcode",
        };

        Ok(AuthResult {
            success: true,
            method: AuthMethod::Biometric,
            session_token: challenge.map(|c| c.to_vec()),
            valid_until: Some(std::time::SystemTime::now() + std::time::Duration::from_secs(300)),
        })
    }

    /// Get available biometry type
    pub fn biometry_type(&self) -> PlatformResult<BiometryType> {
        // In a real implementation, this would call LAContext.biometryType
        Ok(BiometryType::TouchId)
    }
}

impl Default for crate::ios::IOSPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_la_config() {
        let config = LAConfig::default();
        assert!(config.fallback_to_passcode);
        assert!(!config.biometry_only);
    }

    #[tokio::test]
    async fn test_local_authentication() {
        let config = LAConfig::default();
        let context = LAContext::new(config);
        let result = context
            .evaluate_policy(LAPolicy::BiometryOrPasscode, Some(b"test_challenge"))
            .await
            .unwrap();

        assert!(result.success);
        assert_eq!(result.method, AuthMethod::Biometric);
    }
}
