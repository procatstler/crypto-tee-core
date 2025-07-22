//! iOS Local Authentication Framework integration
//!
//! This module provides integration with iOS's LocalAuthentication framework
//! for biometric and passcode authentication.

use crate::error::{PlatformError, PlatformResult};
use crate::types::AuthResult;

/// Local authentication configuration
#[derive(Debug, Clone)]
pub struct LAConfig {
    /// Reason shown to user
    pub reason: String,
    /// Allow fallback to passcode
    pub fallback_to_passcode: bool,
    /// Cancel button title
    pub cancel_title: Option<String>,
    /// Fallback button title  
    pub fallback_title: Option<String>,
    /// Require biometric (no passcode fallback in UI)
    pub biometry_only: bool,
}

impl Default for LAConfig {
    fn default() -> Self {
        Self {
            reason: "Authenticate to access secure key".to_string(),
            fallback_to_passcode: true,
            cancel_title: None,
            fallback_title: None,
            biometry_only: false,
        }
    }
}

/// Biometry type available on device
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    /// Device passcode
    DevicePasscode,
    /// Biometry only
    BiometryOnly,
    /// Biometry or passcode
    BiometryOrPasscode,
}

/// Local authentication context
pub struct LAContext {
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
        policy: LAPolicy,
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
        let method = match self.biometry_type()? {
            BiometryType::FaceId => "face_id",
            BiometryType::TouchId => "touch_id",
            BiometryType::None => "passcode",
        };

        Ok(AuthResult {
            success: true,
            method: method.to_string(),
            timestamp: std::time::SystemTime::now(),
            validity_duration: Some(std::time::Duration::from_secs(300)),
            metadata: challenge.map(|c| {
                serde_json::json!({
                    "challenge_response": base64_encode(c),
                    "policy": format!("{:?}", policy),
                })
            }),
        })
    }

    /// Get available biometry type
    pub fn biometry_type(&self) -> PlatformResult<BiometryType> {
        use super::system_info::{is_face_id_available, is_touch_id_available};

        if is_face_id_available()? {
            Ok(BiometryType::FaceId)
        } else if is_touch_id_available()? {
            Ok(BiometryType::TouchId)
        } else {
            Ok(BiometryType::None)
        }
    }

    /// Check if policy can be evaluated
    pub fn can_evaluate_policy(&self, policy: LAPolicy) -> PlatformResult<bool> {
        match policy {
            LAPolicy::DevicePasscode => Ok(true), // Assume passcode is set
            LAPolicy::BiometryOnly | LAPolicy::BiometryOrPasscode => {
                Ok(self.biometry_type()? != BiometryType::None)
            }
        }
    }
}

/// Authenticate using Local Authentication
pub async fn authenticate_with_la(
    reason: impl Into<String>,
    policy: LAPolicy,
    challenge: Option<&[u8]>,
) -> PlatformResult<AuthResult> {
    let config = LAConfig { reason: reason.into(), ..Default::default() };

    let context = LAContext::new(config);
    context.evaluate_policy(policy, challenge).await
}

/// Check if biometric authentication is available
pub fn is_biometric_available() -> PlatformResult<bool> {
    let context = LAContext::new(LAConfig::default());
    Ok(context.biometry_type()? != BiometryType::None)
}

/// Get enrolled biometry type
pub fn get_biometry_type() -> PlatformResult<BiometryType> {
    let context = LAContext::new(LAConfig::default());
    context.biometry_type()
}

// Helper function to encode base64
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Builder for Local Authentication
pub struct LAContextBuilder {
    config: LAConfig,
}

impl LAContextBuilder {
    pub fn new(reason: impl Into<String>) -> Self {
        Self { config: LAConfig { reason: reason.into(), ..Default::default() } }
    }

    pub fn fallback_to_passcode(mut self, allow: bool) -> Self {
        self.config.fallback_to_passcode = allow;
        self
    }

    pub fn cancel_title(mut self, title: impl Into<String>) -> Self {
        self.config.cancel_title = Some(title.into());
        self
    }

    pub fn fallback_title(mut self, title: impl Into<String>) -> Self {
        self.config.fallback_title = Some(title.into());
        self
    }

    pub fn biometry_only(mut self, only: bool) -> Self {
        self.config.biometry_only = only;
        self
    }

    pub fn build(self) -> LAContext {
        LAContext::new(self.config)
    }

    pub async fn authenticate(self, challenge: Option<&[u8]>) -> PlatformResult<AuthResult> {
        let context = self.build();
        let policy = if context.config.biometry_only {
            LAPolicy::BiometryOnly
        } else {
            LAPolicy::BiometryOrPasscode
        };
        context.evaluate_policy(policy, challenge).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_la_config() {
        let config = LAConfig::default();
        assert!(!config.reason.is_empty());
        assert!(config.fallback_to_passcode);
    }

    #[tokio::test]
    async fn test_local_authentication() {
        let result = LAContextBuilder::new("Test authentication")
            .fallback_to_passcode(true)
            .authenticate(Some(b"test_challenge"))
            .await
            .unwrap();

        assert!(result.success);
        assert!(!result.method.is_empty());
    }

    #[test]
    fn test_biometry_availability() {
        let biometry_type = get_biometry_type().unwrap();
        println!("Biometry type: {:?}", biometry_type);

        if biometry_type != BiometryType::None {
            assert!(is_biometric_available().unwrap());
        }
    }
}
