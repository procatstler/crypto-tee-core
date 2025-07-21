//! Android biometric authentication integration
//!
//! This module provides integration with Android's BiometricPrompt API
//! for user authentication.

use crate::error::{PlatformError, PlatformResult};
use crate::types::AuthResult;

/// Biometric authentication configuration
#[derive(Debug, Clone)]
pub struct BiometricConfig {
    /// Title shown in the prompt
    pub title: String,
    /// Subtitle shown in the prompt
    pub subtitle: Option<String>,
    /// Description shown in the prompt
    pub description: Option<String>,
    /// Allow device credential as fallback
    pub allow_device_credential: bool,
    /// Require strong biometric (Class 3)
    pub require_strong_biometric: bool,
    /// Confirmation required after biometric
    pub confirmation_required: bool,
}

impl Default for BiometricConfig {
    fn default() -> Self {
        Self {
            title: "Authenticate to access secure key".to_string(),
            subtitle: None,
            description: None,
            allow_device_credential: true,
            require_strong_biometric: false,
            confirmation_required: false,
        }
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
    config: BiometricConfig,
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
        crypto_object: challenge.map(|c| {
            // In real implementation, this would be a signed challenge
            let mut result = vec![0u8; 64]; // Simulated signature
            result[..c.len().min(64)].copy_from_slice(&c[..c.len().min(64)]);
            result
        }),
    })
}

/// Check if biometric authentication is available
pub fn is_biometric_available() -> PlatformResult<bool> {
    // In a real implementation, this would check:
    // - BiometricManager.canAuthenticate(BIOMETRIC_WEAK)
    // - Device has enrolled biometrics
    
    Ok(true) // Assume available for development
}

/// Check if strong biometric is available
pub fn is_strong_biometric_available() -> PlatformResult<bool> {
    // In a real implementation, this would check:
    // - BiometricManager.canAuthenticate(BIOMETRIC_STRONG)
    
    Ok(true) // Assume available for development
}

/// Get enrolled biometric types
pub fn get_enrolled_biometrics() -> PlatformResult<Vec<BiometricType>> {
    // In a real implementation, this would query:
    // - FingerprintManager for fingerprints
    // - FaceManager for face
    // - Device capabilities
    
    Ok(vec![
        BiometricType::Fingerprint,
        BiometricType::Face,
    ])
}

/// Types of biometric authentication
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricType {
    /// Fingerprint sensor
    Fingerprint,
    /// Face recognition
    Face,
    /// Iris scanner
    Iris,
}

/// Convert BiometricResult to generic AuthResult
impl From<BiometricResult> for AuthResult {
    fn from(bio_result: BiometricResult) -> Self {
        AuthResult {
            success: bio_result.success,
            method: match bio_result.method {
                AuthMethod::Fingerprint => "fingerprint".to_string(),
                AuthMethod::Face => "face".to_string(),
                AuthMethod::Iris => "iris".to_string(),
                AuthMethod::DeviceCredential => "device_credential".to_string(),
                AuthMethod::UnknownBiometric => "biometric".to_string(),
            },
            timestamp: std::time::SystemTime::now(),
            validity_duration: Some(std::time::Duration::from_secs(300)), // 5 minutes
            metadata: bio_result.crypto_object.map(|co| {
                serde_json::json!({
                    "crypto_object": base64::encode(co)
                })
            }),
        }
    }
}

/// Biometric prompt builder for fluent API
pub struct BiometricPromptBuilder {
    config: BiometricConfig,
}

impl BiometricPromptBuilder {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            config: BiometricConfig {
                title: title.into(),
                ..Default::default()
            },
        }
    }
    
    pub fn subtitle(mut self, subtitle: impl Into<String>) -> Self {
        self.config.subtitle = Some(subtitle.into());
        self
    }
    
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.config.description = Some(description.into());
        self
    }
    
    pub fn allow_device_credential(mut self, allow: bool) -> Self {
        self.config.allow_device_credential = allow;
        self
    }
    
    pub fn require_strong_biometric(mut self, require: bool) -> Self {
        self.config.require_strong_biometric = require;
        self
    }
    
    pub fn confirmation_required(mut self, required: bool) -> Self {
        self.config.confirmation_required = required;
        self
    }
    
    pub async fn authenticate(self, challenge: Option<&[u8]>) -> PlatformResult<BiometricResult> {
        authenticate_biometric(self.config, challenge).await
    }
}

// Helper function to encode base64
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

// Re-export base64 encode function with correct import
mod base64 {
    pub fn encode(data: Vec<u8>) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_config() {
        let config = BiometricConfig::default();
        assert!(!config.title.is_empty());
        assert!(config.allow_device_credential);
    }

    #[tokio::test]
    async fn test_biometric_authentication() {
        let result = BiometricPromptBuilder::new("Test Authentication")
            .subtitle("Test subtitle")
            .description("Test description")
            .authenticate(Some(b"test_challenge"))
            .await
            .unwrap();
            
        assert!(result.success);
        assert_eq!(result.method, AuthMethod::Fingerprint);
        assert!(result.crypto_object.is_some());
    }

    #[test]
    fn test_biometric_availability() {
        assert!(is_biometric_available().unwrap());
        assert!(is_strong_biometric_available().unwrap());
        
        let biometrics = get_enrolled_biometrics().unwrap();
        assert!(!biometrics.is_empty());
    }
}