//! Samsung Knox Vault Implementation
//!
//! Knox Vault provides enhanced hardware-backed security for key storage
//! and cryptographic operations on Samsung devices.

use crate::error::{VendorError, VendorResult};
use jni::{
    objects::{JObject, JValue},
    JNIEnv,
};

/// Knox Vault specific operations
pub struct KnoxVault;

impl KnoxVault {
    /// Check if Knox Vault is available
    pub fn is_available(env: &mut JNIEnv) -> VendorResult<bool> {
        // Check for Knox Vault availability
        let knox_vault_class = env
            .find_class("com/samsung/android/knox/keystore/KnoxSecurityUtils")
            .map_err(|_| VendorError::NotAvailable)?;

        let is_knox_vault_supported_method = env
            .get_static_method_id(knox_vault_class, "isKnoxVaultSupported", "()Z")
            .map_err(|_| VendorError::NotAvailable)?;

        let result = unsafe {
            env.call_static_method_unchecked(
                knox_vault_class,
                is_knox_vault_supported_method,
                &[],
                jni::signature::ReturnType::Primitive(jni::signature::Primitive::Boolean),
            )
        }
        .map_err(|_| VendorError::NotAvailable)?;

        Ok(result.z().unwrap_or(false))
    }

    /// Enable Knox Vault for a key
    pub fn enable_for_key(env: &mut JNIEnv, spec_builder: &JObject) -> VendorResult<()> {
        let builder_class = env.get_object_class(spec_builder).map_err(|e| {
            VendorError::KeyGeneration(format!("Failed to get builder class: {}", e))
        })?;

        // Set Knox Vault flag
        let set_knox_vault_method = env
            .get_method_id(
                builder_class,
                "setKnoxVault",
                "(Z)Lcom/samsung/android/knox/keystore/KnoxKeyGenParameterSpec$Builder;",
            )
            .map_err(|e| {
                VendorError::KeyGeneration(format!("Failed to find setKnoxVault: {}", e))
            })?;

        unsafe {
            env.call_method_unchecked(
                spec_builder,
                set_knox_vault_method,
                &[JValue::Bool(1).as_jni()],
                jni::signature::ReturnType::Object,
            )
        }
        .map_err(|e| VendorError::KeyGeneration(format!("Failed to enable Knox Vault: {}", e)))?;

        Ok(())
    }

    /// Set authentication requirements
    pub fn set_authentication(
        env: &mut JNIEnv,
        spec_builder: &JObject,
        require_auth: bool,
        validity_seconds: Option<u32>,
    ) -> VendorResult<()> {
        if !require_auth {
            return Ok(());
        }

        let builder_class = env.get_object_class(spec_builder).map_err(|e| {
            VendorError::KeyGeneration(format!("Failed to get builder class: {}", e))
        })?;

        // Set user authentication required
        let set_user_auth_method = env
            .get_method_id(
                builder_class,
                "setUserAuthenticationRequired",
                "(Z)Lcom/samsung/android/knox/keystore/KnoxKeyGenParameterSpec$Builder;",
            )
            .map_err(|e| {
                VendorError::KeyGeneration(format!(
                    "Failed to find setUserAuthenticationRequired: {}",
                    e
                ))
            })?;

        unsafe {
            env.call_method_unchecked(
                spec_builder,
                set_user_auth_method,
                &[JValue::Bool(1).as_jni()],
                jni::signature::ReturnType::Object,
            )
        }
        .map_err(|e| {
            VendorError::KeyGeneration(format!("Failed to set user authentication: {}", e))
        })?;

        // Set validity duration if specified
        if let Some(seconds) = validity_seconds {
            let set_validity_method = env
                .get_method_id(
                    builder_class,
                    "setUserAuthenticationValidityDurationSeconds",
                    "(I)Lcom/samsung/android/knox/keystore/KnoxKeyGenParameterSpec$Builder;",
                )
                .map_err(|e| {
                    VendorError::KeyGeneration(format!(
                        "Failed to find setUserAuthenticationValidityDurationSeconds: {}",
                        e
                    ))
                })?;

            unsafe {
                env.call_method_unchecked(
                    spec_builder,
                    set_validity_method,
                    &[JValue::Int(seconds as i32).as_jni()],
                    jni::signature::ReturnType::Object,
                )
            }
            .map_err(|e| {
                VendorError::KeyGeneration(format!("Failed to set validity duration: {}", e))
            })?;
        }

        Ok(())
    }

    /// Set biometric authentication
    pub fn set_biometric_auth(env: &mut JNIEnv, spec_builder: &JObject) -> VendorResult<()> {
        let builder_class = env.get_object_class(spec_builder).map_err(|e| {
            VendorError::KeyGeneration(format!("Failed to get builder class: {}", e))
        })?;

        // Set biometric authentication
        let set_biometric_method = env
            .get_method_id(
                builder_class,
                "setUserAuthenticationValidWhileOnBody",
                "(Z)Lcom/samsung/android/knox/keystore/KnoxKeyGenParameterSpec$Builder;",
            )
            .map_err(|e| {
                VendorError::KeyGeneration(format!(
                    "Failed to find setUserAuthenticationValidWhileOnBody: {}",
                    e
                ))
            })?;

        unsafe {
            env.call_method_unchecked(
                spec_builder,
                set_biometric_method,
                &[JValue::Bool(1).as_jni()],
                jni::signature::ReturnType::Object,
            )
        }
        .map_err(|e| VendorError::KeyGeneration(format!("Failed to set biometric auth: {}", e)))?;

        Ok(())
    }

    /// Get Knox Vault status
    pub fn get_status(env: &mut JNIEnv) -> VendorResult<KnoxVaultStatus> {
        let knox_vault_class =
            env.find_class("com/samsung/android/knox/keystore/KnoxSecurityUtils").map_err(|e| {
                VendorError::HardwareError(format!("Failed to find KnoxSecurityUtils: {}", e))
            })?;

        // Check if enabled
        let is_enabled_method =
            env.get_static_method_id(knox_vault_class, "isKnoxVaultEnabled", "()Z").map_err(
                |e| VendorError::HardwareError(format!("Failed to find isKnoxVaultEnabled: {}", e)),
            )?;

        let enabled = unsafe {
            env.call_static_method_unchecked(
                knox_vault_class,
                is_enabled_method,
                &[],
                jni::signature::ReturnType::Primitive(jni::signature::Primitive::Boolean),
            )
        }
        .map_err(|e| {
            VendorError::HardwareError(format!("Failed to check Knox Vault enabled: {}", e))
        })?;

        let is_enabled = enabled.z().unwrap_or(false);

        // Get version
        let get_version_method = env
            .get_static_method_id(knox_vault_class, "getKnoxVaultVersion", "()I")
            .map_err(|_| {
                // Method might not exist on older versions
                VendorError::NotSupported("Knox Vault version check not available".to_string())
            })?;

        let version = unsafe {
            env.call_static_method_unchecked(
                knox_vault_class,
                get_version_method,
                &[],
                jni::signature::ReturnType::Primitive(jni::signature::Primitive::Int),
            )
        }
        .map_err(|_| VendorError::NotSupported("Failed to get Knox Vault version".to_string()))?;

        let version_number = version.i().unwrap_or(0) as u32;

        Ok(KnoxVaultStatus {
            enabled: is_enabled,
            version: version_number,
            max_keys: 100, // Default max keys
            used_keys: 0,  // Would need to query actual usage
        })
    }
}

/// Knox Vault status information
#[derive(Debug, Clone)]
pub struct KnoxVaultStatus {
    /// Whether Knox Vault is enabled
    pub enabled: bool,

    /// Knox Vault version
    pub version: u32,

    /// Maximum number of keys supported
    pub max_keys: u32,

    /// Number of keys currently stored
    pub used_keys: u32,
}

/// Knox Vault security levels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KnoxVaultSecurityLevel {
    /// Standard security
    Standard,

    /// Enhanced security with StrongBox
    StrongBox,

    /// Maximum security with additional protections
    Maximum,
}

impl KnoxVaultSecurityLevel {
    /// Convert to JNI parameter
    pub fn to_jni_value(&self) -> i32 {
        match self {
            Self::Standard => 0,
            Self::StrongBox => 1,
            Self::Maximum => 2,
        }
    }
}
