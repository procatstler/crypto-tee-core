//! Samsung Knox TEE Implementation
//!
//! This module provides the actual implementation of Samsung Knox TEE
//! for Android devices.

use super::jni_bridge::{get_jni_context, KnoxJniContext};
use super::KnoxParams;
use crate::{
    error::{VendorError, VendorResult},
    traits::VendorTEE,
    types::*,
};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Samsung Knox TEE implementation
pub struct SamsungKnoxTEE {
    jni_context: Arc<KnoxJniContext>,
    key_handles: Arc<Mutex<HashMap<String, KnoxKeyInfo>>>,
}

/// Information about a Knox key
#[derive(Debug, Clone)]
struct KnoxKeyInfo {
    alias: String,
    algorithm: Algorithm,
    created_at: std::time::SystemTime,
    uses_knox_vault: bool,
    requires_auth: bool,
}

impl SamsungKnoxTEE {
    /// Create new Samsung Knox TEE instance
    pub fn new() -> VendorResult<Self> {
        let jvm = get_jni_context()
            .ok_or_else(|| VendorError::InitializationError("JNI not initialized".to_string()))?;

        let jni_context = Arc::new(KnoxJniContext::new(jvm));

        Ok(Self { jni_context, key_handles: Arc::new(Mutex::new(HashMap::new())) })
    }

    /// Convert algorithm to Knox algorithm string
    fn algorithm_to_knox_string(algorithm: Algorithm) -> VendorResult<&'static str> {
        match algorithm {
            Algorithm::Ed25519 => Ok("Ed25519"),
            Algorithm::EcdsaP256 => Ok("EC"),
            Algorithm::EcdsaP384 => Ok("EC"),
            Algorithm::EcdsaP521 => Ok("EC"),
            Algorithm::Rsa2048 => Ok("RSA"),
            Algorithm::Rsa3072 => Ok("RSA"),
            Algorithm::Rsa4096 => Ok("RSA"),
            Algorithm::Aes128 => Ok("AES"),
            Algorithm::Aes256 => Ok("AES"),
        }
    }

    /// Get key size for algorithm
    fn get_key_size(algorithm: Algorithm) -> i32 {
        match algorithm {
            Algorithm::Ed25519 => 256,
            Algorithm::EcdsaP256 => 256,
            Algorithm::EcdsaP384 => 384,
            Algorithm::EcdsaP521 => 521,
            Algorithm::Rsa2048 => 2048,
            Algorithm::Rsa3072 => 3072,
            Algorithm::Rsa4096 => 4096,
            Algorithm::Aes128 => 128,
            Algorithm::Aes256 => 256,
        }
    }

    /// Generate unique key alias
    fn generate_key_alias(&self) -> String {
        format!("knox_key_{}", uuid::Uuid::new_v4())
    }
}

/// Check if Knox is available on this device
pub fn is_knox_available() -> VendorResult<bool> {
    let jvm = get_jni_context().ok_or_else(|| VendorError::NotAvailable)?;

    let mut env = jvm
        .attach_current_thread()
        .map_err(|e| VendorError::InitializationError(format!("Failed to attach thread: {}", e)))?;

    let context = KnoxJniContext::new(jvm);
    context.is_knox_available(&mut env)
}

#[async_trait]
impl VendorTEE for SamsungKnoxTEE {
    async fn probe(&self) -> VendorResult<VendorCapabilities> {
        let jvm = self.jni_context.jvm.clone();
        let mut env = jvm.attach_current_thread().map_err(|e| {
            VendorError::InitializationError(format!("Failed to attach thread: {}", e))
        })?;

        // Check Knox availability
        if !self.jni_context.is_knox_available(&mut env)? {
            return Err(VendorError::NotAvailable);
        }

        Ok(VendorCapabilities {
            name: "Samsung Knox TEE".to_string(),
            version: "3.9".to_string(), // Knox 3.9
            algorithms: vec![
                Algorithm::Ed25519,
                Algorithm::EcdsaP256,
                Algorithm::EcdsaP384,
                Algorithm::Rsa2048,
                Algorithm::Rsa3072,
                Algorithm::Rsa4096,
            ],
            hardware_backed: true,
            attestation: true,
            features: VendorFeatures {
                hardware_backed: true,
                secure_key_import: true,
                secure_key_export: false,
                attestation: true,
                strongbox: true, // Knox Vault
                biometric_bound: true,
                secure_deletion: true,
            },
            max_keys: 100,
        })
    }

    async fn generate_key(&self, params: &KeyGenParams) -> VendorResult<VendorKeyHandle> {
        let jvm = self.jni_context.jvm.clone();
        let mut env = jvm
            .attach_current_thread()
            .map_err(|e| VendorError::KeyGeneration(format!("Failed to attach thread: {}", e)))?;

        // Extract Knox parameters
        let knox_params = if let Some(VendorParams::Samsung(knox_params)) = &params.vendor_params {
            knox_params.clone()
        } else {
            KnoxParams::default()
        };

        // Generate key alias
        let alias = self.generate_key_alias();

        // Convert algorithm
        let knox_algorithm = Self::algorithm_to_knox_string(params.algorithm)?;
        let key_size = Self::get_key_size(params.algorithm);

        // Generate key using JNI
        self.jni_context.generate_key(
            &mut env,
            &alias,
            knox_algorithm,
            key_size,
            knox_params.use_knox_vault,
        )?;

        // Store key info
        let key_info = KnoxKeyInfo {
            alias: alias.clone(),
            algorithm: params.algorithm,
            created_at: std::time::SystemTime::now(),
            uses_knox_vault: knox_params.use_knox_vault,
            requires_auth: knox_params.require_user_auth,
        };

        self.key_handles.lock().unwrap().insert(alias.clone(), key_info);

        Ok(VendorKeyHandle {
            id: alias,
            algorithm: params.algorithm,
            vendor: "Samsung Knox".to_string(),
            hardware_backed: params.hardware_backed,
            vendor_data: None,
        })
    }

    async fn import_key(
        &self,
        _key_data: &[u8],
        _params: &KeyGenParams,
    ) -> VendorResult<VendorKeyHandle> {
        // Knox supports key import but with restrictions
        // For now, return not supported
        Err(VendorError::NotSupported("Key import not yet implemented for Knox".to_string()))
    }

    async fn sign(&self, key: &VendorKeyHandle, data: &[u8]) -> VendorResult<Signature> {
        let jvm = self.jni_context.jvm.clone();
        let mut env = jvm
            .attach_current_thread()
            .map_err(|e| VendorError::SigningError(format!("Failed to attach thread: {}", e)))?;

        // Check if key exists
        let key_handles = self.key_handles.lock().unwrap();
        let _key_info = key_handles
            .get(&key.id)
            .ok_or_else(|| VendorError::KeyNotFound(format!("Key not found: {}", key.id)))?;

        // Sign data using JNI
        let signature_bytes = self.jni_context.sign_data(&mut env, &key.id, data)?;

        Ok(Signature { algorithm: key.algorithm, data: signature_bytes })
    }

    async fn verify(
        &self,
        _key: &VendorKeyHandle,
        _data: &[u8],
        _signature: &Signature,
    ) -> VendorResult<bool> {
        // Verification can be done using public key
        // For now, return not implemented
        Err(VendorError::NotSupported("Verification not yet implemented for Knox".to_string()))
    }

    async fn delete_key(&self, key: &VendorKeyHandle) -> VendorResult<()> {
        // Remove from internal tracking
        self.key_handles.lock().unwrap().remove(&key.id);

        // Knox keys in Android KeyStore are automatically managed
        // Deletion happens through KeyStore API
        Ok(())
    }

    async fn get_attestation(&self) -> VendorResult<Attestation> {
        // Knox device attestation
        Ok(Attestation {
            format: AttestationFormat::Custom("knox_device_attestation".to_string()),
            data: vec![],         // Would contain actual attestation data
            certificates: vec![], // Would contain certificate chain
        })
    }

    async fn get_key_attestation(&self, key: &VendorKeyHandle) -> VendorResult<Attestation> {
        let jvm = self.jni_context.jvm.clone();
        let mut env = jvm.attach_current_thread().map_err(|e| {
            VendorError::AttestationFailed(format!("Failed to attach thread: {}", e))
        })?;

        // Get attestation certificate chain
        let cert_chain = self.jni_context.get_attestation(&mut env, &key.id)?;

        Ok(Attestation {
            format: AttestationFormat::AndroidKey,
            data: vec![], // Attestation extension data would be extracted from certificates
            certificates: cert_chain,
        })
    }

    async fn list_keys(&self) -> VendorResult<Vec<VendorKeyHandle>> {
        let key_handles = self.key_handles.lock().unwrap();

        let handles: Vec<VendorKeyHandle> = key_handles
            .values()
            .map(|info| VendorKeyHandle {
                id: info.alias.clone(),
                algorithm: info.algorithm,
                vendor: "Samsung Knox".to_string(),
                hardware_backed: true,
                vendor_data: None,
            })
            .collect();

        Ok(handles)
    }
}
