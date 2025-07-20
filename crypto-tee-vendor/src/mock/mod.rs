//! Mock vendor implementation for testing and software fallback

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ring::signature::{self, KeyPair};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::{debug, info};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    error::{VendorError, VendorResult},
    traits::VendorTEE,
    types::*,
};

/// Mock vendor implementation using software crypto
pub struct MockVendor {
    name: String,
    keys: Arc<Mutex<HashMap<String, MockKey>>>,
    capabilities: VendorCapabilities,
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct MockKey {
    #[zeroize(skip)]
    handle: VendorKeyHandle,
    private_key: Vec<u8>,
    public_key: Option<Vec<u8>>,
}

impl Default for MockVendor {
    fn default() -> Self {
        Self::new("mock-vendor")
    }
}

impl MockVendor {
    /// Perform constant-time signature verification to prevent timing attacks
    fn constant_time_verify<T: AsRef<[u8]>>(
        public_key: &signature::UnparsedPublicKey<T>,
        data: &[u8],
        signature: &[u8],
    ) -> bool {
        // Perform the actual verification
        let actual_result = public_key.verify(data, signature).is_ok();
        
        // Always perform a dummy verification to ensure constant timing
        let dummy_signature = vec![0u8; signature.len()];
        let _dummy_result = public_key.verify(data, &dummy_signature);
        
        // Use constant-time comparison for the final result
        let success_byte = if actual_result { 1u8 } else { 0u8 };
        let expected_byte = 1u8;
        
        // This ensures constant-time comparison regardless of the result
        success_byte.ct_eq(&expected_byte).into()
    }

    pub fn new(name: &str) -> Self {
        let capabilities = VendorCapabilities {
            name: format!("Mock Vendor: {}", name),
            version: "1.0.0".to_string(),
            algorithms: vec![
                Algorithm::Rsa2048,
                Algorithm::Rsa3072,
                Algorithm::Rsa4096,
                Algorithm::EcdsaP256,
                Algorithm::EcdsaP384,
                Algorithm::Ed25519,
            ],
            hardware_backed: false,
            attestation: true,
            max_keys: 1000,
            features: VendorFeatures {
                hardware_backed: false,
                secure_key_import: true,
                secure_key_export: true,
                attestation: true,
                strongbox: false,
                biometric_bound: false,
                secure_deletion: false,
            },
        };

        Self {
            name: name.to_string(),
            keys: Arc::new(Mutex::new(HashMap::new())),
            capabilities,
        }
    }
}

#[async_trait]
impl VendorTEE for MockVendor {
    async fn probe(&self) -> VendorResult<VendorCapabilities> {
        info!("Probing mock vendor: {}", self.name);
        Ok(self.capabilities.clone())
    }

    async fn generate_key(&self, params: &KeyGenParams) -> VendorResult<VendorKeyHandle> {
        debug!("Generating key with params: {:?}", params);

        let key_id = format!("mock-key-{}", uuid::Uuid::new_v4());
        
        let (private_key, public_key) = match params.algorithm {
            Algorithm::Ed25519 => {
                let doc = signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                    .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                let key_pair = signature::Ed25519KeyPair::from_pkcs8(doc.as_ref())
                    .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                (doc.as_ref().to_vec(), Some(key_pair.public_key().as_ref().to_vec()))
            }
            Algorithm::EcdsaP256 => {
                let rng = ring::rand::SystemRandom::new();
                let doc = signature::EcdsaKeyPair::generate_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    doc.as_ref(),
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                (doc.as_ref().to_vec(), Some(key_pair.public_key().as_ref().to_vec()))
            }
            _ => {
                return Err(VendorError::NotSupported(format!(
                    "Algorithm {:?} not yet implemented in mock",
                    params.algorithm
                )))
            }
        };

        let handle = VendorKeyHandle {
            id: key_id.clone(),
            algorithm: params.algorithm,
            hardware_backed: false,
            attestation: None,
        };

        let mock_key = MockKey {
            handle: handle.clone(),
            private_key,
            public_key,
        };

        self.keys.lock().await.insert(key_id, mock_key);

        info!("Generated mock key: {}", handle.id);
        Ok(handle)
    }

    async fn delete_key(&self, key: &VendorKeyHandle) -> VendorResult<()> {
        debug!("Deleting key: {}", key.id);
        
        match self.keys.lock().await.remove(&key.id) {
            Some(_) => {
                info!("Deleted mock key: {}", key.id);
                Ok(())
            }
            None => Err(VendorError::KeyNotFound(key.id.clone())),
        }
    }

    async fn sign(&self, key: &VendorKeyHandle, data: &[u8]) -> VendorResult<Signature> {
        debug!("Signing data with key: {}", key.id);

        let keys = self.keys.lock().await;
        let mock_key = keys
            .get(&key.id)
            .ok_or_else(|| VendorError::KeyNotFound(key.id.clone()))?;

        let signature_data = match key.algorithm {
            Algorithm::Ed25519 => {
                let key_pair = signature::Ed25519KeyPair::from_pkcs8(&mock_key.private_key)
                    .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                key_pair.sign(data).as_ref().to_vec()
            }
            Algorithm::EcdsaP256 => {
                let rng = ring::rand::SystemRandom::new();
                let key_pair = signature::EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &mock_key.private_key,
                    &rng,
                )
                .map_err(|e| VendorError::CryptoError(e.to_string()))?;
                key_pair.sign(&rng, data)
                    .map_err(|e| VendorError::CryptoError(e.to_string()))?
                    .as_ref()
                    .to_vec()
            }
            _ => {
                return Err(VendorError::NotSupported(format!(
                    "Algorithm {:?} not yet implemented for signing",
                    key.algorithm
                )))
            }
        };

        Ok(Signature {
            algorithm: key.algorithm,
            data: signature_data,
        })
    }

    async fn verify(
        &self,
        key: &VendorKeyHandle,
        data: &[u8],
        signature: &Signature,
    ) -> VendorResult<bool> {
        debug!("Verifying signature with key: {}", key.id);

        let keys = self.keys.lock().await;
        let mock_key = keys
            .get(&key.id)
            .ok_or_else(|| VendorError::KeyNotFound(key.id.clone()))?;

        let public_key = mock_key.public_key.as_ref()
            .ok_or_else(|| VendorError::CryptoError("No public key available".to_string()))?;

        // Perform verification with timing attack protection
        let result = match key.algorithm {
            Algorithm::Ed25519 => {
                let peer_public_key = signature::UnparsedPublicKey::new(
                    &signature::ED25519,
                    public_key,
                );
                Self::constant_time_verify(&peer_public_key, data, &signature.data)
            }
            Algorithm::EcdsaP256 => {
                let peer_public_key = signature::UnparsedPublicKey::new(
                    &signature::ECDSA_P256_SHA256_ASN1,
                    public_key,
                );
                Self::constant_time_verify(&peer_public_key, data, &signature.data)
            }
            _ => {
                return Err(VendorError::NotSupported(format!(
                    "Algorithm {:?} not yet implemented for verification",
                    key.algorithm
                )))
            }
        };

        Ok(result)
    }

    async fn get_attestation(&self) -> VendorResult<Attestation> {
        info!("Getting mock attestation");
        
        Ok(Attestation {
            format: AttestationFormat::Custom("mock-attestation".to_string()),
            data: b"mock-attestation-data".to_vec(),
            certificates: vec![b"mock-certificate".to_vec()],
        })
    }

    async fn get_key_attestation(&self, key: &VendorKeyHandle) -> VendorResult<Attestation> {
        debug!("Getting attestation for key: {}", key.id);

        // Verify key exists
        if !self.keys.lock().await.contains_key(&key.id) {
            return Err(VendorError::KeyNotFound(key.id.clone()));
        }

        Ok(Attestation {
            format: AttestationFormat::Custom("mock-key-attestation".to_string()),
            data: format!("mock-attestation-for-{}", key.id).into_bytes(),
            certificates: vec![b"mock-key-certificate".to_vec()],
        })
    }

    async fn list_keys(&self) -> VendorResult<Vec<VendorKeyHandle>> {
        let keys = self.keys.lock().await;
        Ok(keys.values().map(|k| k.handle.clone()).collect())
    }

    async fn import_key(
        &self,
        key_data: &[u8],
        params: &KeyGenParams,
    ) -> VendorResult<VendorKeyHandle> {
        debug!("Importing key with params: {:?}", params);

        let key_id = format!("mock-imported-{}", uuid::Uuid::new_v4());

        // Basic validation
        if key_data.is_empty() {
            return Err(VendorError::InvalidKeyParams("Empty key data".to_string()));
        }

        let handle = VendorKeyHandle {
            id: key_id.clone(),
            algorithm: params.algorithm,
            hardware_backed: false,
            attestation: None,
        };

        let mock_key = MockKey {
            handle: handle.clone(),
            private_key: key_data.to_vec(),
            public_key: None, // Would need to extract from private key
        };

        self.keys.lock().await.insert(key_id, mock_key);

        info!("Imported mock key: {}", handle.id);
        Ok(handle)
    }

    async fn export_key(&self, key: &VendorKeyHandle) -> VendorResult<Vec<u8>> {
        debug!("Exporting key: {}", key.id);

        let keys = self.keys.lock().await;
        let mock_key = keys
            .get(&key.id)
            .ok_or_else(|| VendorError::KeyNotFound(key.id.clone()))?;

        Ok(mock_key.private_key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_vendor_probe() {
        let vendor = MockVendor::default();
        let caps = vendor.probe().await.unwrap();
        assert!(!caps.algorithms.is_empty());
        assert!(!caps.hardware_backed);
        assert!(caps.attestation);
    }

    #[tokio::test]
    async fn test_key_lifecycle() {
        let vendor = MockVendor::default();
        
        // Generate key
        let params = KeyGenParams {
            algorithm: Algorithm::Ed25519,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            vendor_params: None,
        };
        
        let key = vendor.generate_key(&params).await.unwrap();
        assert_eq!(key.algorithm, Algorithm::Ed25519);
        
        // List keys
        let keys = vendor.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        
        // Delete key
        vendor.delete_key(&key).await.unwrap();
        
        // Verify deleted
        let keys = vendor.list_keys().await.unwrap();
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_sign_verify() {
        let vendor = MockVendor::default();
        
        let params = KeyGenParams {
            algorithm: Algorithm::Ed25519,
            hardware_backed: false,
            exportable: true,
            usage: KeyUsage::default(),
            vendor_params: None,
        };
        
        let key = vendor.generate_key(&params).await.unwrap();
        let data = b"test message";
        
        // Sign
        let signature = vendor.sign(&key, data).await.unwrap();
        
        // Verify
        let valid = vendor.verify(&key, data, &signature).await.unwrap();
        assert!(valid);
        
        // Verify with wrong data
        let invalid = vendor.verify(&key, b"wrong message", &signature).await.unwrap();
        assert!(!invalid);
    }
}