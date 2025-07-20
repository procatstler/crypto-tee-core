//! Core vendor trait definitions

use async_trait::async_trait;

use crate::{
    error::VendorResult,
    types::{Attestation, KeyGenParams, Signature, VendorCapabilities, VendorKeyHandle},
};

/// Core trait for vendor-specific TEE implementations
#[async_trait]
pub trait VendorTEE: Send + Sync {
    /// Probe the vendor TEE and return its capabilities
    async fn probe(&self) -> VendorResult<VendorCapabilities>;

    /// Check if the vendor TEE is available on this device
    async fn is_available(&self) -> bool {
        self.probe().await.is_ok()
    }

    /// Generate a new key in the vendor TEE
    async fn generate_key(&self, params: &KeyGenParams) -> VendorResult<VendorKeyHandle>;

    /// Delete a key from the vendor TEE
    async fn delete_key(&self, key: &VendorKeyHandle) -> VendorResult<()>;

    /// Sign data using a key in the vendor TEE
    async fn sign(&self, key: &VendorKeyHandle, data: &[u8]) -> VendorResult<Signature>;

    /// Verify a signature using a key in the vendor TEE
    async fn verify(
        &self,
        key: &VendorKeyHandle,
        data: &[u8],
        signature: &Signature,
    ) -> VendorResult<bool>;

    /// Get attestation for the vendor TEE
    async fn get_attestation(&self) -> VendorResult<Attestation>;

    /// Get attestation for a specific key
    async fn get_key_attestation(&self, key: &VendorKeyHandle) -> VendorResult<Attestation>;

    /// List all key handles managed by this vendor
    async fn list_keys(&self) -> VendorResult<Vec<VendorKeyHandle>>;

    /// Import a key into the vendor TEE (if supported)
    async fn import_key(
        &self,
        _key_data: &[u8],
        _params: &KeyGenParams,
    ) -> VendorResult<VendorKeyHandle> {
        Err(crate::error::VendorError::NotSupported(
            "Key import not supported by this vendor".to_string(),
        ))
    }

    /// Export a key from the vendor TEE (if supported and key is exportable)
    async fn export_key(&self, _key: &VendorKeyHandle) -> VendorResult<Vec<u8>> {
        Err(crate::error::VendorError::NotSupported(
            "Key export not supported by this vendor".to_string(),
        ))
    }
}