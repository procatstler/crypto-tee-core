//! Stub implementation of Apple Secure Enclave for non-Apple platforms
//! 
//! This provides a placeholder implementation that returns appropriate errors
//! when Secure Enclave is not available on the platform.

use async_trait::async_trait;
use crate::{
    error::{VendorError, VendorResult},
    traits::VendorTEE,
    types::*,
};

/// Stub implementation for Apple Secure Enclave
pub struct AppleSecureEnclaveStub;

impl AppleSecureEnclaveStub {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl VendorTEE for AppleSecureEnclaveStub {
    async fn probe(&self) -> VendorResult<VendorCapabilities> {
        Err(VendorError::NotAvailable)
    }

    async fn generate_key(&self, _params: &KeyGenParams) -> VendorResult<VendorKeyHandle> {
        Err(VendorError::NotAvailable)
    }

    async fn import_key(&self, _key_data: &[u8], _params: &KeyGenParams) -> VendorResult<VendorKeyHandle> {
        Err(VendorError::NotAvailable)
    }

    async fn delete_key(&self, _key: &VendorKeyHandle) -> VendorResult<()> {
        Err(VendorError::NotAvailable)
    }

    async fn sign(&self, _key: &VendorKeyHandle, _data: &[u8]) -> VendorResult<Signature> {
        Err(VendorError::NotAvailable)
    }

    async fn verify(
        &self,
        _key: &VendorKeyHandle,
        _data: &[u8],
        _signature: &Signature,
    ) -> VendorResult<bool> {
        Err(VendorError::NotAvailable)
    }

    async fn get_attestation(&self) -> VendorResult<Attestation> {
        Err(VendorError::NotAvailable)
    }

    async fn get_key_attestation(&self, _key: &VendorKeyHandle) -> VendorResult<Attestation> {
        Err(VendorError::NotAvailable)
    }

    async fn list_keys(&self) -> VendorResult<Vec<VendorKeyHandle>> {
        Err(VendorError::NotAvailable)
    }
}