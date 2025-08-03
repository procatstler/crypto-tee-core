//! Stub implementation for non-Android platforms

use crate::error::{VendorError, VendorResult};
use crate::traits::VendorTEE;
use crate::types::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

/// Stub implementation of Qualcomm QSEE for non-Android platforms
pub struct QualcommStubTEE {
    #[allow(dead_code)]
    keys: Mutex<HashMap<String, StubKeyData>>,
}

#[allow(dead_code)]
struct StubKeyData {
    algorithm: Algorithm,
    created_at: std::time::SystemTime,
}

impl QualcommStubTEE {
    pub fn new() -> VendorResult<Self> {
        Ok(Self { keys: Mutex::new(HashMap::new()) })
    }
}

#[async_trait]
impl VendorTEE for QualcommStubTEE {
    async fn probe(&self) -> VendorResult<VendorCapabilities> {
        Err(VendorError::NotAvailable)
    }

    async fn generate_key(&self, _params: &KeyGenParams) -> VendorResult<VendorKeyHandle> {
        // Always fail on non-Android platforms
        Err(VendorError::NotSupported(
            "Qualcomm QSEE is only available on Android devices with Qualcomm chipsets".to_string(),
        ))
    }

    async fn delete_key(&self, _key: &VendorKeyHandle) -> VendorResult<()> {
        Err(VendorError::NotSupported(
            "Qualcomm QSEE is only available on Android devices".to_string(),
        ))
    }

    async fn sign(&self, _key: &VendorKeyHandle, _data: &[u8]) -> VendorResult<Signature> {
        Err(VendorError::NotSupported(
            "Qualcomm QSEE is only available on Android devices".to_string(),
        ))
    }

    async fn verify(
        &self,
        _key: &VendorKeyHandle,
        _data: &[u8],
        _signature: &Signature,
    ) -> VendorResult<bool> {
        Err(VendorError::NotSupported(
            "Qualcomm QSEE is only available on Android devices".to_string(),
        ))
    }

    async fn get_attestation(&self) -> VendorResult<Attestation> {
        Err(VendorError::NotSupported(
            "Qualcomm QSEE is only available on Android devices".to_string(),
        ))
    }

    async fn get_key_attestation(&self, _key: &VendorKeyHandle) -> VendorResult<Attestation> {
        Err(VendorError::NotSupported(
            "Qualcomm QSEE is only available on Android devices".to_string(),
        ))
    }

    async fn list_keys(&self) -> VendorResult<Vec<VendorKeyHandle>> {
        Err(VendorError::NotSupported(
            "Qualcomm QSEE is only available on Android devices".to_string(),
        ))
    }
}
