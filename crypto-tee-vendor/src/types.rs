//! Vendor-specific types and data structures

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Supported cryptographic algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Algorithm {
    /// RSA with specified key size
    Rsa2048,
    Rsa3072,
    Rsa4096,
    
    /// Elliptic Curve algorithms
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Ed25519,
    
    /// Symmetric algorithms
    Aes128,
    Aes256,
}

/// Key generation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyGenParams {
    /// Algorithm to use
    pub algorithm: Algorithm,
    
    /// Whether the key should be stored in secure hardware
    pub hardware_backed: bool,
    
    /// Whether the key can be exported
    pub exportable: bool,
    
    /// Key usage flags
    pub usage: KeyUsage,
    
    /// Additional vendor-specific parameters
    pub vendor_params: Option<VendorParams>,
}

/// Key usage flags
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct KeyUsage {
    pub sign: bool,
    pub verify: bool,
    pub encrypt: bool,
    pub decrypt: bool,
    pub wrap: bool,
    pub unwrap: bool,
}

impl Default for KeyUsage {
    fn default() -> Self {
        Self {
            sign: true,
            verify: true,
            encrypt: false,
            decrypt: false,
            wrap: false,
            unwrap: false,
        }
    }
}

/// Vendor-specific parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VendorParams {
    /// Samsung Knox specific parameters
    #[cfg(feature = "samsung")]
    Samsung(super::samsung::KnoxParams),
    
    /// Apple Secure Enclave specific parameters
    #[cfg(feature = "apple")]
    Apple(super::apple::SecureEnclaveParams),
    
    /// Qualcomm QSEE specific parameters
    #[cfg(feature = "qualcomm")]
    Qualcomm(super::qualcomm::QSEEParams),
    
    /// Generic parameters
    Generic {
        hardware_backed: bool,
        require_auth: bool,
    },
}

/// Handle to a key stored in the vendor TEE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorKeyHandle {
    /// Unique identifier for the key
    pub id: String,
    
    /// Algorithm used by this key
    pub algorithm: Algorithm,
    
    /// Whether this key is hardware-backed
    pub hardware_backed: bool,
    
    /// Attestation data (if available)
    pub attestation: Option<Attestation>,
}

/// Vendor capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorCapabilities {
    /// Supported algorithms
    pub algorithms: Vec<Algorithm>,
    
    /// Whether keys are hardware-backed
    pub hardware_backed: bool,
    
    /// Whether attestation is supported
    pub attestation: bool,
    
    /// Maximum number of keys
    pub max_keys: u32,
}

/// Attestation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Attestation format
    pub format: AttestationFormat,
    
    /// Attestation data
    pub data: Vec<u8>,
    
    /// Certificate chain
    pub certificates: Vec<Vec<u8>>,
}

/// Attestation format types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttestationFormat {
    /// Android Key Attestation
    AndroidKey,
    
    /// Apple DeviceCheck
    AppleDeviceCheck,
    
    /// FIDO U2F
    FidoU2F,
    
    /// Custom format
    Custom(String),
}

/// Signature format
#[derive(Debug, Clone)]
pub struct Signature {
    /// Algorithm used
    pub algorithm: Algorithm,
    
    /// Signature bytes
    pub data: Vec<u8>,
}

impl Signature {
    /// Get the signature data
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }
    
    /// Convert to bytes, consuming the signature
    pub fn into_bytes(mut self) -> Vec<u8> {
        let data = std::mem::take(&mut self.data);
        std::mem::forget(self); // Prevent Drop from running
        data
    }
}

impl Zeroize for Signature {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for Signature {
    fn drop(&mut self) {
        self.zeroize();
    }
}