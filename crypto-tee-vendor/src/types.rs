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
    Samsung(SamsungParams),
    Apple(AppleParams),
    Qualcomm(QualcommParams),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SamsungParams {
    pub use_knox_vault: bool,
    pub require_user_auth: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppleParams {
    pub use_secure_enclave: bool,
    pub access_control: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QualcommParams {
    pub qsee_app_id: Option<String>,
}

/// Handle to a key stored in the vendor TEE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorKeyHandle {
    /// Unique identifier for the key
    pub id: String,
    
    /// Algorithm used by this key
    pub algorithm: Algorithm,
    
    /// Vendor that created this key
    pub vendor: String,
    
    /// Whether this key is hardware-backed
    pub hardware_backed: bool,
    
    /// Opaque vendor-specific data
    #[serde(skip)]
    pub vendor_data: Option<Vec<u8>>,
}

/// Vendor capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorCapabilities {
    /// Vendor name
    pub name: String,
    
    /// Vendor version
    pub version: String,
    
    /// Supported algorithms
    pub algorithms: Vec<Algorithm>,
    
    /// Hardware security features
    pub features: VendorFeatures,
    
    /// Maximum key count
    pub max_keys: Option<u32>,
}

/// Hardware security features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorFeatures {
    pub hardware_backed: bool,
    pub secure_key_import: bool,
    pub secure_key_export: bool,
    pub attestation: bool,
    pub strongbox: bool,
    pub biometric_bound: bool,
    pub secure_deletion: bool,
}

/// Attestation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Attestation format (vendor-specific)
    pub format: String,
    
    /// Attestation data
    pub data: Vec<u8>,
    
    /// Certificate chain
    pub certificates: Vec<Vec<u8>>,
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