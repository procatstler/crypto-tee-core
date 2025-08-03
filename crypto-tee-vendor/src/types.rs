//! Vendor-specific types and data structures

use serde::{Deserialize, Serialize};
use std::fmt;
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

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Rsa2048 => write!(f, "RSA-2048"),
            Algorithm::Rsa3072 => write!(f, "RSA-3072"),
            Algorithm::Rsa4096 => write!(f, "RSA-4096"),
            Algorithm::EcdsaP256 => write!(f, "ECDSA-P256"),
            Algorithm::EcdsaP384 => write!(f, "ECDSA-P384"),
            Algorithm::EcdsaP521 => write!(f, "ECDSA-P521"),
            Algorithm::Ed25519 => write!(f, "Ed25519"),
            Algorithm::Aes128 => write!(f, "AES-128"),
            Algorithm::Aes256 => write!(f, "AES-256"),
        }
    }
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
    #[cfg(all(feature = "samsung", target_os = "android"))]
    Samsung(super::samsung::KnoxParams),

    #[cfg(all(
        feature = "simulator-samsung",
        not(all(feature = "samsung", target_os = "android"))
    ))]
    Samsung(super::simulator::samsung::KnoxParams),

    /// Apple Secure Enclave specific parameters
    #[cfg(all(feature = "apple", any(target_os = "ios", target_os = "macos")))]
    Apple(super::apple::SecureEnclaveParams),

    #[cfg(all(
        feature = "simulator-apple",
        not(all(feature = "apple", any(target_os = "ios", target_os = "macos")))
    ))]
    Apple(super::simulator::apple::SecureEnclaveParams),

    /// Qualcomm QSEE specific parameters
    #[cfg(all(feature = "qualcomm", target_os = "android"))]
    Qualcomm(super::qualcomm::QSEEParams),

    #[cfg(all(
        feature = "simulator-qualcomm",
        not(all(feature = "qualcomm", target_os = "android"))
    ))]
    Qualcomm(super::simulator::qualcomm::QSEEParams),

    /// Generic parameters
    Generic { hardware_backed: bool, require_auth: bool },
}

/// Handle to a key stored in the vendor TEE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorKeyHandle {
    /// Unique identifier for the key
    pub id: String,

    /// Algorithm used by this key
    pub algorithm: Algorithm,

    /// Vendor name
    pub vendor: String,

    /// Whether this key is hardware-backed
    pub hardware_backed: bool,

    /// Vendor-specific data
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

    /// Whether keys are hardware-backed
    pub hardware_backed: bool,

    /// Whether attestation is supported
    pub attestation: bool,

    /// Maximum number of keys
    pub max_keys: u32,

    /// Vendor features
    pub features: VendorFeatures,
}

/// Vendor-specific features
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VendorFeatures {
    /// Whether keys are hardware-backed
    pub hardware_backed: bool,

    /// Whether secure key import is supported
    pub secure_key_import: bool,

    /// Whether secure key export is supported
    pub secure_key_export: bool,

    /// Whether attestation is supported
    pub attestation: bool,

    /// Whether strongbox security level is supported
    pub strongbox: bool,

    /// Whether biometric-bound keys are supported
    pub biometric_bound: bool,

    /// Whether secure deletion is supported
    pub secure_deletion: bool,
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
