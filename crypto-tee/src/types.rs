//! Core types and data structures

use crypto_tee_platform::traits::PlatformKeyHandle;
use crypto_tee_vendor::{Algorithm, KeyUsage};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Options for key generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyOptions {
    /// Cryptographic algorithm
    pub algorithm: Algorithm,

    /// Key usage permissions
    pub usage: KeyUsage,

    /// Whether to use hardware-backed storage if available
    pub hardware_backed: bool,

    /// Whether the key can be exported
    pub exportable: bool,

    /// Whether user authentication is required for key use
    pub require_auth: bool,

    /// Key expiration time
    pub expires_at: Option<SystemTime>,

    /// Additional metadata
    pub metadata: Option<serde_json::Value>,
}

impl Default for KeyOptions {
    fn default() -> Self {
        Self {
            algorithm: Algorithm::Ed25519,
            usage: KeyUsage::default(),
            hardware_backed: true,
            exportable: false,
            require_auth: false,
            expires_at: None,
            metadata: None,
        }
    }
}

/// Options for signing operations
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SignOptions {
    /// Hash algorithm to use before signing
    pub hash_algorithm: Option<HashAlgorithm>,

    /// Padding scheme for RSA
    pub padding: Option<PaddingScheme>,

    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
}

/// Supported hash algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    SHA256,
    SHA384,
    SHA512,
    SHA3_256,
    SHA3_512,
}

/// Padding schemes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PaddingScheme {
    PKCS1v15,
    PSS,
    OAEP,
}

/// Handle to a key managed by CryptoTEE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyHandle {
    /// Unique key alias
    pub alias: String,

    /// Platform-specific handle
    pub platform_handle: PlatformKeyHandle,

    /// Key metadata
    pub metadata: KeyMetadata,
}

/// Key metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key algorithm
    pub algorithm: Algorithm,

    /// Key creation time
    pub created_at: SystemTime,

    /// Last used time
    pub last_used: Option<SystemTime>,

    /// Usage count
    pub usage_count: u64,

    /// Whether the key is hardware-backed
    pub hardware_backed: bool,

    /// Custom metadata
    pub custom: Option<serde_json::Value>,
}

/// Key information for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Key alias
    pub alias: String,

    /// Algorithm
    pub algorithm: Algorithm,

    /// Creation time
    pub created_at: SystemTime,

    /// Whether hardware-backed
    pub hardware_backed: bool,

    /// Whether authentication is required
    pub requires_auth: bool,
}

/// Operation context for plugins
pub struct OperationContext {
    /// Operation name
    pub operation: String,

    /// Operation parameters
    pub params: serde_json::Value,

    /// Platform context
    pub platform: Box<dyn crypto_tee_platform::PlatformTEE>,

    /// Vendor context
    pub vendor: Box<dyn crypto_tee_vendor::VendorTEE>,
}
