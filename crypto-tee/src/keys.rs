//! Key Management Types and Utilities
//!
//! This module provides common key management types used across the backup system.

use crypto_tee_vendor::types::Algorithm;
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// Key handle structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyHandle {
    /// Unique key identifier
    pub id: String,

    /// Cryptographic algorithm
    pub algorithm: Algorithm,

    /// Vendor identifier
    pub vendor: String,

    /// Whether key is hardware-backed
    pub hardware_backed: bool,

    /// Vendor-specific data
    pub vendor_data: Option<serde_json::Value>,
}

/// Key metadata structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    /// Key identifier
    pub id: String,

    /// Cryptographic algorithm
    pub algorithm: Algorithm,

    /// Creation timestamp
    pub created_at: SystemTime,

    /// Key usage permissions
    pub usage: KeyUsage,

    /// Whether key is hardware-backed
    pub hardware_backed: bool,

    /// Whether key is exportable
    pub exportable: bool,
}

/// Key usage permissions
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KeyUsage {
    /// Can be used for signing
    pub sign: bool,

    /// Can be used for verification
    pub verify: bool,

    /// Can be used for encryption
    pub encrypt: bool,

    /// Can be used for decryption
    pub decrypt: bool,

    /// Can be used for key agreement
    pub key_agreement: bool,

    /// Can be used to derive other keys
    pub derive: bool,

    /// Can be wrapped/exported
    pub wrap: bool,

    /// Can be unwrapped/imported
    pub unwrap: bool,
}

impl KeyUsage {
    /// Create usage for signing keys
    pub fn signing() -> Self {
        Self { sign: true, verify: true, ..Default::default() }
    }

    /// Create usage for encryption keys
    pub fn encryption() -> Self {
        Self { encrypt: true, decrypt: true, ..Default::default() }
    }

    /// Create usage for key agreement
    pub fn key_agreement() -> Self {
        Self { key_agreement: true, derive: true, ..Default::default() }
    }

    /// Create usage allowing all operations
    pub fn all() -> Self {
        Self {
            sign: true,
            verify: true,
            encrypt: true,
            decrypt: true,
            key_agreement: true,
            derive: true,
            wrap: true,
            unwrap: true,
        }
    }
}
