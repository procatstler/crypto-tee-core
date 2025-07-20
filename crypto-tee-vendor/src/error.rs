//! Vendor-specific error types

use thiserror::Error;

pub type VendorResult<T> = Result<T, VendorError>;

#[derive(Error, Debug)]
pub enum VendorError {
    #[error("TEE not available on this device")]
    NotAvailable,

    #[error("TEE feature not supported: {0}")]
    NotSupported(String),

    #[error("Access denied to TEE: {0}")]
    AccessDenied(String),

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key parameters: {0}")]
    InvalidKeyParams(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("TEE communication error: {0}")]
    CommunicationError(String),

    #[error("Attestation error: {0}")]
    AttestationError(String),

    #[error("Hardware security module error: {0}")]
    HardwareError(String),

    #[error("Internal vendor error: {0}")]
    InternalError(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}