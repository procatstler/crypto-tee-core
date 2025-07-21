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

    #[error("Key generation failed: {0}")]
    KeyGeneration(String),

    #[error("Signing operation failed: {0}")]
    SigningError(String),

    #[error("Key corrupted: {0}")]
    KeyCorrupted(String),

    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Configuration error: {0}")]
    ConfigurationError(String),

    #[error("Not initialized: {0}")]
    NotInitialized(String),

    #[error("Security violation: {0}")]
    SecurityViolation(String),

    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    #[error("Verification error: {0}")]
    VerificationError(String),

    #[error("Initialization error: {0}")]
    InitializationError(String),

    #[error("Key deletion failed: {0}")]
    KeyDeletion(String),

    #[error("Key listing failed: {0}")]
    KeyListing(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
