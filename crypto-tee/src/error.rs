//! Core error types

use thiserror::Error;

pub type CryptoTEEResult<T> = Result<T, CryptoTEEError>;

#[derive(Error, Debug)]
pub enum CryptoTEEError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Invalid key alias: {0}")]
    InvalidKeyAlias(String),

    #[error("Operation not supported: {0}")]
    NotSupported(String),

    #[error("Plugin error: {0}")]
    PluginError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Initialization error: {0}")]
    InitError(String),

    #[error("IO error: {0}")]
    IoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Platform error: {0}")]
    PlatformError(#[from] crypto_tee_platform::PlatformError),

    #[error("Vendor error: {0}")]
    VendorError(#[from] crypto_tee_vendor::VendorError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
