//! Platform-specific error types

use thiserror::Error;

pub type PlatformResult<T> = Result<T, PlatformError>;

#[derive(Error, Debug)]
pub enum PlatformError {
    #[error("Platform not supported: {0}")]
    NotSupported(String),

    #[error("Platform feature not available: {0}")]
    FeatureNotAvailable(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Authentication required: {0}")]
    AuthenticationRequired(String),

    #[error("Platform API error: {0}")]
    ApiError(String),

    #[error("FFI error: {0}")]
    FfiError(String),

    #[error("Vendor error: {0}")]
    VendorError(#[from] crypto_tee_vendor::VendorError),

    #[error("Platform configuration error: {0}")]
    ConfigError(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
