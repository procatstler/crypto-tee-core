//! RFC 9421 error types

use thiserror::Error;

pub type Rfc9421Result<T> = Result<T, Rfc9421Error>;

#[derive(Error, Debug)]
pub enum Rfc9421Error {
    #[error("Invalid signature parameters: {0}")]
    InvalidParameters(String),

    #[error("Canonicalization error: {0}")]
    CanonicalizationError(String),

    #[error("Signature verification failed")]
    VerificationFailed,

    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    #[error("Invalid HTTP message: {0}")]
    InvalidMessage(String),

    #[error("CryptoTEE error: {0}")]
    CryptoTEEError(#[from] crypto_tee::CryptoTEEError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}