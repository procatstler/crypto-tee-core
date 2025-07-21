//! RFC 9421 HTTP Message Signatures implementation
//!
//! This crate provides the message signing layer (L4) that implements
//! RFC 9421 HTTP Message Signatures using keys from CryptoTEE.

pub mod adapter;
pub mod error;
pub mod types;

pub use adapter::Rfc9421Adapter;
pub use error::{Rfc9421Error, Rfc9421Result};
pub use types::*;

/// RFC 9421 version supported
pub const RFC9421_VERSION: &str = "draft-ietf-httpbis-message-signatures-19";
