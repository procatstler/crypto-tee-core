//! CryptoTEE Core API
//!
//! This crate provides the core abstraction layer (L3) for hardware-backed
//! key management and cryptographic operations across different platforms
//! and vendor TEE implementations.

pub mod core;
pub mod error;
pub mod plugins;
pub mod types;

pub use core::api::{CryptoTEE, CryptoTEEBuilder};
pub use error::{CryptoTEEError, CryptoTEEResult};
pub use plugins::{CryptoPlugin, PluginManager};
pub use types::*;

// Re-export important types from lower layers
pub use crypto_tee_platform::{PlatformConfig, PlatformError};
pub use crypto_tee_vendor::{Algorithm, KeyUsage, VendorError};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
