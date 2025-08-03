//! CryptoTEE Core API
//!
//! This crate provides the core abstraction layer (L3) for hardware-backed
//! key management and cryptographic operations across different platforms
//! and vendor TEE implementations.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::let_and_return)]
#![allow(clippy::type_complexity)]
#![allow(clippy::new_without_default)]
#![allow(clippy::format_in_format_args)]
#![allow(clippy::collapsible_if)]
#![allow(clippy::needless_borrow)]
#![allow(clippy::borrowed_box)]

pub mod audit;
pub mod backup;
pub mod core;
pub mod error;
pub mod health;
pub mod keys;
pub mod plugins;
pub mod rotation;
pub mod types;

pub use core::api::{CryptoTEE, CryptoTEEBuilder};
pub use error::{CryptoTEEError, CryptoTEEResult};
pub use health::{
    ComponentHealth, HealthConfig, HealthMonitor, HealthReport, HealthStatus, TeeHealth,
};
pub use plugins::{CryptoPlugin, PluginManager};
pub use rotation::{
    KeyRotationManager, KeyVersion, KeyVersionStatus, RotationPolicy, RotationReason,
    RotationResult, RotationStrategy,
};
pub use types::*;

// Re-export important types from lower layers
pub use crypto_tee_platform::{PlatformConfig, PlatformError};
pub use crypto_tee_vendor::{Algorithm, KeyUsage, VendorError};

/// Library version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
