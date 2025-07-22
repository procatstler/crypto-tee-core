//! Vendor-specific TEE implementations for CryptoTEE
//!
//! This crate provides the lowest layer (L1) of the CryptoTEE architecture,
//! handling vendor-specific TEE implementations such as Samsung Knox,
//! Apple Secure Enclave, Qualcomm QSEE, and OP-TEE.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::await_holding_lock)]

pub mod cache;
pub mod error;
pub mod mock;
pub mod optimized;
pub mod traits;
pub mod types;

#[cfg(feature = "simulator")]
pub mod simulator;

#[cfg(any(feature = "samsung", feature = "simulator"))]
pub mod samsung;

#[cfg(any(feature = "apple", feature = "simulator"))]
pub mod apple;

#[cfg(any(feature = "qualcomm", feature = "simulator"))]
pub mod qualcomm;

pub use error::{VendorError, VendorResult};
pub use traits::VendorTEE;
pub use types::*;

// Re-export mock for testing
#[cfg(any(test, feature = "software-fallback"))]
pub use mock::MockVendor;

// Re-export simulator components
#[cfg(feature = "simulator")]
pub use simulator::{SimulationConfig, SimulatorFactory, SimulatorType, TEESimulator};
