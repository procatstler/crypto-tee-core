//! Vendor-specific TEE implementations for CryptoTEE
//!
//! This crate provides the lowest layer (L1) of the CryptoTEE architecture,
//! handling vendor-specific TEE implementations such as Samsung Knox,
//! Apple Secure Enclave, Qualcomm QSEE, and OP-TEE.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::await_holding_lock)]
#![allow(unexpected_cfgs)]

pub mod cache;
pub mod error;
pub mod mock;
pub mod optimized;
pub mod traits;
pub mod types;

#[cfg(feature = "simulator")]
pub mod simulator;

#[cfg(all(feature = "samsung", target_os = "android"))]
pub mod samsung;

#[cfg(all(feature = "apple", any(target_os = "ios", target_os = "macos")))]
pub mod apple;

#[cfg(all(feature = "qualcomm", target_os = "android"))]
pub mod qualcomm;

// Mock implementations for non-target platforms when features are enabled
#[cfg(all(feature = "samsung", not(target_os = "android")))]
pub mod samsung {
    pub use crate::mock::MockVendor as SamsungKnoxVendor;
}

#[cfg(all(feature = "apple", not(any(target_os = "ios", target_os = "macos"))))]
pub mod apple {
    pub use crate::mock::MockVendor as AppleSecureEnclaveVendor;
}

#[cfg(all(feature = "qualcomm", not(target_os = "android")))]
pub mod qualcomm {
    pub use crate::mock::MockVendor as QualcommQSEE;
}

pub use error::{VendorError, VendorResult};
pub use traits::VendorTEE;
pub use types::*;

// Re-export mock for testing
#[cfg(any(test, feature = "software-fallback"))]
pub use mock::MockVendor;

// Re-export simulator components
#[cfg(feature = "simulator")]
pub use simulator::{SimulationConfig, SimulatorFactory, SimulatorType, TEESimulator};
