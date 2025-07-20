//! Vendor-specific TEE implementations for CryptoTEE
//! 
//! This crate provides the lowest layer (L1) of the CryptoTEE architecture,
//! handling vendor-specific TEE implementations such as Samsung Knox,
//! Apple Secure Enclave, Qualcomm QSEE, and OP-TEE.

pub mod error;
pub mod types;
pub mod traits;
pub mod mock;

#[cfg(feature = "simulator")]
pub mod simulator;

#[cfg(feature = "samsung")]
pub mod samsung;

#[cfg(feature = "apple")]
pub mod apple;

#[cfg(feature = "qualcomm")]
pub mod qualcomm;

pub use error::{VendorError, VendorResult};
pub use types::*;
pub use traits::VendorTEE;

// Re-export mock for testing
#[cfg(any(test, feature = "software-fallback"))]
pub use mock::MockVendor;

// Re-export simulator components
#[cfg(feature = "simulator")]
pub use simulator::{TEESimulator, SimulatorFactory, SimulationConfig, SimulatorType};