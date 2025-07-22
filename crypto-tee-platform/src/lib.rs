//! Platform-specific adapters for CryptoTEE
//!
//! This crate provides the platform layer (L2) that bridges between
//! the core CryptoTEE API and platform-specific security APIs.

#![allow(clippy::uninlined_format_args)]
#![allow(clippy::new_without_default)]
#![allow(unused_imports)]

pub mod error;
pub mod fallback;
pub mod traits;
pub mod types;

#[cfg(test)]
mod tests;

#[cfg(feature = "android")]
pub mod android;

#[cfg(feature = "ios")]
pub mod ios;

#[cfg(feature = "linux")]
pub mod linux;

pub use error::{PlatformError, PlatformResult};
pub use traits::PlatformTEE;
pub use types::*;

// Re-export fallback for testing
pub use fallback::FallbackPlatform;

/// Detect and load the appropriate platform implementation
pub fn load_platform() -> Box<dyn PlatformTEE> {
    #[cfg(target_os = "android")]
    {
        Box::new(android::AndroidPlatform::new())
    }

    #[cfg(target_os = "ios")]
    {
        Box::new(ios::IOSPlatform::new())
    }

    #[cfg(target_os = "linux")]
    {
        Box::new(linux::LinuxPlatform::new())
    }

    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "linux")))]
    {
        Box::new(fallback::FallbackPlatform::new())
    }
}
