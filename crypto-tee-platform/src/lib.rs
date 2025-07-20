//! Platform-specific adapters for CryptoTEE
//! 
//! This crate provides the platform layer (L2) that bridges between
//! the core CryptoTEE API and platform-specific security APIs.

pub fn platform_name() -> &'static str {
    #[cfg(target_os = "android")]
    return "Android";
    
    #[cfg(target_os = "ios")]
    return "iOS";
    
    #[cfg(target_os = "linux")]
    return "Linux";
    
    #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "linux")))]
    return "Unknown";
}