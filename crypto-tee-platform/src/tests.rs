//! Platform layer tests

#[cfg(test)]
mod platform_tests {
    use crate::load_platform;

    #[tokio::test]
    async fn test_load_platform() {
        let platform = load_platform();

        // Should load fallback on non-mobile platforms
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "linux")))]
        assert_eq!(platform.name(), "fallback");

        // Should have a version
        assert!(!platform.version().is_empty());
    }

    #[tokio::test]
    async fn test_platform_vendor_detection() {
        let platform = load_platform();
        let _vendors = platform.detect_vendors().await;

        // Fallback platform should have at least one vendor
        #[cfg(not(any(target_os = "android", target_os = "ios", target_os = "linux")))]
        assert!(!_vendors.is_empty());
    }

    #[tokio::test]
    async fn test_key_handle_wrapping() {
        use crypto_tee_vendor::types::{Algorithm, VendorKeyHandle};

        let platform = load_platform();

        let vendor_handle = VendorKeyHandle {
            id: "test-key".to_string(),
            algorithm: Algorithm::Ed25519,
            vendor: "test".to_string(),
            hardware_backed: false,
            vendor_data: None,
        };

        // Wrap and unwrap should preserve the handle
        let wrapped = platform
            .wrap_key_handle(vendor_handle.clone())
            .await
            .expect("Platform test should succeed");
        assert_eq!(wrapped.vendor_handle.id, vendor_handle.id);
        assert_eq!(wrapped.platform, platform.name());

        let unwrapped =
            platform.unwrap_key_handle(&wrapped).await.expect("Platform test should succeed");
        assert_eq!(unwrapped.id, vendor_handle.id);
    }
}
