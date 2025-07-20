//! Integration tests for CryptoTEE

use crypto_tee::{
    Algorithm, CryptoTEE, CryptoTEEBuilder, KeyOptions, KeyUsage, PlatformConfig,
};

#[tokio::test]
async fn test_cryptotee_initialization() {
    let tee = CryptoTEEBuilder::new().build().await.unwrap();
    
    let capabilities = tee.list_capabilities().await.unwrap();
    assert!(!capabilities.is_empty());
    
    // Should have at least vendor info
    assert!(capabilities.iter().any(|c| c.starts_with("vendor:")));
}

#[tokio::test]
async fn test_key_lifecycle() {
    let tee = CryptoTEEBuilder::new().build().await.unwrap();
    
    // Generate key
    let options = KeyOptions {
        algorithm: Algorithm::Ed25519,
        usage: KeyUsage::default(),
        hardware_backed: false, // Use software for testing
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };
    
    let key_handle = tee.generate_key("test-key", options).await.unwrap();
    assert_eq!(key_handle.alias, "test-key");
    
    // List keys
    let keys = tee.list_keys().await.unwrap();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].alias, "test-key");
    
    // Get key info
    let info = tee.get_key_info("test-key").await.unwrap();
    assert_eq!(info.alias, "test-key");
    assert_eq!(info.algorithm, Algorithm::Ed25519);
    
    // Delete key
    tee.delete_key("test-key").await.unwrap();
    
    // Verify deleted
    let keys = tee.list_keys().await.unwrap();
    assert_eq!(keys.len(), 0);
}

#[tokio::test]
async fn test_sign_verify() {
    let tee = CryptoTEEBuilder::new().build().await.unwrap();
    
    // Generate key
    let options = KeyOptions {
        algorithm: Algorithm::Ed25519,
        usage: KeyUsage {
            sign: true,
            verify: true,
            ..Default::default()
        },
        hardware_backed: false,
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };
    
    tee.generate_key("sign-key", options).await.unwrap();
    
    // Sign data
    let data = b"Hello, CryptoTEE!";
    let signature = tee.sign("sign-key", data, None).await.unwrap();
    
    // Verify signature
    let valid = tee
        .verify("sign-key", data, &signature, None)
        .await
        .unwrap();
    assert!(valid);
    
    // Verify with wrong data
    let invalid = tee
        .verify("sign-key", b"Wrong data", &signature, None)
        .await
        .unwrap();
    assert!(!invalid);
    
    // Cleanup
    tee.delete_key("sign-key").await.unwrap();
}

#[tokio::test]
async fn test_duplicate_key_error() {
    let tee = CryptoTEEBuilder::new().build().await.unwrap();
    
    let options = KeyOptions::default();
    
    // First key should succeed
    tee.generate_key("dup-key", options.clone()).await.unwrap();
    
    // Duplicate should fail
    let result = tee.generate_key("dup-key", options).await;
    assert!(result.is_err());
    
    // Cleanup
    tee.delete_key("dup-key").await.unwrap();
}

#[tokio::test]
async fn test_missing_key_error() {
    let tee = CryptoTEEBuilder::new().build().await.unwrap();
    
    // Operations on non-existent key should fail
    assert!(tee.get_key_info("missing").await.is_err());
    assert!(tee.delete_key("missing").await.is_err());
    assert!(tee.sign("missing", b"data", None).await.is_err());
}

#[tokio::test]
async fn test_with_platform_config() {
    let config = PlatformConfig {
        require_auth: false,
        auth_validity_seconds: Some(300),
        allow_biometric: true,
        require_strong_biometric: false,
        platform_options: None,
    };
    
    let tee = CryptoTEEBuilder::new()
        .with_platform_config(config)
        .build()
        .await
        .unwrap();
    
    // Should initialize successfully
    let capabilities = tee.list_capabilities().await.unwrap();
    assert!(!capabilities.is_empty());
}