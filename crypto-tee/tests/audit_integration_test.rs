//! Integration tests for audit logging

use crypto_tee::types::KeyOptions;
use crypto_tee::{Algorithm, KeyUsage};
use crypto_tee::{CryptoTEE, CryptoTEEBuilder};
use std::path::Path;

#[tokio::test]
async fn test_audit_logging_generates_logs() {
    // Create CryptoTEE instance
    let crypto_tee =
        CryptoTEEBuilder::new().build().await.expect("Failed to create CryptoTEE instance");

    // Generate a key
    let options = KeyOptions {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: false,
        exportable: false,
        usage: KeyUsage {
            sign: true,
            verify: true,
            encrypt: false,
            decrypt: false,
            wrap: false,
            unwrap: false,
        },
        metadata: Default::default(),
        expires_at: None,
        require_auth: false,
    };

    let _key_handle =
        crypto_tee.generate_key("test_key_audit", options).await.expect("Failed to generate key");

    // Check that audit log file exists
    let audit_log_path = Path::new("audit_logs/crypto-tee-audit.jsonl");
    assert!(audit_log_path.exists(), "Audit log file should exist");

    // Sign some data
    let data = b"Hello, CryptoTEE with Audit!";
    let _signature =
        crypto_tee.sign("test_key_audit", data, None).await.expect("Failed to sign data");

    // Delete the key
    crypto_tee.delete_key("test_key_audit").await.expect("Failed to delete key");

    // Cleanup
    if let Ok(_) = std::fs::remove_dir_all("audit_logs") {
        // Directory removed
    }
}
