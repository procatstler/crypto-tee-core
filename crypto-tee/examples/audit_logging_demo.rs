//! Example demonstrating audit logging in CryptoTEE

use crypto_tee::types::KeyOptions;
use crypto_tee::{Algorithm, CryptoTEE, CryptoTEEBuilder, KeyUsage};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    println!("CryptoTEE Audit Logging Demo");
    println!("============================\n");

    // Create CryptoTEE instance with audit logging enabled
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    println!("✓ CryptoTEE initialized with audit logging\n");

    // Generate a key (this will be audited)
    println!("Generating a new key...");
    let key_options = KeyOptions {
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

    let key_handle = crypto_tee.generate_key("demo_key", key_options).await?;

    println!("✓ Key generated: {}\n", key_handle.alias);

    // Sign some data (this will be audited)
    println!("Signing data...");
    let data = b"Hello, CryptoTEE with Audit Logging!";
    let signature = crypto_tee.sign("demo_key", data, None).await?;

    println!(
        "✓ Data signed, signature length: {signature_length} bytes\n",
        signature_length = signature.len()
    );

    // Verify the signature (this will be audited)
    println!("Verifying signature...");
    let valid = crypto_tee.verify("demo_key", data, &signature, None).await?;

    println!("✓ Signature verification result: {valid}\n");

    // Get key info (this will be audited)
    println!("Getting key information...");
    let key_info = crypto_tee.get_key_info("demo_key").await?;

    println!("✓ Key info retrieved:");
    println!("  - Algorithm: {:?}", key_info.algorithm);
    println!("  - Hardware backed: {}", key_info.hardware_backed);
    println!("  - Created at: {:?}\n", key_info.created_at);

    // Delete the key (this will be audited)
    println!("Deleting key...");
    crypto_tee.delete_key("demo_key").await?;

    println!("✓ Key deleted\n");

    println!("Audit logs have been written to:");
    println!("  - Console output (text format)");
    println!("  - audit_logs/crypto-tee-audit.jsonl (JSON format)");
    println!("\nAll operations have been audited for compliance!");

    Ok(())
}
