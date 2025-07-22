//! Complete RFC 9421 HTTP message signing example
//!
//! This example demonstrates how to sign HTTP messages according to RFC 9421
//! using CryptoTEE for secure key management.

use chrono::Utc;
use crypto_tee::prelude::*;
use crypto_tee_rfc9421::{
    types::{HttpMessage, SignatureAlgorithm, SignatureComponent, SignatureInputBuilder},
    Rfc9421Adapter,
};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("RFC 9421 HTTP Message Signing Example");
    println!("====================================");

    // Initialize CryptoTEE
    println!("\n1. Initializing CryptoTEE...");
    let crypto_tee = CryptoTEEBuilder::new()
        .prefer_hardware(true)
        .enable_software_fallback(true)
        .build()
        .await?;

    println!("✅ CryptoTEE initialized");

    // Create RFC 9421 adapter
    println!("\n2. Creating RFC 9421 adapter...");
    let adapter = Rfc9421Adapter::new_with_crypto_tee(crypto_tee.clone()).await?;
    println!("✅ RFC 9421 adapter created");

    // Generate a signing key for HTTP messages
    println!("\n3. Generating signing key...");
    let key_alias = "http-signing-key";

    let key_handle = crypto_tee
        .generate_key(
            key_alias,
            KeyOptions {
                algorithm: Algorithm::Ed25519, // Fast and secure for HTTP signing
                usage: KeyUsage::SIGN_VERIFY,
                hardware_backed: true,
                exportable: false,   // Keep keys secure
                require_auth: false, // Don't prompt for auth on every request
                expires_at: None,
                metadata: Some(KeyMetadata {
                    description: Some("HTTP message signing key".to_string()),
                    tags: vec!["http".to_string(), "rfc9421".to_string()],
                    created_by: Some("basic_signing_example".to_string()),
                    purpose: Some("HTTP message signatures".to_string()),
                }),
            },
        )
        .await?;

    println!("✅ Signing key generated");
    println!("   Key ID: {}", key_handle.id);
    println!("   Algorithm: {:?}", key_handle.algorithm);
    println!("   Hardware-backed: {}", key_handle.hardware_backed);

    // Create an HTTP POST request to sign
    println!("\n4. Creating HTTP message...");

    let mut headers = HashMap::new();
    headers.insert("host".to_string(), vec!["example.com".to_string()]);
    headers.insert("content-type".to_string(), vec!["application/json".to_string()]);
    headers.insert("content-length".to_string(), vec!["17".to_string()]);
    headers.insert(
        "date".to_string(),
        vec![Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()],
    );

    let message = HttpMessage {
        method: Some("POST".to_string()),
        uri: Some("https://example.com/api/users".to_string()),
        status: None,
        headers: headers.clone(),
        body: Some(b"{\"name\":\"Alice\"}".to_vec()),
    };

    println!("✅ HTTP message created");
    println!("   Method: {}", message.method.as_ref().unwrap());
    println!("   URI: {}", message.uri.as_ref().unwrap());
    println!("   Headers: {}", message.headers.len());
    println!("   Body size: {} bytes", message.body.as_ref().unwrap().len());

    // Build signature parameters according to RFC 9421
    println!("\n5. Building signature parameters...");

    let signature_params =
        SignatureInputBuilder::new(key_alias.to_string(), SignatureAlgorithm::Ed25519)
            // Required components for this request
            .add_component(SignatureComponent::Method) // @method
            .add_component(SignatureComponent::Path) // @path
            .add_component(SignatureComponent::Authority) // @authority
            .add_component(SignatureComponent::Header("host".to_string()))
            .add_component(SignatureComponent::Header("content-type".to_string()))
            .add_component(SignatureComponent::Header("content-length".to_string()))
            .add_component(SignatureComponent::Header("date".to_string()))
            // Optional: include request body hash
            .add_component(SignatureComponent::ContentDigest) // content-digest
            // RFC 9421 metadata
            .created(Utc::now()) // created timestamp
            .expires(Utc::now() + chrono::Duration::hours(1)) // expires in 1 hour
            .nonce(Some("random-nonce-12345".to_string())) // anti-replay nonce
            .build();

    println!("✅ Signature parameters built");
    println!("   Key ID: {}", signature_params.key_id);
    println!("   Algorithm: {:?}", signature_params.algorithm);
    println!("   Components: {} items", signature_params.covered_components.len());

    for (i, component) in signature_params.covered_components.iter().enumerate() {
        println!("     {}: {:?}", i + 1, component);
    }

    // Sign the HTTP message
    println!("\n6. Signing HTTP message...");

    let signed_message = adapter.sign_message(&message, &signature_params).await?;

    println!("✅ HTTP message signed successfully");

    // Display the signature headers
    println!("\n7. Signature results...");

    if let Some(signature_input) = signed_message.headers.get("signature-input") {
        println!("   Signature-Input: {}", signature_input.join(", "));
    }

    if let Some(signature) = signed_message.headers.get("signature") {
        println!("   Signature: {}", signature.join(", "));
    }

    // Verify the signature
    println!("\n8. Verifying signature...");

    let is_valid = adapter.verify_message(&signed_message, &signature_params).await?;

    println!("✅ Signature verification: {}", if is_valid { "VALID" } else { "INVALID" });

    // Show the complete signed HTTP request
    println!("\n9. Complete signed HTTP request:");
    println!("   {}", "=".repeat(50));

    println!(
        "   {} {} HTTP/1.1",
        signed_message.method.as_ref().unwrap(),
        signed_message.uri.as_ref().unwrap().replace("https://example.com", "")
    );

    for (name, values) in &signed_message.headers {
        for value in values {
            println!("   {}: {}", name, value);
        }
    }

    println!();
    if let Some(body) = &signed_message.body {
        println!("   {}", String::from_utf8_lossy(body));
    }

    println!("   {}", "=".repeat(50));

    // Performance demonstration
    println!("\n10. Performance test...");

    let start = std::time::Instant::now();
    let _signed = adapter.sign_message(&message, &signature_params).await?;
    let sign_time = start.elapsed();

    let start = std::time::Instant::now();
    let _is_valid = adapter.verify_message(&signed_message, &signature_params).await?;
    let verify_time = start.elapsed();

    println!("✅ Performance results:");
    println!("    Sign time: {:?}", sign_time);
    println!("    Verify time: {:?}", verify_time);

    // RFC 9421 compliance notes
    println!("\n🔐 RFC 9421 Security Features:");
    println!("   • Message integrity protection");
    println!("   • Non-repudiation through digital signatures");
    println!("   • Replay protection via nonce and expiry");
    println!("   • Cryptographic proof of request authenticity");
    println!("   • Support for multiple signature algorithms");
    println!("   • Granular component selection for signing");

    // Clean up
    println!("\n11. Cleanup...");
    crypto_tee.delete_key(key_alias).await?;
    println!("✅ Signing key deleted");

    println!("\n✅ RFC 9421 HTTP Message Signing example completed successfully!");

    Ok(())
}
