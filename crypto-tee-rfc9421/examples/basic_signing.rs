//! Basic RFC 9421 HTTP message signing example
//!
//! This example demonstrates simple HTTP message signing according to RFC 9421
//! using CryptoTEE for secure key management.

use chrono::Utc;
use crypto_tee::{Algorithm, CryptoTEE, CryptoTEEBuilder, KeyOptions, KeyUsage};
use crypto_tee_rfc9421::{
    types::{HttpMessage, SignatureAlgorithm, SignatureComponent, SignatureInputBuilder},
    Rfc9421Adapter,
};
use std::collections::HashMap;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("RFC 9421 HTTP Message Signing Example");
    println!("====================================");

    // Initialize CryptoTEE
    println!("\n1. Initializing CryptoTEE...");
    let crypto_tee = CryptoTEEBuilder::new().build().await?;
    let crypto_tee = Arc::new(crypto_tee);

    println!("✅ CryptoTEE initialized");

    // Create RFC 9421 adapter
    println!("\n2. Creating RFC 9421 adapter...");
    let adapter = Rfc9421Adapter::with_crypto_tee(crypto_tee.clone());
    println!("✅ RFC 9421 adapter created");

    // Generate a signing key for HTTP messages
    println!("\n3. Generating signing key...");
    let key_alias = "http-signing-key";

    let key_handle = crypto_tee
        .generate_key(
            key_alias,
            KeyOptions {
                algorithm: Algorithm::Ed25519, // Fast and secure for HTTP signing
                usage: KeyUsage {
                    sign: true,
                    verify: true,
                    encrypt: false,
                    decrypt: false,
                    wrap: false,
                    unwrap: false,
                },
                hardware_backed: true,
                exportable: false,   // Keep keys secure
                require_auth: false, // Don't prompt for auth on every request
                expires_at: None,
                metadata: None,
            },
        )
        .await?;

    println!("✅ Signing key generated");
    println!("   Key alias: {}", key_handle.alias);
    println!("   Algorithm: {:?}", key_handle.metadata.algorithm);

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
            // RFC 9421 metadata
            .created(Utc::now()) // created timestamp
            .expires(Utc::now() + chrono::Duration::hours(1)) // expires in 1 hour
            .nonce("random-nonce-12345".to_string()) // anti-replay nonce
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

    let signature_output = adapter.sign_message(&message, signature_params.clone()).await?;

    println!("✅ HTTP message signed successfully");

    // Display the signature results
    println!("\n7. Signature results...");

    println!("   Signature-Input: {}", signature_output.signature_input);
    println!("   Signature: {}", signature_output.signature);

    // Verify the signature
    println!("\n8. Verifying signature...");

    let verification_result = adapter
        .verify_message(&message, &signature_output.signature, &signature_output.params)
        .await?;

    println!("✅ Signature verification: {}", verification_result.valid);
    if verification_result.valid {
        println!("   Key ID: {}", verification_result.key_id);
        println!("   Algorithm: {:?}", verification_result.algorithm);
        if let Some(created) = verification_result.created {
            println!("   Created: {}", created);
        }
        if let Some(expires) = verification_result.expires {
            println!("   Expires: {}", expires);
        }
    }

    // Show the complete signed HTTP request
    println!("\n9. Complete signed HTTP request:");
    println!("   {}", "=".repeat(50));

    println!(
        "   {} {} HTTP/1.1",
        message.method.as_ref().unwrap(),
        message.uri.as_ref().unwrap().replace("https://example.com", "")
    );

    // Add the signature headers to the output
    let mut output_headers = message.headers.clone();
    output_headers.insert(
        "signature-input".to_string(),
        vec![signature_output.signature_input.clone()],
    );
    output_headers.insert(
        "signature".to_string(),
        vec![format!("sig1=:{}", signature_output.signature)],
    );

    for (name, values) in &output_headers {
        for value in values {
            println!("   {}: {}", name, value);
        }
    }

    println!();
    if let Some(body) = &message.body {
        println!("   {}", String::from_utf8_lossy(body));
    }

    println!("   {}", "=".repeat(50));

    // Performance demonstration
    println!("\n10. Performance test...");

    let start = std::time::Instant::now();
    let _signed = adapter.sign_message(&message, signature_params.clone()).await?;
    let sign_time = start.elapsed();

    let start = std::time::Instant::now();
    let _is_valid = adapter
        .verify_message(&message, &signature_output.signature, &signature_output.params)
        .await?;
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