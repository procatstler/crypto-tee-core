//! Basic RFC 9421 HTTP message signing example

use std::collections::HashMap;
use crypto_tee_rfc9421::{
    Rfc9421Adapter,
    types::{HttpMessage, SignatureComponent, SignatureInputBuilder, SignatureAlgorithm},
};
use chrono::Utc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing (optional)

    // Create adapter
    println!("Creating RFC 9421 adapter...");
    let adapter = Rfc9421Adapter::new().await?;

    // Create an HTTP message to sign
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), vec!["application/json".to_string()]);
    headers.insert("date".to_string(), vec!["Tue, 20 Apr 2023 02:07:56 GMT".to_string()]);

    let message = HttpMessage {
        method: Some("POST".to_string()),
        uri: Some("https://example.com/api/users".to_string()),
        status: None,
        headers,
        body: Some(b"{\"name\": \"Alice\"}".to_vec()),
    };

    // Build signature parameters
    let params = SignatureInputBuilder::new(
        "test-key".to_string(),
        SignatureAlgorithm::Ed25519,
    )
    .add_component(SignatureComponent::Method)
    .add_component(SignatureComponent::Path)
    .add_component(SignatureComponent::Authority)
    .add_component(SignatureComponent::Header("content-type".to_string()))
    .add_component(SignatureComponent::Header("date".to_string()))
    .created(Utc::now())
    .build();

    println!("Signature parameters:");
    println!("  Key ID: {}", params.key_id);
    println!("  Algorithm: {:?}", params.algorithm);
    println!("  Components: {:?}", params.covered_components);

    // Note: This example shows the structure - actual signing would require
    // a key to be available in the CryptoTEE instance
    println!("\nRFC 9421 HTTP Message Signing example completed!");
    println!("To run actual signing, first generate a key using CryptoTEE API.");
    
    Ok(())
}