//! RFC 9421 HTTP Message Signatures example
//!
//! This example demonstrates how to use CryptoTEE with the RFC 9421
//! adapter to sign and verify HTTP messages.

use crypto_tee::{Algorithm, CryptoTEEBuilder, KeyOptions, KeyUsage};
use crypto_tee_rfc9421::{
    HttpSignatureBuilder, HttpSignatureError, HttpSignatureVerifier, SignatureParams,
};
use http::{HeaderMap, Method, Request, Uri};
use std::error::Error;
use std::time::{Duration, SystemTime};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    tracing_subscriber::fmt::init();

    println!("CryptoTEE RFC 9421 HTTP Signatures Example\n");

    // Initialize CryptoTEE
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Generate a signing key
    println!("Generating signing key...");
    let signing_key = crypto_tee
        .generate_key(
            "http-signing-key",
            KeyOptions {
                algorithm: Algorithm::Ed25519,
                usage: KeyUsage::SIGN_VERIFY,
                extractable: false,
                hardware_backed: true,
                require_auth: false,
                expires_at: None,
            },
        )
        .await?;
    println!("✓ Generated key: {}\n", signing_key.alias);

    // Example 1: Sign a simple GET request
    println!("Example 1: Simple GET request");
    sign_get_request(&crypto_tee, &signing_key.alias).await?;

    // Example 2: Sign a POST request with body
    println!("\nExample 2: POST request with body");
    sign_post_request(&crypto_tee, &signing_key.alias).await?;

    // Example 3: Sign with custom components
    println!("\nExample 3: Custom signature components");
    sign_custom_components(&crypto_tee, &signing_key.alias).await?;

    // Example 4: Verify signatures
    println!("\nExample 4: Signature verification");
    verify_signatures(&crypto_tee, &signing_key.alias).await?;

    // Clean up
    crypto_tee.delete_key(&signing_key.alias).await?;

    println!("\nExample completed successfully!");
    Ok(())
}

async fn sign_get_request(
    crypto_tee: &impl crypto_tee::CryptoTEE,
    key_alias: &str,
) -> Result<(), Box<dyn Error>> {
    // Create a GET request
    let request = Request::builder()
        .method(Method::GET)
        .uri("https://api.example.com/data/123")
        .header("Host", "api.example.com")
        .header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
        .header("Accept", "application/json")
        .body(Vec::new())?;

    // Create signature builder
    let signature_builder = HttpSignatureBuilder::new(crypto_tee.clone(), key_alias.to_string());

    // Sign the request with default components
    let signed_request = signature_builder.sign_request(request).await?;

    // Display the signature header
    let sig_header = signed_request
        .headers()
        .get("Signature")
        .unwrap()
        .to_str()?;
    println!("  Signature header: {}", sig_header);

    let sig_input = signed_request
        .headers()
        .get("Signature-Input")
        .unwrap()
        .to_str()?;
    println!("  Signature-Input: {}", sig_input);

    Ok(())
}

async fn sign_post_request(
    crypto_tee: &impl crypto_tee::CryptoTEE,
    key_alias: &str,
) -> Result<(), Box<dyn Error>> {
    let body = r#"{"name": "Alice", "email": "alice@example.com"}"#;

    // Create a POST request
    let request = Request::builder()
        .method(Method::POST)
        .uri("https://api.example.com/users")
        .header("Host", "api.example.com")
        .header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
        .header("Content-Type", "application/json")
        .header("Content-Length", body.len().to_string())
        .body(body.as_bytes().to_vec())?;

    // Create signature builder with content digest
    let mut signature_builder =
        HttpSignatureBuilder::new(crypto_tee.clone(), key_alias.to_string());

    // Include content digest in signature
    signature_builder
        .with_signature_params(SignatureParams {
            key_id: format!("key-{}", key_alias),
            algorithm: Some("ed25519".to_string()),
            created: Some(SystemTime::now()),
            expires: Some(SystemTime::now() + Duration::from_secs(300)),
            nonce: Some("unique-nonce-123".to_string()),
            covered_components: vec![
                "@method".to_string(),
                "@target-uri".to_string(),
                "@request-target".to_string(),
                "host".to_string(),
                "date".to_string(),
                "content-type".to_string(),
                "content-digest".to_string(),
            ],
            parameters: vec![],
        })
        .include_content_digest(true);

    // Sign the request
    let signed_request = signature_builder.sign_request(request).await?;

    // Display headers
    println!("  Content-Digest: {}", signed_request.headers().get("Content-Digest").unwrap().to_str()?);
    println!("  Signature: {}", signed_request.headers().get("Signature").unwrap().to_str()?);

    Ok(())
}

async fn sign_custom_components(
    crypto_tee: &impl crypto_tee::CryptoTEE,
    key_alias: &str,
) -> Result<(), Box<dyn Error>> {
    // Create a request with custom headers
    let request = Request::builder()
        .method(Method::PUT)
        .uri("https://api.example.com/resource/456")
        .header("Host", "api.example.com")
        .header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
        .header("X-API-Key", "secret-api-key")
        .header("X-Request-ID", "req-12345")
        .header("Authorization", "Bearer token123")
        .body(Vec::new())?;

    // Create signature builder with specific components
    let mut signature_builder =
        HttpSignatureBuilder::new(crypto_tee.clone(), key_alias.to_string());

    signature_builder.with_signature_params(SignatureParams {
        key_id: format!("key-{}", key_alias),
        algorithm: Some("ed25519".to_string()),
        created: Some(SystemTime::now()),
        expires: None,
        nonce: None,
        covered_components: vec![
            "@method".to_string(),
            "@authority".to_string(),
            "@path".to_string(),
            "date".to_string(),
            "x-api-key".to_string(),
            "x-request-id".to_string(),
        ],
        parameters: vec![("tag".to_string(), "custom-tag".to_string())],
    });

    // Sign the request
    let signed_request = signature_builder.sign_request(request).await?;

    let sig_input = signed_request
        .headers()
        .get("Signature-Input")
        .unwrap()
        .to_str()?;
    println!("  Custom components: {}", sig_input);

    Ok(())
}

async fn verify_signatures(
    crypto_tee: &impl crypto_tee::CryptoTEE,
    key_alias: &str,
) -> Result<(), Box<dyn Error>> {
    // Create and sign a request
    let request = Request::builder()
        .method(Method::GET)
        .uri("https://api.example.com/verify")
        .header("Host", "api.example.com")
        .header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
        .body(Vec::new())?;

    let signature_builder = HttpSignatureBuilder::new(crypto_tee.clone(), key_alias.to_string());
    let signed_request = signature_builder.sign_request(request).await?;

    // Create verifier
    let verifier = HttpSignatureVerifier::new(crypto_tee.clone());

    // Verify the signature
    match verifier.verify_request(&signed_request).await {
        Ok(verification_result) => {
            println!("  ✓ Signature verified successfully");
            println!("  Key ID: {}", verification_result.key_id);
            println!("  Algorithm: {:?}", verification_result.algorithm);
            if let Some(created) = verification_result.created {
                println!("  Created: {:?}", created);
            }
        }
        Err(e) => {
            println!("  ✗ Verification failed: {}", e);
        }
    }

    // Demonstrate verification failure with tampered request
    let mut tampered_request = signed_request;
    tampered_request.headers_mut().insert("Host", "evil.example.com".parse()?);

    println!("\n  Verifying tampered request:");
    match verifier.verify_request(&tampered_request).await {
        Ok(_) => println!("  ✗ Unexpected: Tampered request verified!"),
        Err(HttpSignatureError::VerificationFailed) => {
            println!("  ✓ Correctly rejected tampered request");
        }
        Err(e) => println!("  Error: {}", e),
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_http_signature_roundtrip() {
        // Setup
        let crypto_tee = CryptoTEEBuilder::new().build().await.unwrap();
        let key = crypto_tee
            .generate_key(
                "test-http-key",
                KeyOptions {
                    algorithm: Algorithm::Ed25519,
                    usage: KeyUsage::SIGN_VERIFY,
                    extractable: false,
                    hardware_backed: false,
                    require_auth: false,
                    expires_at: None,
                },
            )
            .await
            .unwrap();

        // Create request
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://example.com/test")
            .header("Host", "example.com")
            .header("Content-Type", "application/json")
            .body(b"{\"test\": true}".to_vec())
            .unwrap();

        // Sign
        let builder = HttpSignatureBuilder::new(crypto_tee.clone(), key.alias.clone());
        let signed = builder.sign_request(request).await.unwrap();

        // Verify
        let verifier = HttpSignatureVerifier::new(crypto_tee.clone());
        let result = verifier.verify_request(&signed).await.unwrap();

        assert_eq!(result.key_id, format!("key-{}", key.alias));

        // Clean up
        crypto_tee.delete_key(&key.alias).await.unwrap();
    }
}