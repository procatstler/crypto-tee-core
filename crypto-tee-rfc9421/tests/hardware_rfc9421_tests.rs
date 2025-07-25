//! Hardware-specific RFC 9421 integration tests
//!
//! This module tests RFC 9421 HTTP Message Signatures with software fallback
//! when hardware is not available.

use chrono::Utc;
use crypto_tee::CryptoTEEBuilder;
use crypto_tee_rfc9421::{
    types::{HttpMessage, SignatureAlgorithm, SignatureComponent, SignatureInputBuilder},
    Rfc9421Adapter,
};
use std::collections::HashMap;
use std::sync::Arc;

/// Helper for creating test HTTP messages
pub struct HttpMessageBuilder {
    method: String,
    uri: String,
    headers: HashMap<String, Vec<String>>,
    body: Option<Vec<u8>>,
}

impl HttpMessageBuilder {
    pub fn new() -> Self {
        Self {
            method: "POST".to_string(),
            uri: "https://api.example.com/data".to_string(),
            headers: HashMap::new(),
            body: None,
        }
    }

    pub fn method(mut self, method: &str) -> Self {
        self.method = method.to_string();
        self
    }

    pub fn uri(mut self, uri: &str) -> Self {
        self.uri = uri.to_string();
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.insert(name.to_lowercase(), vec![value.to_string()]);
        self
    }

    pub fn body(mut self, body: &[u8]) -> Self {
        self.body = Some(body.to_vec());
        self
    }

    pub fn build(mut self) -> HttpMessage {
        // Add standard headers if not present
        if !self.headers.contains_key("host") {
            self.headers.insert("host".to_string(), vec!["api.example.com".to_string()]);
        }
        if !self.headers.contains_key("date") {
            self.headers.insert(
                "date".to_string(),
                vec![Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()],
            );
        }
        if self.body.is_some() {
            let body_len = self.body.as_ref().unwrap().len();
            self.headers.insert("content-length".to_string(), vec![body_len.to_string()]);
            if !self.headers.contains_key("content-type") {
                self.headers
                    .insert("content-type".to_string(), vec!["application/json".to_string()]);
            }
        }

        HttpMessage {
            method: Some(self.method),
            uri: Some(self.uri),
            status: None,
            headers: self.headers,
            body: self.body,
        }
    }
}

/// Basic test to ensure RFC 9421 adapter can be created with CryptoTEE
#[tokio::test]
async fn test_rfc9421_adapter_creation() {
    let crypto_tee = CryptoTEEBuilder::new().build().await.expect("Should initialize CryptoTEE");

    let _adapter = Rfc9421Adapter::with_crypto_tee(Arc::new(crypto_tee));

    println!("✅ RFC 9421 adapter created successfully");
}

/// Test creating signature parameters
#[tokio::test]
async fn test_signature_params_creation() {
    let signature_params =
        SignatureInputBuilder::new("test-key".to_string(), SignatureAlgorithm::Ed25519)
            .add_component(SignatureComponent::Method)
            .add_component(SignatureComponent::Path)
            .add_component(SignatureComponent::Authority)
            .add_component(SignatureComponent::Header("host".to_string()))
            .created(Utc::now())
            .expires(Utc::now() + chrono::Duration::hours(1))
            .nonce("test-nonce-123".to_string())
            .build();

    assert_eq!(signature_params.key_id, "test-key");
    assert_eq!(signature_params.algorithm, SignatureAlgorithm::Ed25519);
    assert_eq!(signature_params.covered_components.len(), 4);
    assert!(signature_params.created.is_some());
    assert!(signature_params.expires.is_some());
    assert_eq!(signature_params.nonce, Some("test-nonce-123".to_string()));

    println!("✅ Signature parameters created successfully");
}

/// Test HTTP message builder
#[tokio::test]
async fn test_http_message_builder() {
    let message = HttpMessageBuilder::new()
        .method("POST")
        .uri("https://api.example.com/test")
        .header("authorization", "Bearer token123")
        .header("x-request-id", "req-12345")
        .body(b"{\"test\": \"data\"}")
        .build();

    assert_eq!(message.method, Some("POST".to_string()));
    assert_eq!(message.uri, Some("https://api.example.com/test".to_string()));
    assert!(message.headers.contains_key("host"));
    assert!(message.headers.contains_key("date"));
    assert!(message.headers.contains_key("content-length"));
    assert!(message.headers.contains_key("content-type"));
    assert!(message.headers.contains_key("authorization"));
    assert!(message.headers.contains_key("x-request-id"));
    assert!(message.body.is_some());

    println!("✅ HTTP message builder test completed");
}