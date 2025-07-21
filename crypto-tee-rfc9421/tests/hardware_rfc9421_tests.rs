//! Hardware-specific RFC 9421 integration tests
//!
//! This module tests RFC 9421 HTTP Message Signatures with software fallback
//! when hardware is not available.

use crypto_tee::{CryptoTEE, CryptoTEEBuilder, KeyOptions, KeyUsage, Algorithm};
use crypto_tee_rfc9421::{
    types::{HttpMessage, SignatureAlgorithm, SignatureComponent, SignatureInputBuilder},
    Rfc9421Adapter,
};
use std::collections::HashMap;
use chrono::Utc;

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
            self.headers.insert("date".to_string(), vec![
                Utc::now().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
            ]);
        }
        if self.body.is_some() {
            let body_len = self.body.as_ref().unwrap().len();
            self.headers.insert("content-length".to_string(), vec![body_len.to_string()]);
            if !self.headers.contains_key("content-type") {
                self.headers.insert("content-type".to_string(), vec!["application/json".to_string()]);
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

/// Test RFC 9421 with Ed25519 algorithm
#[tokio::test]
async fn test_rfc9421_with_ed25519() {
    let crypto_tee = CryptoTEEBuilder::new().build()
        .await
        .expect("Should initialize CryptoTEE");

    let adapter = Rfc9421Adapter::new_with_crypto_tee(crypto_tee.clone()).await
        .expect("Should create RFC 9421 adapter");

    let key_alias = "rfc9421_ed25519_key";
    
    let key_options = KeyOptions {
        algorithm: Algorithm::Ed25519,
        usage: KeyUsage::default(),
        hardware_backed: false,
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };

    // Generate signing key
    let _key = crypto_tee.generate_key(key_alias, key_options).await
        .expect("Should generate RFC 9421 signing key");

    // Create test HTTP message
    let message = HttpMessageBuilder::new()
        .method("POST")
        .uri("https://api.example.com/secure-endpoint")
        .header("authorization", "Bearer token123")
        .header("x-request-id", "req-12345")
        .body(b"{\"data\": \"test\"}")
        .build();

    // Build signature parameters
    let signature_params = SignatureInputBuilder::new(
        key_alias.to_string(),
        SignatureAlgorithm::Ed25519
    )
    .add_component(SignatureComponent::Method)
    .add_component(SignatureComponent::Path)
    .add_component(SignatureComponent::Authority)
    .add_component(SignatureComponent::Header("authorization".to_string()))
    .add_component(SignatureComponent::Header("x-request-id".to_string()))
    .add_component(SignatureComponent::ContentDigest)
    .created(Utc::now())
    .expires(Utc::now() + chrono::Duration::hours(1))
    .nonce(Some("test-nonce-123".to_string()))
    .build();

    // Sign the message
    let signed_message = adapter.sign_message(&message, &signature_params).await
        .expect("Should sign HTTP message with Ed25519");

    // Verify required signature headers are present
    assert!(signed_message.headers.contains_key("signature-input"));
    assert!(signed_message.headers.contains_key("signature"));

    // Verify the signature
    let is_valid = adapter.verify_message(&signed_message, &signature_params).await
        .expect("Should verify HTTP signature");
    assert!(is_valid, "HTTP signature should be valid");

    println!("✅ RFC 9421 with Ed25519 completed successfully");

    // Cleanup
    crypto_tee.delete_key(key_alias).await.expect("Should cleanup test key");
}

/// Test RFC 9421 with ECDSA P-256 algorithm
#[tokio::test]
async fn test_rfc9421_with_ecdsa_p256() {
    let crypto_tee = CryptoTEEBuilder::new().build()
        .await
        .expect("Should initialize CryptoTEE");

    let adapter = Rfc9421Adapter::new_with_crypto_tee(crypto_tee.clone()).await
        .expect("Should create RFC 9421 adapter");

    let key_alias = "rfc9421_ecdsa_key";
    
    let key_options = KeyOptions {
        algorithm: Algorithm::EcdsaP256,
        usage: KeyUsage::default(),
        hardware_backed: false,
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };

    // Generate signing key
    let _key = crypto_tee.generate_key(key_alias, key_options).await
        .expect("Should generate ECDSA key");

    // Create test HTTP message for mobile API
    let message = HttpMessageBuilder::new()
        .method("PUT")
        .uri("https://mobile-api.example.com/user/profile")
        .header("user-agent", "TestApp/1.0")
        .header("x-device-id", "device-12345")
        .header("x-app-version", "1.2.3")
        .body(b"{\"profile\": {\"name\": \"Test User\"}}")
        .build();

    // Build signature parameters
    let signature_params = SignatureInputBuilder::new(
        key_alias.to_string(),
        SignatureAlgorithm::EcdsaP256
    )
    .add_component(SignatureComponent::Method)
    .add_component(SignatureComponent::Path)
    .add_component(SignatureComponent::Authority)
    .add_component(SignatureComponent::Header("user-agent".to_string()))
    .add_component(SignatureComponent::Header("x-device-id".to_string()))
    .add_component(SignatureComponent::Header("x-app-version".to_string()))
    .add_component(SignatureComponent::ContentDigest)
    .created(Utc::now())
    .expires(Utc::now() + chrono::Duration::minutes(30))
    .nonce(Some("ecdsa-test-nonce-456".to_string()))
    .build();

    // Sign the message
    let signed_message = adapter.sign_message(&message, &signature_params).await
        .expect("Should sign HTTP message with ECDSA P-256");

    // Verify signature headers
    assert!(signed_message.headers.contains_key("signature-input"));
    assert!(signed_message.headers.contains_key("signature"));

    // Verify the signature
    let is_valid = adapter.verify_message(&signed_message, &signature_params).await
        .expect("Should verify HTTP signature");
    assert!(is_valid, "ECDSA HTTP signature should be valid");

    println!("✅ RFC 9421 with ECDSA P-256 completed successfully");

    // Cleanup
    crypto_tee.delete_key(key_alias).await.expect("Should cleanup test key");
}

/// Test RFC 9421 performance
#[tokio::test]
async fn test_rfc9421_signing_performance() {
    let crypto_tee = CryptoTEEBuilder::new().build()
        .await
        .expect("Should initialize CryptoTEE");

    let adapter = Rfc9421Adapter::new_with_crypto_tee(crypto_tee.clone()).await
        .expect("Should create RFC 9421 adapter");

    // Test performance with different algorithms
    let performance_tests = vec![
        ("ed25519_perf", Algorithm::Ed25519, SignatureAlgorithm::Ed25519),
        ("ecdsa_perf", Algorithm::EcdsaP256, SignatureAlgorithm::EcdsaP256),
    ];

    for (key_alias, key_algorithm, sig_algorithm) in performance_tests {
        let key_options = KeyOptions {
            algorithm: key_algorithm,
            usage: KeyUsage::default(),
            hardware_backed: false,
            exportable: false,
            require_auth: false,
            expires_at: None,
            metadata: None,
        };

        // Generate key
        let _key = crypto_tee.generate_key(key_alias, key_options).await
            .expect("Should generate performance test key");

        // Create test HTTP message
        let message = HttpMessageBuilder::new()
            .method("POST")
            .uri("https://api.example.com/performance-test")
            .header("content-type", "application/json")
            .header("x-test-iteration", "performance")
            .body(b"{\"test\": \"performance data\"}")
            .build();

        let signature_params = SignatureInputBuilder::new(
            key_alias.to_string(),
            sig_algorithm
        )
        .add_component(SignatureComponent::Method)
        .add_component(SignatureComponent::Path)
        .add_component(SignatureComponent::Authority)
        .add_component(SignatureComponent::Header("content-type".to_string()))
        .add_component(SignatureComponent::Header("x-test-iteration".to_string()))
        .add_component(SignatureComponent::ContentDigest)
        .created(Utc::now())
        .build();

        // Performance test
        let iterations = 10;
        let mut sign_times = Vec::new();
        let mut verify_times = Vec::new();

        for _ in 0..iterations {
            // Measure signing time
            let sign_start = std::time::Instant::now();
            let signed_message = adapter.sign_message(&message, &signature_params).await
                .expect("Should sign for performance test");
            sign_times.push(sign_start.elapsed());

            // Measure verification time
            let verify_start = std::time::Instant::now();
            let is_valid = adapter.verify_message(&signed_message, &signature_params).await
                .expect("Should verify for performance test");
            verify_times.push(verify_start.elapsed());

            assert!(is_valid, "Performance test signature should be valid");
        }

        // Calculate statistics
        let avg_sign_time = sign_times.iter().sum::<std::time::Duration>() / iterations as u32;
        let avg_verify_time = verify_times.iter().sum::<std::time::Duration>() / iterations as u32;

        println!("🏃 RFC 9421 Performance Results for {:?}:", key_algorithm);
        println!("   Average sign time: {:?}", avg_sign_time);
        println!("   Average verify time: {:?}", avg_verify_time);

        // Basic performance assertions
        assert!(avg_sign_time < std::time::Duration::from_millis(500), 
            "Average signing should be reasonable for {:?}", key_algorithm);
        assert!(avg_verify_time < std::time::Duration::from_millis(200), 
            "Average verification should be reasonable for {:?}", key_algorithm);

        // Cleanup
        crypto_tee.delete_key(key_alias).await.expect("Should cleanup performance test key");
    }
}

/// Test RFC 9421 concurrent signing
#[tokio::test]
async fn test_rfc9421_concurrent_signing() {
    let crypto_tee = CryptoTEEBuilder::new().build()
        .await
        .expect("Should initialize CryptoTEE");

    let adapter = Rfc9421Adapter::new_with_crypto_tee(crypto_tee.clone()).await
        .expect("Should create RFC 9421 adapter");

    // Generate signing key
    let key_alias = "rfc9421_concurrent";
    let key_options = KeyOptions {
        algorithm: Algorithm::Ed25519, // Use fast algorithm for concurrency test
        usage: KeyUsage::default(),
        hardware_backed: false,
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };

    let _key = crypto_tee.generate_key(key_alias, key_options).await
        .expect("Should generate concurrent test key");

    // Create multiple HTTP messages to sign concurrently
    let concurrent_requests = 5;
    let mut sign_futures = Vec::new();

    for i in 0..concurrent_requests {
        let adapter_clone = adapter.clone();
        let message = HttpMessageBuilder::new()
            .method("POST")
            .uri(&format!("https://api.example.com/concurrent/{}", i))
            .header("x-request-id", &format!("concurrent-req-{}", i))
            .body(format!("{{\"data\": \"concurrent test {}\"}}", i).as_bytes())
            .build();

        let signature_params = SignatureInputBuilder::new(
            key_alias.to_string(),
            SignatureAlgorithm::Ed25519
        )
        .add_component(SignatureComponent::Method)
        .add_component(SignatureComponent::Path)
        .add_component(SignatureComponent::Authority)
        .add_component(SignatureComponent::Header("x-request-id".to_string()))
        .add_component(SignatureComponent::ContentDigest)
        .created(Utc::now())
        .nonce(Some(format!("concurrent-nonce-{}", i)))
        .build();

        let future = async move {
            let signed_message = adapter_clone.sign_message(&message, &signature_params).await?;
            let is_valid = adapter_clone.verify_message(&signed_message, &signature_params).await?;
            
            if !is_valid {
                return Err("Concurrent signature verification failed".into());
            }
            
            Result::<i32, Box<dyn std::error::Error + Send + Sync>>::Ok(i)
        };

        sign_futures.push(future);
    }

    // Wait for all concurrent operations
    let results = futures::future::try_join_all(sign_futures).await
        .expect("All concurrent signing operations should succeed");

    assert_eq!(results.len(), concurrent_requests);
    println!("✅ RFC 9421 concurrent signing completed: {} operations", results.len());

    // Cleanup
    crypto_tee.delete_key(key_alias).await.expect("Should cleanup concurrent test key");
}

/// Test RFC 9421 with different message types
#[tokio::test]
async fn test_rfc9421_message_variations() {
    let crypto_tee = CryptoTEEBuilder::new().build()
        .await
        .expect("Should initialize CryptoTEE");

    let adapter = Rfc9421Adapter::new_with_crypto_tee(crypto_tee.clone()).await
        .expect("Should create RFC 9421 adapter");

    let key_alias = "rfc9421_variation_test";
    let key_options = KeyOptions {
        algorithm: Algorithm::Ed25519,
        usage: KeyUsage::default(),
        hardware_backed: false,
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };

    let _key = crypto_tee.generate_key(key_alias, key_options).await
        .expect("Should generate variation test key");

    // Test different HTTP methods and message types
    let test_cases = vec![
        ("GET", "https://api.example.com/users", None),
        ("POST", "https://api.example.com/users", Some(b"{\"name\": \"John\"}" as &[u8])),
        ("PUT", "https://api.example.com/users/123", Some(b"{\"name\": \"Jane\"}" as &[u8])),
        ("DELETE", "https://api.example.com/users/123", None),
    ];

    for (i, (method, uri, body)) in test_cases.into_iter().enumerate() {
        let mut message_builder = HttpMessageBuilder::new()
            .method(method)
            .uri(uri);

        if let Some(body_data) = body {
            message_builder = message_builder.body(body_data);
        }

        let message = message_builder.build();

        let mut signature_builder = SignatureInputBuilder::new(
            key_alias.to_string(),
            SignatureAlgorithm::Ed25519
        )
        .add_component(SignatureComponent::Method)
        .add_component(SignatureComponent::Path)
        .add_component(SignatureComponent::Authority);

        if body.is_some() {
            signature_builder = signature_builder.add_component(SignatureComponent::ContentDigest);
        }

        let signature_params = signature_builder
            .created(Utc::now())
            .nonce(Some(format!("variation-test-{}", i)))
            .build();

        let signed_message = adapter.sign_message(&message, &signature_params).await
            .expect(&format!("Should sign {} request", method));

        let is_valid = adapter.verify_message(&signed_message, &signature_params).await
            .expect(&format!("Should verify {} signature", method));

        assert!(is_valid, "{} signature should be valid", method);
        
        println!("✅ RFC 9421 {} request signed and verified", method);
    }

    // Cleanup
    crypto_tee.delete_key(key_alias).await.expect("Should cleanup variation test key");
}