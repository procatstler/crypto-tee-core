//! RFC 9421 types and data structures

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// HTTP signature algorithm as defined in RFC 9421
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    /// ECDSA P-256 with SHA-256
    EcdsaP256Sha256,
    /// ECDSA P-384 with SHA-384
    EcdsaP384Sha384,
    /// Ed25519
    Ed25519,
    /// RSA PSS with SHA-256
    RsaPssSha256,
    /// RSA PSS with SHA-384
    RsaPssSha384,
    /// RSA PSS with SHA-512
    RsaPssSha512,
}

impl SignatureAlgorithm {
    /// Get the algorithm identifier for the HTTP Signature header
    pub fn identifier(&self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ecdsa-p256-sha256",
            Self::EcdsaP384Sha384 => "ecdsa-p384-sha384",
            Self::Ed25519 => "ed25519",
            Self::RsaPssSha256 => "rsa-pss-sha256",
            Self::RsaPssSha384 => "rsa-pss-sha384",
            Self::RsaPssSha512 => "rsa-pss-sha512",
        }
    }
}

/// Components that can be included in a signature
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignatureComponent {
    /// HTTP method
    Method,
    /// Target URI
    TargetUri,
    /// Authority (host)
    Authority,
    /// Scheme (http/https)
    Scheme,
    /// Request target
    RequestTarget,
    /// Path
    Path,
    /// Query parameters
    Query,
    /// Query parameters (including ?)
    QueryParams,
    /// HTTP status code (for responses)
    Status,
    /// Request or response headers
    Header(String),
    /// Derived component
    Derived(DerivedComponent),
}

/// Derived components as defined in RFC 9421
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DerivedComponent {
    /// Signature metadata
    SignatureParams,
    /// Creation timestamp
    Created,
    /// Expiration timestamp
    Expires,
    /// Nonce
    Nonce,
    /// Algorithm
    Alg,
    /// Key ID
    KeyId,
}

/// Parameters for creating a signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureParams {
    /// Key identifier
    pub key_id: String,
    /// Algorithm to use
    pub algorithm: SignatureAlgorithm,
    /// Components to include in the signature
    pub covered_components: Vec<SignatureComponent>,
    /// Creation timestamp
    pub created: Option<DateTime<Utc>>,
    /// Expiration timestamp
    pub expires: Option<DateTime<Utc>>,
    /// Nonce for replay protection
    pub nonce: Option<String>,
    /// Additional parameters
    pub extensions: HashMap<String, String>,
}

/// Signature input string builder
pub struct SignatureInputBuilder {
    components: Vec<SignatureComponent>,
    params: SignatureParams,
}

impl SignatureInputBuilder {
    pub fn new(key_id: String, algorithm: SignatureAlgorithm) -> Self {
        Self {
            components: Vec::new(),
            params: SignatureParams {
                key_id,
                algorithm,
                covered_components: Vec::new(),
                created: None,
                expires: None,
                nonce: None,
                extensions: HashMap::new(),
            },
        }
    }

    pub fn add_component(mut self, component: SignatureComponent) -> Self {
        self.components.push(component);
        self
    }

    pub fn created(mut self, timestamp: DateTime<Utc>) -> Self {
        self.params.created = Some(timestamp);
        self
    }

    pub fn expires(mut self, timestamp: DateTime<Utc>) -> Self {
        self.params.expires = Some(timestamp);
        self
    }

    pub fn nonce(mut self, nonce: String) -> Self {
        self.params.nonce = Some(nonce);
        self
    }

    pub fn build(mut self) -> SignatureParams {
        self.params.covered_components = self.components;
        self.params
    }
}

/// HTTP message for signing
#[derive(Debug, Clone)]
pub struct HttpMessage {
    /// HTTP method (for requests)
    pub method: Option<String>,
    /// Target URI
    pub uri: Option<String>,
    /// HTTP status (for responses)
    pub status: Option<u16>,
    /// Headers
    pub headers: HashMap<String, Vec<String>>,
    /// Body (optional)
    pub body: Option<Vec<u8>>,
}

/// Result of signature creation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureOutput {
    /// The signature value (base64 encoded)
    pub signature: String,
    /// The signature input string (for debugging)
    pub signature_input: String,
    /// The signature parameters
    pub params: SignatureParams,
}

/// Result of signature verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the signature is valid
    pub valid: bool,
    /// Key ID used
    pub key_id: String,
    /// Algorithm used
    pub algorithm: SignatureAlgorithm,
    /// When the signature was created
    pub created: Option<DateTime<Utc>>,
    /// When the signature expires
    pub expires: Option<DateTime<Utc>>,
}

/// Convert CryptoTEE algorithm to RFC 9421 algorithm
pub fn map_algorithm(algo: crypto_tee_vendor::types::Algorithm) -> Option<SignatureAlgorithm> {
    match algo {
        crypto_tee_vendor::types::Algorithm::EcdsaP256 => Some(SignatureAlgorithm::EcdsaP256Sha256),
        crypto_tee_vendor::types::Algorithm::EcdsaP384 => Some(SignatureAlgorithm::EcdsaP384Sha384),
        crypto_tee_vendor::types::Algorithm::Ed25519 => Some(SignatureAlgorithm::Ed25519),
        crypto_tee_vendor::types::Algorithm::Rsa2048 
        | crypto_tee_vendor::types::Algorithm::Rsa3072 
        | crypto_tee_vendor::types::Algorithm::Rsa4096 => Some(SignatureAlgorithm::RsaPssSha256),
        _ => None,
    }
}