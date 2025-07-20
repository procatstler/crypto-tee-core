//! RFC 9421 adapter implementation

use std::sync::Arc;
use crypto_tee::{CryptoTEE, CryptoTEEBuilder};
use tracing::{debug, info};
use base64::prelude::*;

use crate::{
    error::{Rfc9421Error, Rfc9421Result},
    types::*,
};

/// RFC 9421 HTTP Message Signatures adapter
pub struct Rfc9421Adapter {
    crypto_tee: Arc<dyn CryptoTEE>,
}

impl Rfc9421Adapter {
    /// Create a new RFC 9421 adapter
    pub async fn new() -> Rfc9421Result<Self> {
        let crypto_tee = CryptoTEEBuilder::new()
            .build()
            .await
            .map_err(|e| Rfc9421Error::CryptoTEEError(e))?;
        
        Ok(Self {
            crypto_tee: Arc::new(crypto_tee),
        })
    }

    /// Create adapter with existing CryptoTEE instance
    pub fn with_crypto_tee(crypto_tee: Arc<dyn CryptoTEE>) -> Self {
        Self { crypto_tee }
    }

    /// Sign an HTTP message according to RFC 9421
    pub async fn sign_message(
        &self,
        message: &HttpMessage,
        params: SignatureParams,
    ) -> Rfc9421Result<SignatureOutput> {
        info!("Signing HTTP message with key: [REDACTED]");

        // Build signature base
        let signature_base = self.build_signature_base(message, &params)?;
        debug!("Signature base generated ({} bytes)", signature_base.len());

        // Sign with CryptoTEE
        let signature_bytes = self.crypto_tee
            .sign(&params.key_id, signature_base.as_bytes(), None)
            .await
            .map_err(|e| Rfc9421Error::CryptoTEEError(e))?;

        // Encode signature
        let signature = base64::prelude::BASE64_STANDARD.encode(&signature_bytes);

        Ok(SignatureOutput {
            signature,
            signature_input: signature_base,
            params,
        })
    }

    /// Verify an HTTP message signature
    pub async fn verify_message(
        &self,
        message: &HttpMessage,
        signature: &str,
        params: &SignatureParams,
    ) -> Rfc9421Result<VerificationResult> {
        info!("Verifying HTTP message signature with key: {}", params.key_id);

        // Build signature base
        let signature_base = self.build_signature_base(message, params)?;

        // Decode signature
        let signature_bytes = base64::prelude::BASE64_STANDARD.decode(signature)
            .map_err(|e| Rfc9421Error::InvalidParameters(format!("Invalid base64: {}", e)))?;

        // Verify with CryptoTEE
        let valid = self.crypto_tee
            .verify(&params.key_id, signature_base.as_bytes(), &signature_bytes, None)
            .await
            .map_err(|e| Rfc9421Error::CryptoTEEError(e))?;

        Ok(VerificationResult {
            valid,
            key_id: params.key_id.clone(),
            algorithm: params.algorithm,
            created: params.created,
            expires: params.expires,
        })
    }

    /// Bridge to sage-core for advanced operations
    pub async fn sign_with_sage(
        &self,
        message: &HttpMessage,
        params: SignatureParams,
    ) -> Rfc9421Result<SignatureOutput> {
        info!("Using sage-core for RFC 9421 signing");

        // Get key info from CryptoTEE
        let _key_info = self.crypto_tee
            .get_key_info(&params.key_id)
            .await
            .map_err(|e| Rfc9421Error::CryptoTEEError(e))?;

        // For future sage-core integration - currently commented out
        /*
        let key_type = match key_info.algorithm {
            crypto_tee_vendor::types::Algorithm::Ed25519 => KeyType::Ed25519,
            crypto_tee_vendor::types::Algorithm::EcdsaP256 => {
                warn!("sage-core doesn't support P-256, falling back to regular signing");
                return self.sign_message(message, params).await;
            },
            _ => {
                return Err(Rfc9421Error::UnsupportedAlgorithm(
                    format!("{:?} not supported by sage-core", key_info.algorithm)
                ));
            }
        };
        */

        // For now, we'll use CryptoTEE's signing since sage-core would need
        // access to the raw private key, which defeats the purpose of TEE
        self.sign_message(message, params).await
    }

    /// Build the signature base string according to RFC 9421
    fn build_signature_base(
        &self,
        message: &HttpMessage,
        params: &SignatureParams,
    ) -> Rfc9421Result<String> {
        let mut lines = Vec::new();

        // Process each covered component
        for component in &params.covered_components {
            let line = self.format_component(message, component)?;
            lines.push(line);
        }

        // Add signature parameters
        let sig_params = self.format_signature_params(params)?;
        lines.push(format!("\"@signature-params\": {}", sig_params));

        Ok(lines.join("\n"))
    }

    /// Format a single component for the signature base
    fn format_component(
        &self,
        message: &HttpMessage,
        component: &SignatureComponent,
    ) -> Rfc9421Result<String> {
        match component {
            SignatureComponent::Method => {
                let method = message.method.as_ref()
                    .ok_or_else(|| Rfc9421Error::InvalidMessage("Missing method".to_string()))?;
                Ok(format!("\"@method\": {}", method.to_uppercase()))
            },
            SignatureComponent::TargetUri => {
                let uri = message.uri.as_ref()
                    .ok_or_else(|| Rfc9421Error::InvalidMessage("Missing URI".to_string()))?;
                Ok(format!("\"@target-uri\": {}", uri))
            },
            SignatureComponent::Authority => {
                let uri = message.uri.as_ref()
                    .ok_or_else(|| Rfc9421Error::InvalidMessage("Missing URI".to_string()))?;
                let url = url::Url::parse(uri)
                    .map_err(|e| Rfc9421Error::InvalidMessage(format!("Invalid URI: {}", e)))?;
                let authority = url.host_str()
                    .ok_or_else(|| Rfc9421Error::InvalidMessage("Missing host".to_string()))?;
                Ok(format!("\"@authority\": {}", authority))
            },
            SignatureComponent::Path => {
                let uri = message.uri.as_ref()
                    .ok_or_else(|| Rfc9421Error::InvalidMessage("Missing URI".to_string()))?;
                let url = url::Url::parse(uri)
                    .map_err(|e| Rfc9421Error::InvalidMessage(format!("Invalid URI: {}", e)))?;
                Ok(format!("\"@path\": {}", url.path()))
            },
            SignatureComponent::Status => {
                let status = message.status
                    .ok_or_else(|| Rfc9421Error::InvalidMessage("Missing status".to_string()))?;
                Ok(format!("\"@status\": {}", status))
            },
            SignatureComponent::Header(name) => {
                let values = message.headers.get(name)
                    .ok_or_else(|| Rfc9421Error::InvalidMessage(format!("Missing header: {}", name)))?;
                let value = values.join(", ");
                Ok(format!("\"{}\": {}", name.to_lowercase(), value))
            },
            _ => Err(Rfc9421Error::InvalidParameters(
                format!("Component {:?} not implemented", component)
            )),
        }
    }

    /// Format signature parameters
    fn format_signature_params(&self, params: &SignatureParams) -> Rfc9421Result<String> {
        let mut parts = Vec::new();

        // Covered components
        let components: Vec<String> = params.covered_components.iter()
            .map(|c| match c {
                SignatureComponent::Method => "\"@method\"".to_string(),
                SignatureComponent::TargetUri => "\"@target-uri\"".to_string(),
                SignatureComponent::Authority => "\"@authority\"".to_string(),
                SignatureComponent::Path => "\"@path\"".to_string(),
                SignatureComponent::Status => "\"@status\"".to_string(),
                SignatureComponent::Header(name) => format!("\"{}\"", name.to_lowercase()),
                _ => format!("{:?}", c),
            })
            .collect();
        parts.push(format!("({})", components.join(" ")));

        // Created timestamp
        if let Some(created) = params.created {
            parts.push(format!("created={}", created.timestamp()));
        }

        // Expires timestamp
        if let Some(expires) = params.expires {
            parts.push(format!("expires={}", expires.timestamp()));
        }

        // Nonce
        if let Some(nonce) = &params.nonce {
            parts.push(format!("nonce=\"{}\"", nonce));
        }

        // Algorithm
        parts.push(format!("alg=\"{}\"", params.algorithm.identifier()));

        // Key ID
        parts.push(format!("keyid=\"{}\"", params.key_id));

        Ok(parts.join(";"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_signature_base_construction() {
        let message = HttpMessage {
            method: Some("POST".to_string()),
            uri: Some("https://example.com/api/test".to_string()),
            status: None,
            headers: {
                let mut h = HashMap::new();
                h.insert("content-type".to_string(), vec!["application/json".to_string()]);
                h
            },
            body: None,
        };

        let params = SignatureInputBuilder::new(
            "test-key".to_string(),
            SignatureAlgorithm::Ed25519,
        )
        .add_component(SignatureComponent::Method)
        .add_component(SignatureComponent::Path)
        .add_component(SignatureComponent::Header("content-type".to_string()))
        .created(Utc::now())
        .build();

        // This test would need a mock CryptoTEE implementation
        // For now, we're just testing that the code compiles
    }
}