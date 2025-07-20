//! RFC 9421 HTTP Message Signatures implementation
//! 
//! This crate provides the message signing layer (L4) that implements
//! RFC 9421 HTTP Message Signatures using keys from CryptoTEE.

pub fn rfc9421_version() -> &'static str {
    "draft-ietf-httpbis-message-signatures-19"
}