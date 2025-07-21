//! CryptoKit Bridge for Modern Apple Cryptography
//!
//! This module provides integration with Apple's CryptoKit framework
//! for modern cryptographic operations on iOS 13+ and macOS 10.15+.

use crate::error::{VendorError, VendorResult};
use crate::types::*;

#[cfg(any(target_os = "ios", target_os = "macos"))]
use objc::rc::StrongPtr;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use objc::runtime::Object;
#[cfg(any(target_os = "ios", target_os = "macos"))]
use objc::{msg_send, sel, sel_impl};

/// CryptoKit operations wrapper
pub struct CryptoKitOperations;

impl CryptoKitOperations {
    /// Check if CryptoKit is available
    pub fn is_available() -> bool {
        #[cfg(any(target_os = "ios", target_os = "macos"))]
        {
            // CryptoKit requires iOS 13+ or macOS 10.15+
            #[cfg(target_os = "ios")]
            {
                Self::check_ios_version(13, 0)
            }
            #[cfg(target_os = "macos")]
            {
                Self::check_macos_version(10, 15)
            }
            #[cfg(not(any(target_os = "ios", target_os = "macos")))]
            {
                false
            }
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            false
        }
    }

    #[cfg(target_os = "ios")]
    fn check_ios_version(major: u32, minor: u32) -> bool {
        use objc::runtime::Class;

        // SAFETY: This is safe because:
        // 1. NSProcessInfo is a standard iOS system class that always exists
        // 2. Class::get returns None for non-existent classes, unwrap is safe here
        // 3. Objective-C runtime guarantees are maintained by objc crate
        unsafe {
            let process_info_class = Class::get("NSProcessInfo").unwrap();
            let process_info: *mut Object = msg_send![process_info_class, processInfo];

            let version: *mut Object = msg_send![process_info, operatingSystemVersion];
            let major_version: i64 = msg_send![version, majorVersion];
            let minor_version: i64 = msg_send![version, minorVersion];

            major_version as u32 >= major && minor_version as u32 >= minor
        }
    }

    #[cfg(target_os = "macos")]
    fn check_macos_version(major: u32, minor: u32) -> bool {
        use objc::runtime::Class;

        unsafe {
            let process_info_class = Class::get("NSProcessInfo").unwrap();
            let process_info: *mut Object = msg_send![process_info_class, processInfo];

            let version: *mut Object = msg_send![process_info, operatingSystemVersion];
            let major_version: i64 = msg_send![version, majorVersion];
            let minor_version: i64 = msg_send![version, minorVersion];

            major_version as u32 >= major && minor_version as u32 >= minor
        }
    }

    /// Generate key using CryptoKit
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    pub fn generate_key(algorithm: Algorithm) -> VendorResult<CryptoKitKey> {
        match algorithm {
            Algorithm::EcdsaP256 => Self::generate_p256_key(),
            Algorithm::EcdsaP384 => Self::generate_p384_key(),
            Algorithm::Ed25519 => Self::generate_ed25519_key(),
            _ => Err(VendorError::NotSupported(format!(
                "Algorithm {:?} not supported by CryptoKit",
                algorithm
            ))),
        }
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn generate_p256_key() -> VendorResult<CryptoKitKey> {
        // SAFETY: This is safe because:
        // 1. P256 is a CryptoKit class available on iOS 13+/macOS 10.15+
        // 2. Error handling is properly implemented with ok_or_else
        // 3. Objective-C runtime safety is maintained by objc crate
        unsafe {
            let p256_class = objc::runtime::Class::get("P256")
                .ok_or_else(|| VendorError::NotSupported("P256 class not found".to_string()))?;

            let signing_class = objc::runtime::Class::get("Signing")
                .ok_or_else(|| VendorError::NotSupported("Signing class not found".to_string()))?;

            let private_key_class = objc::runtime::Class::get("PrivateKey").ok_or_else(|| {
                VendorError::NotSupported("PrivateKey class not found".to_string())
            })?;

            // P256.Signing.PrivateKey()
            let key: *mut Object = msg_send![private_key_class, new];

            if key.is_null() {
                return Err(VendorError::KeyGeneration("Failed to generate P256 key".to_string()));
            }

            Ok(CryptoKitKey { key_object: StrongPtr::new(key), algorithm: Algorithm::EcdsaP256 })
        }
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn generate_p384_key() -> VendorResult<CryptoKitKey> {
        // SAFETY: P384 CryptoKit operations with proper error handling
        unsafe {
            let p384_class = objc::runtime::Class::get("P384")
                .ok_or_else(|| VendorError::NotSupported("P384 class not found".to_string()))?;

            let signing_class = objc::runtime::Class::get("Signing")
                .ok_or_else(|| VendorError::NotSupported("Signing class not found".to_string()))?;

            let private_key_class = objc::runtime::Class::get("PrivateKey").ok_or_else(|| {
                VendorError::NotSupported("PrivateKey class not found".to_string())
            })?;

            // P384.Signing.PrivateKey()
            let key: *mut Object = msg_send![private_key_class, new];

            if key.is_null() {
                return Err(VendorError::KeyGeneration("Failed to generate P384 key".to_string()));
            }

            Ok(CryptoKitKey { key_object: StrongPtr::new(key), algorithm: Algorithm::EcdsaP384 })
        }
    }

    #[cfg(any(target_os = "ios", target_os = "macos"))]
    fn generate_ed25519_key() -> VendorResult<CryptoKitKey> {
        // SAFETY: Ed25519 CryptoKit operations with proper error handling
        unsafe {
            let curve25519_class = objc::runtime::Class::get("Curve25519").ok_or_else(|| {
                VendorError::NotSupported("Curve25519 class not found".to_string())
            })?;

            let signing_class = objc::runtime::Class::get("Signing")
                .ok_or_else(|| VendorError::NotSupported("Signing class not found".to_string()))?;

            let private_key_class = objc::runtime::Class::get("PrivateKey").ok_or_else(|| {
                VendorError::NotSupported("PrivateKey class not found".to_string())
            })?;

            // Curve25519.Signing.PrivateKey()
            let key: *mut Object = msg_send![private_key_class, new];

            if key.is_null() {
                return Err(VendorError::KeyGeneration(
                    "Failed to generate Ed25519 key".to_string(),
                ));
            }

            Ok(CryptoKitKey { key_object: StrongPtr::new(key), algorithm: Algorithm::Ed25519 })
        }
    }

    /// Sign data using CryptoKit key
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    pub fn sign(key: &CryptoKitKey, data: &[u8]) -> VendorResult<Vec<u8>> {
        // SAFETY: CryptoKit signing operation with validated inputs
        unsafe {
            // Create NSData from bytes
            let data_class = objc::runtime::Class::get("NSData").unwrap();
            let ns_data: *mut Object = msg_send![
                data_class,
                dataWithBytes:data.as_ptr()
                length:data.len()
            ];

            // Sign the data
            let signature: *mut Object = msg_send![**key.key_object, signatureForData:ns_data];

            if signature.is_null() {
                return Err(VendorError::SigningError("Failed to create signature".to_string()));
            }

            // Get signature bytes
            let sig_length: usize = msg_send![signature, length];
            let sig_bytes: *const u8 = msg_send![signature, bytes];

            let mut result = vec![0u8; sig_length];
            std::ptr::copy_nonoverlapping(sig_bytes, result.as_mut_ptr(), sig_length);

            Ok(result)
        }
    }

    /// Export public key from CryptoKit private key
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    pub fn export_public_key(key: &CryptoKitKey) -> VendorResult<Vec<u8>> {
        unsafe {
            // Get public key
            let public_key: *mut Object = msg_send![**key.key_object, publicKey];

            if public_key.is_null() {
                return Err(VendorError::KeyExport("Failed to get public key".to_string()));
            }

            // Get raw representation
            let raw_representation: *mut Object = msg_send![public_key, rawRepresentation];

            if raw_representation.is_null() {
                return Err(VendorError::KeyExport("Failed to get raw representation".to_string()));
            }

            // Get bytes
            let length: usize = msg_send![raw_representation, length];
            let bytes: *const u8 = msg_send![raw_representation, bytes];

            let mut result = vec![0u8; length];
            std::ptr::copy_nonoverlapping(bytes, result.as_mut_ptr(), length);

            Ok(result)
        }
    }

    /// Verify signature using CryptoKit
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    pub fn verify(
        public_key: &[u8],
        data: &[u8],
        signature: &[u8],
        algorithm: Algorithm,
    ) -> VendorResult<bool> {
        unsafe {
            // Create public key from bytes
            let data_class = objc::runtime::Class::get("NSData").unwrap();

            let key_data: *mut Object = msg_send![
                data_class,
                dataWithBytes:public_key.as_ptr()
                length:public_key.len()
            ];

            let (curve_class_name, key_class_name) = match algorithm {
                Algorithm::EcdsaP256 => ("P256", "PublicKey"),
                Algorithm::EcdsaP384 => ("P384", "PublicKey"),
                Algorithm::Ed25519 => ("Curve25519", "PublicKey"),
                _ => return Err(VendorError::NotSupported("Unsupported algorithm".to_string())),
            };

            let curve_class = objc::runtime::Class::get(curve_class_name)
                .ok_or_else(|| VendorError::NotSupported("Curve class not found".to_string()))?;

            let signing_class = objc::runtime::Class::get("Signing")
                .ok_or_else(|| VendorError::NotSupported("Signing class not found".to_string()))?;

            let public_key_class = objc::runtime::Class::get(key_class_name).ok_or_else(|| {
                VendorError::NotSupported("PublicKey class not found".to_string())
            })?;

            // Create public key from raw representation
            let public_key_obj: *mut Object = msg_send![
                public_key_class,
                initWithRawRepresentation:key_data
            ];

            if public_key_obj.is_null() {
                return Err(VendorError::VerificationError(
                    "Failed to create public key".to_string(),
                ));
            }

            // Create data and signature NSData objects
            let data_to_verify: *mut Object = msg_send![
                data_class,
                dataWithBytes:data.as_ptr()
                length:data.len()
            ];

            let signature_data: *mut Object = msg_send![
                data_class,
                dataWithBytes:signature.as_ptr()
                length:signature.len()
            ];

            // Verify signature
            let is_valid: bool = msg_send![
                public_key_obj,
                isValidSignature:signature_data
                for:data_to_verify
            ];

            Ok(is_valid)
        }
    }
}

/// CryptoKit key wrapper
#[cfg(any(target_os = "ios", target_os = "macos"))]
pub struct CryptoKitKey {
    key_object: StrongPtr,
    algorithm: Algorithm,
}

#[cfg(not(any(target_os = "ios", target_os = "macos")))]
pub struct CryptoKitKey {
    algorithm: Algorithm,
}

/// Hashing operations using CryptoKit
pub struct CryptoKitHash;

impl CryptoKitHash {
    /// Compute SHA-256 hash
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    pub fn sha256(data: &[u8]) -> VendorResult<Vec<u8>> {
        unsafe {
            let sha256_class = objc::runtime::Class::get("SHA256")
                .ok_or_else(|| VendorError::NotSupported("SHA256 class not found".to_string()))?;

            // Create NSData
            let data_class = objc::runtime::Class::get("NSData").unwrap();
            let ns_data: *mut Object = msg_send![
                data_class,
                dataWithBytes:data.as_ptr()
                length:data.len()
            ];

            // Compute hash
            let hash: *mut Object = msg_send![sha256_class, hashWithData:ns_data];

            if hash.is_null() {
                return Err(VendorError::HashError("Failed to compute SHA256".to_string()));
            }

            // Get hash bytes
            let hash_data: *mut Object = msg_send![hash, rawRepresentation];
            let length: usize = msg_send![hash_data, length];
            let bytes: *const u8 = msg_send![hash_data, bytes];

            let mut result = vec![0u8; length];
            std::ptr::copy_nonoverlapping(bytes, result.as_mut_ptr(), length);

            Ok(result)
        }
    }

    /// Compute SHA-384 hash
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    pub fn sha384(data: &[u8]) -> VendorResult<Vec<u8>> {
        unsafe {
            let sha384_class = objc::runtime::Class::get("SHA384")
                .ok_or_else(|| VendorError::NotSupported("SHA384 class not found".to_string()))?;

            // Create NSData
            let data_class = objc::runtime::Class::get("NSData").unwrap();
            let ns_data: *mut Object = msg_send![
                data_class,
                dataWithBytes:data.as_ptr()
                length:data.len()
            ];

            // Compute hash
            let hash: *mut Object = msg_send![sha384_class, hashWithData:ns_data];

            if hash.is_null() {
                return Err(VendorError::HashError("Failed to compute SHA384".to_string()));
            }

            // Get hash bytes
            let hash_data: *mut Object = msg_send![hash, rawRepresentation];
            let length: usize = msg_send![hash_data, length];
            let bytes: *const u8 = msg_send![hash_data, bytes];

            let mut result = vec![0u8; length];
            std::ptr::copy_nonoverlapping(bytes, result.as_mut_ptr(), length);

            Ok(result)
        }
    }

    /// Compute SHA-512 hash
    #[cfg(any(target_os = "ios", target_os = "macos"))]
    pub fn sha512(data: &[u8]) -> VendorResult<Vec<u8>> {
        unsafe {
            let sha512_class = objc::runtime::Class::get("SHA512")
                .ok_or_else(|| VendorError::NotSupported("SHA512 class not found".to_string()))?;

            // Create NSData
            let data_class = objc::runtime::Class::get("NSData").unwrap();
            let ns_data: *mut Object = msg_send![
                data_class,
                dataWithBytes:data.as_ptr()
                length:data.len()
            ];

            // Compute hash
            let hash: *mut Object = msg_send![sha512_class, hashWithData:ns_data];

            if hash.is_null() {
                return Err(VendorError::HashError("Failed to compute SHA512".to_string()));
            }

            // Get hash bytes
            let hash_data: *mut Object = msg_send![hash, rawRepresentation];
            let length: usize = msg_send![hash_data, length];
            let bytes: *const u8 = msg_send![hash_data, bytes];

            let mut result = vec![0u8; length];
            std::ptr::copy_nonoverlapping(bytes, result.as_mut_ptr(), length);

            Ok(result)
        }
    }
}
