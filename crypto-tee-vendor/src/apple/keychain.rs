//! macOS/iOS Keychain Integration
//! 
//! This module provides integration with the Apple Keychain Services
//! for secure key storage and management.

use crate::error::{VendorError, VendorResult};
use crate::types::*;
use core_foundation::{
    base::{CFType, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::{CFDictionary, CFMutableDictionary},
    number::CFNumber,
    string::CFString,
};
use security_framework::{
    access_control::{SecAccessControl, SecAccessControlCreateFlags},
    item::{ItemClass, ItemSearchOptions, Limit, Reference, SearchResult},
    key::{SecKey, KeyClass},
    os::macos::keychain::SecKeychain,
};
use std::collections::HashMap;

/// Keychain attribute keys
mod attributes {
    use core_foundation::string::CFString;
    
    pub fn class() -> CFString { CFString::from_static_string("class") }
    pub fn label() -> CFString { CFString::from_static_string("labl") }
    pub fn application_tag() -> CFString { CFString::from_static_string("atag") }
    pub fn key_type() -> CFString { CFString::from_static_string("type") }
    pub fn key_size_in_bits() -> CFString { CFString::from_static_string("bsiz") }
    pub fn token_id() -> CFString { CFString::from_static_string("tkid") }
    pub fn access_control() -> CFString { CFString::from_static_string("accc") }
    pub fn access_group() -> CFString { CFString::from_static_string("agrp") }
    pub fn is_permanent() -> CFString { CFString::from_static_string("perm") }
    pub fn application_label() -> CFString { CFString::from_static_string("albl") }
}

/// Keychain key types
mod key_types {
    use core_foundation::string::CFString;
    
    pub fn ec() -> CFString { CFString::from_static_string("73") } // kSecAttrKeyTypeEC
    pub fn ec_secure_enclave() -> CFString { CFString::from_static_string("73") }
    pub fn rsa() -> CFString { CFString::from_static_string("42") } // kSecAttrKeyTypeRSA
}

/// Token IDs
mod tokens {
    use core_foundation::string::CFString;
    
    pub fn secure_enclave() -> CFString { 
        CFString::from_static_string("com.apple.setoken")
    }
}

/// Keychain operations wrapper
pub struct KeychainOperations;

impl KeychainOperations {
    /// Create access control for Secure Enclave key
    pub fn create_access_control(
        params: &super::SecureEnclaveParams,
    ) -> VendorResult<SecAccessControl> {
        let mut flags = SecAccessControlCreateFlags::PRIVATE_KEY_USAGE;
        
        if let Some(ref access_control) = params.access_control {
            if access_control.user_presence {
                flags |= SecAccessControlCreateFlags::USER_PRESENCE;
            }
            
            if access_control.biometry_any {
                flags |= SecAccessControlCreateFlags::BIOMETRY_ANY;
            }
            
            if access_control.biometry_current_set {
                flags |= SecAccessControlCreateFlags::BIOMETRY_CURRENT_SET;
            }
            
            if access_control.device_passcode {
                flags |= SecAccessControlCreateFlags::DEVICE_PASSCODE;
            }
        }
        
        SecAccessControl::create_with_flags(flags)
            .map_err(|e| VendorError::KeyGeneration(format!("Failed to create access control: {:?}", e)))
    }

    /// Generate key in Secure Enclave
    pub fn generate_secure_enclave_key(
        algorithm: Algorithm,
        params: &super::SecureEnclaveParams,
    ) -> VendorResult<(SecKey, String)> {
        let key_size = match algorithm {
            Algorithm::EcdsaP256 => 256,
            Algorithm::EcdsaP384 => 384,
            _ => return Err(VendorError::NotSupported(
                format!("Algorithm {:?} not supported by Secure Enclave", algorithm)
            )),
        };
        
        let mut attributes = CFMutableDictionary::new();
        
        // Key type and size
        attributes.set(attributes::key_type(), key_types::ec());
        attributes.set(attributes::key_size_in_bits(), CFNumber::from(key_size as i32));
        
        // Secure Enclave token
        attributes.set(attributes::token_id(), tokens::secure_enclave());
        
        // Access control
        let access_control = Self::create_access_control(params)?;
        attributes.set(attributes::access_control(), access_control);
        
        // Keychain attributes
        if let Some(ref label) = params.label {
            attributes.set(attributes::label(), CFString::new(label));
        }
        
        if let Some(ref tag) = params.application_tag {
            attributes.set(attributes::application_tag(), CFData::from_buffer(tag));
        }
        
        if let Some(ref group) = params.access_group {
            attributes.set(attributes::access_group(), CFString::new(group));
        }
        
        // Make key permanent in keychain
        attributes.set(attributes::is_permanent(), CFBoolean::true_value());
        
        // Generate unique key ID
        let key_id = format!("se_key_{}", uuid::Uuid::new_v4());
        attributes.set(attributes::application_label(), CFString::new(&key_id));
        
        // Generate the key
        let key = SecKey::generate(attributes.as_concrete_TypeRef())
            .map_err(|e| VendorError::KeyGeneration(format!("Failed to generate key: {:?}", e)))?;
        
        Ok((key, key_id))
    }

    /// Store key reference in keychain
    pub fn store_key_reference(
        key: &SecKey,
        key_id: &str,
        params: &super::SecureEnclaveParams,
    ) -> VendorResult<()> {
        let mut query = CFMutableDictionary::new();
        
        // Item class
        query.set(
            CFString::from_static_string("class"),
            CFString::from_static_string("keys")
        );
        
        // Key reference
        query.set(
            CFString::from_static_string("vref"),
            key.as_CFTypeRef()
        );
        
        // Attributes
        let mut attributes = CFMutableDictionary::new();
        
        if let Some(ref label) = params.label {
            attributes.set(attributes::label(), CFString::new(label));
        }
        
        attributes.set(attributes::application_label(), CFString::new(key_id));
        
        if let Some(ref tag) = params.application_tag {
            attributes.set(attributes::application_tag(), CFData::from_buffer(tag));
        }
        
        if let Some(ref group) = params.access_group {
            attributes.set(attributes::access_group(), CFString::new(group));
        }
        
        query.set(CFString::from_static_string("attrs"), attributes);
        
        // Add to keychain
        let status = unsafe {
            security_framework_sys::keychain_item::SecItemAdd(
                query.as_concrete_TypeRef(),
                std::ptr::null_mut()
            )
        };
        
        if status != 0 {
            return Err(VendorError::KeyGeneration(
                format!("Failed to store key in keychain: {}", status)
            ));
        }
        
        Ok(())
    }

    /// Find key in keychain
    pub fn find_key(key_id: &str) -> VendorResult<SecKey> {
        let mut query = CFMutableDictionary::new();
        
        // Search for keys
        query.set(
            CFString::from_static_string("class"),
            CFString::from_static_string("keys")
        );
        
        // Match by application label (our key ID)
        query.set(attributes::application_label(), CFString::new(key_id));
        
        // Return reference
        query.set(
            CFString::from_static_string("r_ref"),
            CFBoolean::true_value()
        );
        
        // Limit to one result
        query.set(
            CFString::from_static_string("m_Limit"),
            CFString::from_static_string("m_LimitOne")
        );
        
        // Search
        let mut result: *mut core_foundation::base::CFTypeRef = std::ptr::null_mut();
        let status = unsafe {
            security_framework_sys::keychain_item::SecItemCopyMatching(
                query.as_concrete_TypeRef(),
                &mut result
            )
        };
        
        if status != 0 {
            return Err(VendorError::KeyNotFound(
                format!("Key not found: {}", key_id)
            ));
        }
        
        // Convert result to SecKey
        let key = unsafe {
            SecKey::wrap_under_create_rule(result as security_framework_sys::key::SecKeyRef)
        };
        
        Ok(key)
    }

    /// Delete key from keychain
    pub fn delete_key(key_id: &str) -> VendorResult<()> {
        let mut query = CFMutableDictionary::new();
        
        // Search for keys
        query.set(
            CFString::from_static_string("class"),
            CFString::from_static_string("keys")
        );
        
        // Match by application label
        query.set(attributes::application_label(), CFString::new(key_id));
        
        // Delete
        let status = unsafe {
            security_framework_sys::keychain_item::SecItemDelete(
                query.as_concrete_TypeRef()
            )
        };
        
        if status != 0 && status != -25300 { // -25300 = item not found
            return Err(VendorError::KeyDeletion(
                format!("Failed to delete key: {}", status)
            ));
        }
        
        Ok(())
    }

    /// List all keys
    pub fn list_keys(access_group: Option<&str>) -> VendorResult<Vec<String>> {
        let mut query = CFMutableDictionary::new();
        
        // Search for keys
        query.set(
            CFString::from_static_string("class"),
            CFString::from_static_string("keys")
        );
        
        // Filter by access group if specified
        if let Some(group) = access_group {
            query.set(attributes::access_group(), CFString::new(group));
        }
        
        // Return attributes
        query.set(
            CFString::from_static_string("r_Attributes"),
            CFBoolean::true_value()
        );
        
        // Return all matches
        query.set(
            CFString::from_static_string("m_Limit"),
            CFString::from_static_string("m_LimitAll")
        );
        
        // Search
        let mut result: *mut core_foundation::base::CFTypeRef = std::ptr::null_mut();
        let status = unsafe {
            security_framework_sys::keychain_item::SecItemCopyMatching(
                query.as_concrete_TypeRef(),
                &mut result
            )
        };
        
        if status == -25300 { // No items found
            return Ok(Vec::new());
        }
        
        if status != 0 {
            return Err(VendorError::KeyListing(
                format!("Failed to list keys: {}", status)
            ));
        }
        
        // Parse results
        let mut key_ids = Vec::new();
        
        // Result should be CFArray of CFDictionary
        if !result.is_null() {
            let array = unsafe {
                core_foundation::array::CFArray::<CFDictionary>::wrap_under_create_rule(
                    result as core_foundation::array::CFArrayRef
                )
            };
            
            for i in 0..array.len() {
                if let Some(dict) = array.get(i) {
                    // Extract application label (key ID)
                    if let Some(label_value) = dict.find(&attributes::application_label()) {
                        if let Ok(label) = label_value.downcast::<_, CFString>() {
                            key_ids.push(label.to_string());
                        }
                    }
                }
            }
        }
        
        Ok(key_ids)
    }

    /// Get key attributes
    pub fn get_key_attributes(key: &SecKey) -> VendorResult<HashMap<String, String>> {
        let mut attributes = HashMap::new();
        
        // Get key attributes dictionary
        let attrs_dict = key.attributes();
        
        // Extract relevant attributes
        if let Some(key_type) = attrs_dict.find(&attributes::key_type()) {
            if let Ok(s) = key_type.downcast::<_, CFString>() {
                attributes.insert("key_type".to_string(), s.to_string());
            }
        }
        
        if let Some(key_size) = attrs_dict.find(&attributes::key_size_in_bits()) {
            if let Ok(n) = key_size.downcast::<_, CFNumber>() {
                if let Some(size) = n.to_i32() {
                    attributes.insert("key_size".to_string(), size.to_string());
                }
            }
        }
        
        if let Some(token_id) = attrs_dict.find(&attributes::token_id()) {
            if let Ok(s) = token_id.downcast::<_, CFString>() {
                attributes.insert("token_id".to_string(), s.to_string());
            }
        }
        
        if let Some(label) = attrs_dict.find(&attributes::label()) {
            if let Ok(s) = label.downcast::<_, CFString>() {
                attributes.insert("label".to_string(), s.to_string());
            }
        }
        
        Ok(attributes)
    }
}