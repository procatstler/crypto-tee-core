//! Key lifecycle management

use std::collections::HashMap;

use crate::{
    error::{CryptoTEEError, CryptoTEEResult},
    types::{KeyHandle, KeyInfo},
};

/// Key manager for tracking and managing keys
pub struct KeyManager {
    keys: HashMap<String, KeyHandle>,
}

impl KeyManager {
    pub fn new() -> Self {
        Self { keys: HashMap::new() }
    }

    pub fn add_key(&mut self, alias: &str, handle: KeyHandle) -> CryptoTEEResult<()> {
        if self.keys.contains_key(alias) {
            return Err(CryptoTEEError::InvalidKeyAlias(format!("Key '{}' already exists", alias)));
        }
        self.keys.insert(alias.to_string(), handle);
        Ok(())
    }

    pub fn get_key(&self, alias: &str) -> CryptoTEEResult<&KeyHandle> {
        self.keys.get(alias).ok_or_else(|| CryptoTEEError::KeyNotFound(alias.to_string()))
    }

    pub fn get_key_mut(&mut self, alias: &str) -> CryptoTEEResult<&mut KeyHandle> {
        self.keys.get_mut(alias).ok_or_else(|| CryptoTEEError::KeyNotFound(alias.to_string()))
    }

    pub fn remove_key(&mut self, alias: &str) -> CryptoTEEResult<KeyHandle> {
        self.keys.remove(alias).ok_or_else(|| CryptoTEEError::KeyNotFound(alias.to_string()))
    }

    pub fn exists(&self, alias: &str) -> bool {
        self.keys.contains_key(alias)
    }

    pub fn list_keys(&self) -> Vec<KeyInfo> {
        self.keys
            .values()
            .map(|handle| KeyInfo {
                alias: handle.alias.clone(),
                algorithm: handle.metadata.algorithm,
                created_at: handle.metadata.created_at,
                hardware_backed: handle.metadata.hardware_backed,
                requires_auth: handle.platform_handle.requires_auth,
            })
            .collect()
    }

    pub fn count(&self) -> usize {
        self.keys.len()
    }
}

impl Default for KeyManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_tee_platform::traits::PlatformKeyHandle;
    use crypto_tee_vendor::types::{Algorithm, VendorKeyHandle};

    fn create_test_handle(alias: &str) -> KeyHandle {
        KeyHandle {
            alias: alias.to_string(),
            platform_handle: PlatformKeyHandle {
                vendor_handle: VendorKeyHandle {
                    id: format!("test-{}", alias),
                    algorithm: Algorithm::Ed25519,
                    vendor: "test".to_string(),
                    hardware_backed: false,
                    vendor_data: None,
                },
                platform: "test".to_string(),
                requires_auth: false,
                created_at: std::time::SystemTime::now(),
                last_used: None,
                metadata: None,
            },
            metadata: crate::types::KeyMetadata {
                algorithm: Algorithm::Ed25519,
                created_at: std::time::SystemTime::now(),
                last_used: None,
                usage_count: 0,
                hardware_backed: false,
                custom: None,
            },
        }
    }

    #[test]
    fn test_key_manager_operations() {
        let mut manager = KeyManager::new();

        // Add key
        let handle = create_test_handle("test-key");
        manager.add_key("test-key", handle).unwrap();
        assert!(manager.exists("test-key"));
        assert_eq!(manager.count(), 1);

        // Get key
        let retrieved = manager.get_key("test-key").unwrap();
        assert_eq!(retrieved.alias, "test-key");

        // List keys
        let keys = manager.list_keys();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].alias, "test-key");

        // Remove key
        let removed = manager.remove_key("test-key").unwrap();
        assert_eq!(removed.alias, "test-key");
        assert!(!manager.exists("test-key"));
        assert_eq!(manager.count(), 0);
    }

    #[test]
    fn test_key_manager_errors() {
        let mut manager = KeyManager::new();

        // Get non-existent key
        assert!(manager.get_key("missing").is_err());

        // Add duplicate key
        let handle = create_test_handle("test-key");
        manager.add_key("test-key", handle.clone()).unwrap();
        assert!(manager.add_key("test-key", handle).is_err());

        // Remove non-existent key
        assert!(manager.remove_key("missing").is_err());
    }
}
