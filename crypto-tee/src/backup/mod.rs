//! Key Backup and Recovery System
//!
//! This module provides secure backup and recovery mechanisms for cryptographic keys
//! to ensure business continuity and disaster recovery capabilities.

use crate::{
    audit::{AuditEvent, AuditEventType, AuditManager},
    error::{CryptoTEEError, CryptoTEEResult},
    keys::{KeyHandle, KeyMetadata},
};
use crypto_tee_vendor::types::Algorithm;
use async_trait::async_trait;
use ring::{aead, digest, rand::SecureRandom};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod export;
pub mod recovery;
pub mod storage;

/// Backup configuration options
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Enable automatic backups
    pub auto_backup: bool,

    /// Backup interval for automatic backups
    pub backup_interval: Duration,

    /// Maximum number of backup versions to keep
    pub max_backup_versions: u32,

    /// Backup storage location
    pub backup_location: PathBuf,

    /// Enable backup encryption
    pub encryption_enabled: bool,

    /// Backup verification options
    pub verification_config: BackupVerificationConfig,

    /// Retention policy
    pub retention_policy: RetentionPolicy,
}

/// Backup verification configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupVerificationConfig {
    /// Verify backup integrity after creation
    pub verify_on_creation: bool,

    /// Periodic verification interval
    pub periodic_verification_interval: Option<Duration>,

    /// Enable checksum verification
    pub checksum_verification: bool,

    /// Enable digital signature verification
    pub signature_verification: bool,
}

/// Backup retention policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Maximum age for backups
    pub max_age: Duration,

    /// Minimum number of backups to keep
    pub min_backups: u32,

    /// Archive old backups instead of deleting
    pub archive_old_backups: bool,

    /// Archive location for old backups
    pub archive_location: Option<PathBuf>,
}

/// Backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Unique backup identifier
    pub backup_id: String,

    /// Backup creation timestamp
    pub created_at: SystemTime,

    /// Backup version number
    pub version: u32,

    /// Keys included in this backup
    pub key_count: u32,

    /// Total backup size in bytes
    pub size_bytes: u64,

    /// Backup format version
    pub format_version: String,

    /// Backup type (full, incremental, differential)
    pub backup_type: BackupType,

    /// Checksum for integrity verification
    pub checksum: Vec<u8>,

    /// Digital signature for authenticity
    pub signature: Option<Vec<u8>>,

    /// Encryption information
    pub encryption_info: Option<EncryptionInfo>,
}

/// Types of backup
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackupType {
    /// Full backup - contains all keys
    Full,

    /// Incremental backup - contains changes since last backup
    Incremental,

    /// Differential backup - contains changes since last full backup
    Differential,
}

/// Encryption information for backups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    /// Algorithm used for encryption
    pub algorithm: String,

    /// Key derivation method
    pub key_derivation: String,

    /// Salt for key derivation
    pub salt: Vec<u8>,

    /// Initialization vector/nonce
    pub iv: Vec<u8>,

    /// Additional authenticated data
    pub aad: Vec<u8>,
}

/// Backup entry containing key data
#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct BackupEntry {
    /// Key handle information
    #[zeroize(skip)]
    pub key_handle: KeyHandle,

    /// Key metadata
    #[zeroize(skip)]
    pub metadata: KeyMetadata,

    /// Encrypted key material
    pub encrypted_key_data: Vec<u8>,

    /// Entry creation timestamp
    #[zeroize(skip)]
    pub created_at: SystemTime,

    /// Entry checksum
    pub checksum: Vec<u8>,
}

/// Recovery options
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// Verify backup integrity before recovery
    pub verify_integrity: bool,

    /// Overwrite existing keys during recovery
    pub overwrite_existing: bool,

    /// Selective recovery (specific key IDs)
    pub selective_keys: Option<Vec<String>>,

    /// Recovery target location
    pub target_location: Option<PathBuf>,

    /// Enable audit logging during recovery
    pub audit_recovery: bool,
}

/// Backup and recovery manager
pub struct BackupManager {
    /// Configuration
    config: BackupConfig,

    /// Audit manager for logging operations
    audit_manager: Option<AuditManager>,

    /// Backup storage backend
    storage: Box<dyn BackupStorage>,

    /// Encryption key for backups
    encryption_key: Option<aead::LessSafeKey>,

    /// Random number generator
    rng: ring::rand::SystemRandom,
}

/// Trait for backup storage backends
#[async_trait]
pub trait BackupStorage: Send + Sync {
    /// Store a backup
    async fn store_backup(&mut self, metadata: &BackupMetadata, data: &[u8]) -> CryptoTEEResult<()>;

    /// Retrieve a backup
    async fn retrieve_backup(&self, backup_id: &str) -> CryptoTEEResult<(BackupMetadata, Vec<u8>)>;

    /// List available backups
    async fn list_backups(&self) -> CryptoTEEResult<Vec<BackupMetadata>>;

    /// Delete a backup
    async fn delete_backup(&mut self, backup_id: &str) -> CryptoTEEResult<()>;

    /// Verify backup integrity
    async fn verify_backup(&self, backup_id: &str) -> CryptoTEEResult<bool>;
}

impl BackupManager {
    /// Create a new backup manager
    pub fn new(
        config: BackupConfig,
        audit_manager: Option<AuditManager>,
        storage: Box<dyn BackupStorage>,
    ) -> CryptoTEEResult<Self> {
        let manager = Self {
            config,
            audit_manager,
            storage,
            encryption_key: None,
            rng: ring::rand::SystemRandom::new(),
        };

        Ok(manager)
    }

    /// Initialize encryption for backups
    pub async fn initialize_encryption(&mut self) -> CryptoTEEResult<()> {
        if !self.config.encryption_enabled {
            return Ok(());
        }

        // Generate backup encryption key
        let mut key_bytes = [0u8; 32];
        self.rng.fill(&mut key_bytes).map_err(|e| {
            CryptoTEEError::KeyGeneration(format!("Failed to generate backup encryption key: {e}"))
        })?;

        let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key_bytes)
            .map_err(|e| CryptoTEEError::KeyGeneration(format!("Failed to create backup key: {e}")))?;

        self.encryption_key = Some(aead::LessSafeKey::new(unbound_key));

        info!("Backup encryption initialized");
        Ok(())
    }

    /// Create a full backup of all keys
    pub async fn create_full_backup(
        &mut self,
        keys: &HashMap<String, (KeyHandle, KeyMetadata)>,
    ) -> CryptoTEEResult<String> {
        let backup_id = self.generate_backup_id();
        
        info!("Creating full backup: {}", backup_id);

        // Create backup entries
        let mut entries = Vec::new();
        for (key_id, (handle, metadata)) in keys {
            let entry = self.create_backup_entry(key_id, handle, metadata).await?;
            entries.push(entry);
        }

        // Serialize and encrypt backup data
        let backup_data = self.serialize_backup(&entries).await?;
        let encrypted_data = if self.config.encryption_enabled {
            self.encrypt_backup_data(&backup_data).await?
        } else {
            backup_data
        };

        // Calculate checksum
        let checksum = digest::digest(&digest::SHA256, &encrypted_data);

        // Create backup metadata
        let metadata = BackupMetadata {
            backup_id: backup_id.clone(),
            created_at: SystemTime::now(),
            version: 1,
            key_count: entries.len() as u32,
            size_bytes: encrypted_data.len() as u64,
            format_version: "1.0".to_string(),
            backup_type: BackupType::Full,
            checksum: checksum.as_ref().to_vec(),
            signature: None, // TODO: Implement signing
            encryption_info: if self.config.encryption_enabled {
                Some(EncryptionInfo {
                    algorithm: "ChaCha20-Poly1305".to_string(),
                    key_derivation: "Random".to_string(),
                    salt: vec![],
                    iv: vec![],
                    aad: vec![],
                })
            } else {
                None
            },
        };

        // Store backup
        self.storage.store_backup(&metadata, &encrypted_data).await?;

        // Verify backup if enabled
        if self.config.verification_config.verify_on_creation {
            if !self.verify_backup(&backup_id).await? {
                error!("Backup verification failed for {}", backup_id);
                return Err(CryptoTEEError::BackupError("Backup verification failed".to_string()));
            }
        }

        // Audit log
        if let Some(audit_manager) = &self.audit_manager {
            audit_manager
                .log_event(AuditEvent::new(
                    AuditEventType::KeyGenerated,
                    crate::audit::AuditSeverity::Info,
                    "backup_manager".to_string(),
                    Some(backup_id.clone()),
                    true,
                ))
                .await;
        }

        info!("Full backup created successfully: {}", backup_id);
        Ok(backup_id)
    }

    /// Recover keys from a backup
    pub async fn recover_from_backup(
        &mut self,
        backup_id: &str,
        options: &RecoveryOptions,
    ) -> CryptoTEEResult<Vec<KeyHandle>> {
        info!("Starting recovery from backup: {}", backup_id);

        // Verify backup integrity if requested
        if options.verify_integrity && !self.verify_backup(backup_id).await? {
            return Err(CryptoTEEError::BackupError("Backup integrity verification failed".to_string()));
        }

        // Retrieve backup
        let (metadata, encrypted_data) = self.storage.retrieve_backup(backup_id).await?;

        // Decrypt backup data
        let backup_data = if metadata.encryption_info.is_some() {
            self.decrypt_backup_data(&encrypted_data).await?
        } else {
            encrypted_data
        };

        // Deserialize backup entries
        let entries: Vec<BackupEntry> = self.deserialize_backup(&backup_data).await?;

        // Filter entries if selective recovery
        let filtered_entries: Vec<&BackupEntry> = if let Some(selective_keys) = &options.selective_keys {
            entries.iter().filter(|entry| selective_keys.contains(&entry.key_handle.id)).collect()
        } else {
            entries.iter().collect()
        };

        // Recover keys
        let mut recovered_keys = Vec::new();
        let filtered_entries_count = filtered_entries.len();
        for entry in filtered_entries {
            match self.recover_key_from_entry(entry, options).await {
                Ok(key_handle) => {
                    recovered_keys.push(key_handle);

                    // Audit log if enabled
                    if let Some(audit_manager) = &self.audit_manager {
                        if options.audit_recovery {
                            audit_manager
                                .log_event(AuditEvent::new(
                                    AuditEventType::KeyGenerated,
                                    crate::audit::AuditSeverity::Info,
                                    "backup_manager".to_string(),
                                    Some(entry.key_handle.id.clone()),
                                    true,
                                ))
                                .await;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to recover key {}: {}", entry.key_handle.id, e);

                    // Audit log failure
                    if let Some(audit_manager) = &self.audit_manager {
                        if options.audit_recovery {
                            audit_manager
                                .log_event(AuditEvent::new(
                                    AuditEventType::ErrorOccurred,
                                    crate::audit::AuditSeverity::Error,
                                    "backup_manager".to_string(),
                                    Some(entry.key_handle.id.clone()),
                                    false,
                                ))
                                .await;
                        }
                    }
                }
            }
        }

        info!("Recovery completed. Recovered {} out of {} keys", recovered_keys.len(), filtered_entries_count);

        Ok(recovered_keys)
    }

    /// List available backups
    pub async fn list_backups(&self) -> CryptoTEEResult<Vec<BackupMetadata>> {
        self.storage.list_backups().await
    }

    /// Verify backup integrity
    pub async fn verify_backup(&self, backup_id: &str) -> CryptoTEEResult<bool> {
        debug!("Verifying backup integrity: {}", backup_id);

        // Use storage backend verification
        let storage_verified = self.storage.verify_backup(backup_id).await?;

        if !storage_verified {
            return Ok(false);
        }

        // Additional checksum verification
        let (metadata, data) = self.storage.retrieve_backup(backup_id).await?;
        let calculated_checksum = digest::digest(&digest::SHA256, &data);

        let checksum_verified = calculated_checksum.as_ref() == metadata.checksum.as_slice();

        debug!("Backup verification result for {}: {}", backup_id, checksum_verified);
        Ok(checksum_verified)
    }

    /// Delete old backups according to retention policy
    pub async fn cleanup_old_backups(&mut self) -> CryptoTEEResult<u32> {
        let backups = self.storage.list_backups().await?;
        let now = SystemTime::now();
        let mut deleted_count = 0;

        // Sort backups by creation time (newest first)
        let mut sorted_backups = backups;
        sorted_backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        // Keep minimum number of backups
        let backups_to_check = if sorted_backups.len() > self.config.retention_policy.min_backups as usize {
            &sorted_backups[self.config.retention_policy.min_backups as usize..]
        } else {
            &[]
        };

        // Delete backups older than max_age
        for backup in backups_to_check {
            if let Ok(age) = now.duration_since(backup.created_at) {
                if age > self.config.retention_policy.max_age {
                    if self.config.retention_policy.archive_old_backups {
                        // TODO: Implement archiving
                        debug!("Archiving old backup: {}", backup.backup_id);
                    } else {
                        self.storage.delete_backup(&backup.backup_id).await?;
                        deleted_count += 1;
                        info!("Deleted old backup: {}", backup.backup_id);
                    }
                }
            }
        }

        if deleted_count > 0 {
            info!("Cleaned up {} old backups", deleted_count);
        }

        Ok(deleted_count)
    }

    /// Generate unique backup ID
    fn generate_backup_id(&self) -> String {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut random_bytes = [0u8; 8];
        self.rng.fill(&mut random_bytes).unwrap_or_default();

        format!("backup_{}_{:x}", timestamp, u64::from_be_bytes(random_bytes))
    }

    /// Create a backup entry for a key
    async fn create_backup_entry(
        &self,
        key_id: &str,
        handle: &KeyHandle,
        metadata: &KeyMetadata,
    ) -> CryptoTEEResult<BackupEntry> {
        // TODO: Extract actual key material (this is a placeholder)
        let key_data = b"placeholder_key_data"; // In real implementation, get from TEE

        // Encrypt key data if encryption is enabled
        let encrypted_key_data = if self.config.encryption_enabled {
            self.encrypt_key_data(key_data).await?
        } else {
            key_data.to_vec()
        };

        // Calculate checksum
        let checksum = digest::digest(&digest::SHA256, &encrypted_key_data);

        Ok(BackupEntry {
            key_handle: handle.clone(),
            metadata: metadata.clone(),
            encrypted_key_data,
            created_at: SystemTime::now(),
            checksum: checksum.as_ref().to_vec(),
        })
    }

    /// Encrypt key data
    async fn encrypt_key_data(&self, data: &[u8]) -> CryptoTEEResult<Vec<u8>> {
        if let Some(key) = &self.encryption_key {
            let mut nonce_bytes = [0u8; 12];
            self.rng.fill(&mut nonce_bytes).map_err(|e| {
                CryptoTEEError::CryptoError(format!("Failed to generate nonce: {e}"))
            })?;

            let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);
            let mut encrypted_data = data.to_vec();

            let tag = key.seal_in_place_separate_tag(nonce, aead::Aad::empty(), &mut encrypted_data)
                .map_err(|e| CryptoTEEError::CryptoError(format!("Encryption failed: {e}")))?;

            encrypted_data.extend_from_slice(tag.as_ref());
            Ok(encrypted_data)
        } else {
            Err(CryptoTEEError::ConfigurationError("Backup encryption not initialized".to_string()))
        }
    }

    /// Encrypt backup data
    async fn encrypt_backup_data(&self, data: &[u8]) -> CryptoTEEResult<Vec<u8>> {
        self.encrypt_key_data(data).await
    }

    /// Decrypt backup data
    async fn decrypt_backup_data(&self, encrypted_data: &[u8]) -> CryptoTEEResult<Vec<u8>> {
        if let Some(key) = &self.encryption_key {
            let mut nonce_bytes = [0u8; 12];
            // TODO: Extract nonce from encrypted data
            let nonce = aead::Nonce::assume_unique_for_key(nonce_bytes);

            let mut data = encrypted_data.to_vec();
            let decrypted_len = key.open_in_place(nonce, aead::Aad::empty(), &mut data)
                .map_err(|e| CryptoTEEError::CryptoError(format!("Decryption failed: {e}")))?
                .len();

            data.truncate(decrypted_len);
            Ok(data)
        } else {
            Err(CryptoTEEError::ConfigurationError("Backup encryption not initialized".to_string()))
        }
    }

    /// Serialize backup entries
    async fn serialize_backup(&self, entries: &[BackupEntry]) -> CryptoTEEResult<Vec<u8>> {
        serde_json::to_vec(entries)
            .map_err(|e| CryptoTEEError::SerializationError(format!("Failed to serialize backup: {e}")))
    }

    /// Deserialize backup entries
    async fn deserialize_backup(&self, data: &[u8]) -> CryptoTEEResult<Vec<BackupEntry>> {
        serde_json::from_slice(data)
            .map_err(|e| CryptoTEEError::SerializationError(format!("Failed to deserialize backup: {e}")))
    }

    /// Recover a key from a backup entry
    async fn recover_key_from_entry(
        &self,
        entry: &BackupEntry,
        options: &RecoveryOptions,
    ) -> CryptoTEEResult<KeyHandle> {
        // Verify entry checksum
        let calculated_checksum = digest::digest(&digest::SHA256, &entry.encrypted_key_data);
        if calculated_checksum.as_ref() != entry.checksum.as_slice() {
            return Err(CryptoTEEError::BackupError("Entry checksum verification failed".to_string()));
        }

        // Decrypt key data
        let _key_data = if self.config.encryption_enabled {
            self.decrypt_key_data(&entry.encrypted_key_data).await?
        } else {
            entry.encrypted_key_data.clone()
        };

        // TODO: Restore key to TEE (this is a placeholder)
        // In real implementation, this would restore the key to the appropriate TEE

        Ok(entry.key_handle.clone())
    }

    /// Decrypt key data
    async fn decrypt_key_data(&self, encrypted_data: &[u8]) -> CryptoTEEResult<Vec<u8>> {
        self.decrypt_backup_data(encrypted_data).await
    }
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            auto_backup: false,
            backup_interval: Duration::from_secs(3600), // 1 hour
            max_backup_versions: 5,
            backup_location: PathBuf::from("/tmp/crypto-tee-backups"),
            encryption_enabled: true,
            verification_config: BackupVerificationConfig::default(),
            retention_policy: RetentionPolicy::default(),
        }
    }
}

impl Default for BackupVerificationConfig {
    fn default() -> Self {
        Self {
            verify_on_creation: true,
            periodic_verification_interval: Some(Duration::from_secs(86400)), // 24 hours
            checksum_verification: true,
            signature_verification: false,
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            max_age: Duration::from_secs(30 * 24 * 3600), // 30 days
            min_backups: 3,
            archive_old_backups: false,
            archive_location: None,
        }
    }
}

impl Default for RecoveryOptions {
    fn default() -> Self {
        Self {
            verify_integrity: true,
            overwrite_existing: false,
            selective_keys: None,
            target_location: None,
            audit_recovery: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeyUsage;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Mock storage implementation for testing
    struct MockStorage {
        backups: Arc<Mutex<HashMap<String, (BackupMetadata, Vec<u8>)>>>,
    }

    impl MockStorage {
        fn new() -> Self {
            Self {
                backups: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl BackupStorage for MockStorage {
        async fn store_backup(&mut self, metadata: &BackupMetadata, data: &[u8]) -> CryptoTEEResult<()> {
            let mut backups = self.backups.lock().await;
            backups.insert(metadata.backup_id.clone(), (metadata.clone(), data.to_vec()));
            Ok(())
        }

        async fn retrieve_backup(&self, backup_id: &str) -> CryptoTEEResult<(BackupMetadata, Vec<u8>)> {
            let backups = self.backups.lock().await;
            backups.get(backup_id)
                .cloned()
                .ok_or_else(|| CryptoTEEError::BackupError("Backup not found".to_string()))
        }

        async fn list_backups(&self) -> CryptoTEEResult<Vec<BackupMetadata>> {
            let backups = self.backups.lock().await;
            Ok(backups.values().map(|(metadata, _)| metadata.clone()).collect())
        }

        async fn delete_backup(&mut self, backup_id: &str) -> CryptoTEEResult<()> {
            let mut backups = self.backups.lock().await;
            backups.remove(backup_id);
            Ok(())
        }

        async fn verify_backup(&self, backup_id: &str) -> CryptoTEEResult<bool> {
            let backups = self.backups.lock().await;
            Ok(backups.contains_key(backup_id))
        }
    }

    #[tokio::test]
    async fn test_backup_creation() {
        let config = BackupConfig::default();
        let storage = Box::new(MockStorage::new());
        let mut backup_manager = BackupManager::new(config, None, storage).unwrap();

        backup_manager.initialize_encryption().await.unwrap();

        // Create test keys
        let mut keys = HashMap::new();
        let key_handle = KeyHandle {
            id: "test_key_1".to_string(),
            algorithm: Algorithm::Ed25519,
            vendor: "test".to_string(),
            hardware_backed: false,
            vendor_data: None,
        };
        let key_metadata = KeyMetadata {
            id: "test_key_1".to_string(),
            algorithm: Algorithm::Ed25519,
            created_at: SystemTime::now(),
            usage: KeyUsage::default(),
            hardware_backed: false,
            exportable: false,
        };
        keys.insert("test_key_1".to_string(), (key_handle, key_metadata));

        // Create backup
        let backup_id = backup_manager.create_full_backup(&keys).await.unwrap();
        assert!(!backup_id.is_empty());

        // Verify backup exists
        let backups = backup_manager.list_backups().await.unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].backup_id, backup_id);
    }

    #[tokio::test]
    async fn test_backup_recovery() {
        let config = BackupConfig::default();
        let storage = Box::new(MockStorage::new());
        let mut backup_manager = BackupManager::new(config, None, storage).unwrap();

        backup_manager.initialize_encryption().await.unwrap();

        // Create and backup test keys
        let mut keys = HashMap::new();
        let key_handle = KeyHandle {
            id: "test_key_1".to_string(),
            algorithm: Algorithm::Ed25519,
            vendor: "test".to_string(),
            hardware_backed: false,
            vendor_data: None,
        };
        let key_metadata = KeyMetadata {
            id: "test_key_1".to_string(),
            algorithm: Algorithm::Ed25519,
            created_at: SystemTime::now(),
            usage: KeyUsage::default(),
            hardware_backed: false,
            exportable: false,
        };
        keys.insert("test_key_1".to_string(), (key_handle, key_metadata));

        let backup_id = backup_manager.create_full_backup(&keys).await.unwrap();

        // Recover from backup
        let recovery_options = RecoveryOptions::default();
        let recovered_keys = backup_manager.recover_from_backup(&backup_id, &recovery_options).await.unwrap();

        assert_eq!(recovered_keys.len(), 1);
        assert_eq!(recovered_keys[0].id, "test_key_1");
    }
}