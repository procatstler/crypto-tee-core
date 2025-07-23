//! Backup Storage Implementations
//!
//! This module provides various storage backends for cryptographic key backups.

use super::{BackupMetadata, BackupStorage};
use crate::error::{CryptoTEEError, CryptoTEEResult};
use async_trait::async_trait;
use ring::digest;
use serde_json;
use std::{
    fs,
    path::{Path, PathBuf},
};
use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt, AsyncWriteExt},
};
use tracing::{debug, error, info, warn};

/// File system storage backend
pub struct FileSystemStorage {
    /// Base directory for backups
    base_path: PathBuf,

    /// Enable compression
    compression_enabled: bool,

    /// Maximum backup file size
    max_file_size_bytes: u64,
}

/// Cloud storage backend (placeholder for future implementation)
pub struct CloudStorage {
    /// Cloud provider configuration
    _provider_config: CloudProviderConfig,

    /// Encryption at transit
    encrypt_in_transit: bool,

    /// Redundancy level
    redundancy_level: u32,
}

/// Cloud provider configuration
#[derive(Debug, Clone)]
pub enum CloudProviderConfig {
    /// AWS S3 configuration
    AwsS3 { bucket: String, region: String, access_key_id: String, secret_access_key: String },

    /// Azure Blob Storage configuration
    AzureBlob { account_name: String, account_key: String, container_name: String },

    /// Google Cloud Storage configuration
    GoogleCloud { project_id: String, bucket_name: String, service_account_key: String },
}

impl FileSystemStorage {
    /// Create new file system storage
    pub fn new(base_path: impl AsRef<Path>) -> CryptoTEEResult<Self> {
        let base_path = base_path.as_ref().to_path_buf();

        // Create base directory if it doesn't exist
        if !base_path.exists() {
            std::fs::create_dir_all(&base_path).map_err(|e| {
                CryptoTEEError::BackupError(format!(
                    "Failed to create backup directory {}: {}",
                    base_path.display(),
                    e
                ))
            })?;
        }

        Ok(Self {
            base_path,
            compression_enabled: false,
            max_file_size_bytes: 100 * 1024 * 1024, // 100MB default
        })
    }

    /// Enable or disable compression
    pub fn set_compression(&mut self, enabled: bool) {
        self.compression_enabled = enabled;
    }

    /// Set maximum file size
    pub fn set_max_file_size(&mut self, max_size_bytes: u64) {
        self.max_file_size_bytes = max_size_bytes;
    }

    /// Get backup file path
    fn get_backup_path(&self, backup_id: &str) -> PathBuf {
        self.base_path.join(format!("{}.backup", backup_id))
    }

    /// Get metadata file path
    fn get_metadata_path(&self, backup_id: &str) -> PathBuf {
        self.base_path.join(format!("{}.metadata", backup_id))
    }

    /// Compress data if compression is enabled
    fn compress_data(&self, data: &[u8]) -> CryptoTEEResult<Vec<u8>> {
        if self.compression_enabled {
            // TODO: Implement compression (e.g., using flate2)
            // For now, just return the original data
            Ok(data.to_vec())
        } else {
            Ok(data.to_vec())
        }
    }

    /// Decompress data if compression was used
    fn decompress_data(&self, data: &[u8]) -> CryptoTEEResult<Vec<u8>> {
        if self.compression_enabled {
            // TODO: Implement decompression
            // For now, just return the original data
            Ok(data.to_vec())
        } else {
            Ok(data.to_vec())
        }
    }
}

#[async_trait]
impl BackupStorage for FileSystemStorage {
    async fn store_backup(
        &mut self,
        metadata: &BackupMetadata,
        data: &[u8],
    ) -> CryptoTEEResult<()> {
        let backup_id = &metadata.backup_id;

        // Check file size limit
        if data.len() as u64 > self.max_file_size_bytes {
            return Err(CryptoTEEError::BackupError(format!(
                "Backup size {} exceeds maximum allowed size {}",
                data.len(),
                self.max_file_size_bytes
            )));
        }

        debug!("Storing backup {} to filesystem", backup_id);

        // Compress data if enabled
        let processed_data = self.compress_data(data)?;

        // Write backup data
        let backup_path = self.get_backup_path(backup_id);
        let mut backup_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&backup_path)
            .await
            .map_err(|e| {
                CryptoTEEError::BackupError(format!(
                    "Failed to create backup file {}: {}",
                    backup_path.display(),
                    e
                ))
            })?;

        backup_file.write_all(&processed_data).await.map_err(|e| {
            CryptoTEEError::BackupError(format!("Failed to write backup data: {}", e))
        })?;

        backup_file.sync_all().await.map_err(|e| {
            CryptoTEEError::BackupError(format!("Failed to sync backup file: {}", e))
        })?;

        // Write metadata
        let metadata_path = self.get_metadata_path(backup_id);
        let metadata_json = serde_json::to_string_pretty(metadata).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Failed to serialize metadata: {}", e))
        })?;

        let mut metadata_file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&metadata_path)
            .await
            .map_err(|e| {
                CryptoTEEError::BackupError(format!(
                    "Failed to create metadata file {}: {}",
                    metadata_path.display(),
                    e
                ))
            })?;

        metadata_file
            .write_all(metadata_json.as_bytes())
            .await
            .map_err(|e| CryptoTEEError::BackupError(format!("Failed to write metadata: {}", e)))?;

        metadata_file.sync_all().await.map_err(|e| {
            CryptoTEEError::BackupError(format!("Failed to sync metadata file: {}", e))
        })?;

        info!("Successfully stored backup {} ({} bytes)", backup_id, data.len());
        Ok(())
    }

    async fn retrieve_backup(&self, backup_id: &str) -> CryptoTEEResult<(BackupMetadata, Vec<u8>)> {
        debug!("Retrieving backup {} from filesystem", backup_id);

        // Read metadata
        let metadata_path = self.get_metadata_path(backup_id);
        if !metadata_path.exists() {
            return Err(CryptoTEEError::BackupError(format!(
                "Backup metadata not found: {}",
                backup_id
            )));
        }

        let mut metadata_file = File::open(&metadata_path).await.map_err(|e| {
            CryptoTEEError::BackupError(format!(
                "Failed to open metadata file {}: {}",
                metadata_path.display(),
                e
            ))
        })?;

        let mut metadata_json = String::new();
        metadata_file
            .read_to_string(&mut metadata_json)
            .await
            .map_err(|e| CryptoTEEError::BackupError(format!("Failed to read metadata: {}", e)))?;

        let metadata: BackupMetadata = serde_json::from_str(&metadata_json).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Failed to deserialize metadata: {}", e))
        })?;

        // Read backup data
        let backup_path = self.get_backup_path(backup_id);
        if !backup_path.exists() {
            return Err(CryptoTEEError::BackupError(format!(
                "Backup data not found: {}",
                backup_id
            )));
        }

        let mut backup_file = File::open(&backup_path).await.map_err(|e| {
            CryptoTEEError::BackupError(format!(
                "Failed to open backup file {}: {}",
                backup_path.display(),
                e
            ))
        })?;

        let mut compressed_data = Vec::new();
        backup_file.read_to_end(&mut compressed_data).await.map_err(|e| {
            CryptoTEEError::BackupError(format!("Failed to read backup data: {}", e))
        })?;

        // Decompress data if needed
        let data = self.decompress_data(&compressed_data)?;

        info!("Successfully retrieved backup {} ({} bytes)", backup_id, data.len());
        Ok((metadata, data))
    }

    async fn list_backups(&self) -> CryptoTEEResult<Vec<BackupMetadata>> {
        debug!("Listing backups from filesystem");

        let mut backups = Vec::new();

        let entries = fs::read_dir(&self.base_path).map_err(|e| {
            CryptoTEEError::BackupError(format!(
                "Failed to read backup directory {}: {}",
                self.base_path.display(),
                e
            ))
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| {
                CryptoTEEError::BackupError(format!("Failed to read directory entry: {}", e))
            })?;

            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("metadata") {
                match self.read_metadata_file(&path).await {
                    Ok(metadata) => backups.push(metadata),
                    Err(e) => {
                        warn!("Failed to read metadata from {}: {}", path.display(), e);
                    }
                }
            }
        }

        // Sort by creation time (newest first)
        backups.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        info!("Found {} backups", backups.len());
        Ok(backups)
    }

    async fn delete_backup(&mut self, backup_id: &str) -> CryptoTEEResult<()> {
        debug!("Deleting backup {} from filesystem", backup_id);

        let backup_path = self.get_backup_path(backup_id);
        let metadata_path = self.get_metadata_path(backup_id);

        // Delete backup file
        if backup_path.exists() {
            tokio::fs::remove_file(&backup_path).await.map_err(|e| {
                CryptoTEEError::BackupError(format!(
                    "Failed to delete backup file {}: {}",
                    backup_path.display(),
                    e
                ))
            })?;
        }

        // Delete metadata file
        if metadata_path.exists() {
            tokio::fs::remove_file(&metadata_path).await.map_err(|e| {
                CryptoTEEError::BackupError(format!(
                    "Failed to delete metadata file {}: {}",
                    metadata_path.display(),
                    e
                ))
            })?;
        }

        info!("Successfully deleted backup {}", backup_id);
        Ok(())
    }

    async fn verify_backup(&self, backup_id: &str) -> CryptoTEEResult<bool> {
        debug!("Verifying backup {} on filesystem", backup_id);

        let backup_path = self.get_backup_path(backup_id);
        let metadata_path = self.get_metadata_path(backup_id);

        // Check if both files exist
        if !backup_path.exists() || !metadata_path.exists() {
            return Ok(false);
        }

        // Read and verify metadata
        let metadata = match self.read_metadata_file(&metadata_path).await {
            Ok(meta) => meta,
            Err(_) => return Ok(false),
        };

        // Verify backup data checksum
        let mut backup_file = match File::open(&backup_path).await {
            Ok(file) => file,
            Err(_) => return Ok(false),
        };

        let mut data = Vec::new();
        if backup_file.read_to_end(&mut data).await.is_err() {
            return Ok(false);
        }

        let calculated_checksum = digest::digest(&digest::SHA256, &data);
        let checksum_valid = calculated_checksum.as_ref() == metadata.checksum.as_slice();

        if !checksum_valid {
            error!("Checksum verification failed for backup {}", backup_id);
        }

        Ok(checksum_valid)
    }
}

impl FileSystemStorage {
    /// Read metadata from a file
    async fn read_metadata_file(&self, path: &Path) -> CryptoTEEResult<BackupMetadata> {
        let mut file = File::open(path).await.map_err(|e| {
            CryptoTEEError::BackupError(format!(
                "Failed to open metadata file {}: {}",
                path.display(),
                e
            ))
        })?;

        let mut contents = String::new();
        file.read_to_string(&mut contents).await.map_err(|e| {
            CryptoTEEError::BackupError(format!("Failed to read metadata file: {}", e))
        })?;

        serde_json::from_str(&contents).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Failed to parse metadata: {}", e))
        })
    }
}

impl CloudStorage {
    /// Create new cloud storage backend
    pub fn new(provider_config: CloudProviderConfig) -> Self {
        Self { _provider_config: provider_config, encrypt_in_transit: true, redundancy_level: 3 }
    }

    /// Set encryption in transit
    pub fn set_encrypt_in_transit(&mut self, enabled: bool) {
        self.encrypt_in_transit = enabled;
    }

    /// Set redundancy level
    pub fn set_redundancy_level(&mut self, level: u32) {
        self.redundancy_level = level;
    }
}

#[async_trait]
impl BackupStorage for CloudStorage {
    async fn store_backup(
        &mut self,
        _metadata: &BackupMetadata,
        _data: &[u8],
    ) -> CryptoTEEResult<()> {
        // TODO: Implement cloud storage backend
        Err(CryptoTEEError::NotSupported("Cloud storage not yet implemented".to_string()))
    }

    async fn retrieve_backup(
        &self,
        _backup_id: &str,
    ) -> CryptoTEEResult<(BackupMetadata, Vec<u8>)> {
        // TODO: Implement cloud storage backend
        Err(CryptoTEEError::NotSupported("Cloud storage not yet implemented".to_string()))
    }

    async fn list_backups(&self) -> CryptoTEEResult<Vec<BackupMetadata>> {
        // TODO: Implement cloud storage backend
        Err(CryptoTEEError::NotSupported("Cloud storage not yet implemented".to_string()))
    }

    async fn delete_backup(&mut self, _backup_id: &str) -> CryptoTEEResult<()> {
        // TODO: Implement cloud storage backend
        Err(CryptoTEEError::NotSupported("Cloud storage not yet implemented".to_string()))
    }

    async fn verify_backup(&self, _backup_id: &str) -> CryptoTEEResult<bool> {
        // TODO: Implement cloud storage backend
        Err(CryptoTEEError::NotSupported("Cloud storage not yet implemented".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backup::{BackupType, EncryptionInfo};
    use std::time::SystemTime;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_filesystem_storage() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = FileSystemStorage::new(temp_dir.path()).unwrap();

        // Create test metadata and data
        let metadata = BackupMetadata {
            backup_id: "test_backup_1".to_string(),
            created_at: SystemTime::now(),
            version: 1,
            key_count: 2,
            size_bytes: 1024,
            format_version: "1.0".to_string(),
            backup_type: BackupType::Full,
            checksum: vec![1, 2, 3, 4],
            signature: None,
            encryption_info: None,
        };

        let test_data = b"test backup data";

        // Test store
        storage.store_backup(&metadata, test_data).await.unwrap();

        // Test retrieve
        let (retrieved_metadata, retrieved_data) =
            storage.retrieve_backup("test_backup_1").await.unwrap();
        assert_eq!(retrieved_metadata.backup_id, metadata.backup_id);
        assert_eq!(retrieved_data, test_data);

        // Test list
        let backups = storage.list_backups().await.unwrap();
        assert_eq!(backups.len(), 1);
        assert_eq!(backups[0].backup_id, "test_backup_1");

        // Test verify
        let is_valid = storage.verify_backup("test_backup_1").await.unwrap();
        assert!(!is_valid); // Will fail because checksum doesn't match actual data

        // Test delete
        storage.delete_backup("test_backup_1").await.unwrap();
        let backups_after_delete = storage.list_backups().await.unwrap();
        assert_eq!(backups_after_delete.len(), 0);
    }

    #[tokio::test]
    async fn test_filesystem_storage_with_compression() {
        let temp_dir = TempDir::new().unwrap();
        let mut storage = FileSystemStorage::new(temp_dir.path()).unwrap();
        storage.set_compression(true);

        let metadata = BackupMetadata {
            backup_id: "compressed_backup".to_string(),
            created_at: SystemTime::now(),
            version: 1,
            key_count: 1,
            size_bytes: 512,
            format_version: "1.0".to_string(),
            backup_type: BackupType::Full,
            checksum: vec![5, 6, 7, 8],
            signature: None,
            encryption_info: Some(EncryptionInfo {
                algorithm: "ChaCha20-Poly1305".to_string(),
                key_derivation: "PBKDF2".to_string(),
                salt: vec![1, 2, 3, 4],
                iv: vec![5, 6, 7, 8],
                aad: vec![],
            }),
        };

        let test_data = b"compressed test data";

        // Store and retrieve with compression
        storage.store_backup(&metadata, test_data).await.unwrap();
        let (_, retrieved_data) = storage.retrieve_backup("compressed_backup").await.unwrap();
        assert_eq!(retrieved_data, test_data);
    }
}
