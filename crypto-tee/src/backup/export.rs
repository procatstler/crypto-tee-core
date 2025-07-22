//! Backup Export Functionality
//!
//! This module provides functionality to export backups in various formats
//! for compatibility with different systems and compliance requirements.

use super::{BackupEntry, BackupMetadata, BackupType};
use crate::error::{CryptoTEEError, CryptoTEEResult};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io::Write,
    path::{Path, PathBuf},
    time::SystemTime,
};
use tracing::{debug, info};

/// Export format options
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExportFormat {
    /// JSON format for human readability
    Json,

    /// Binary format for efficiency
    Binary,

    /// PKCS#12 format for key exchange
    Pkcs12,

    /// PEM format for certificate chains
    Pem,

    /// Custom encrypted format
    Encrypted,
}

/// Export options
#[derive(Debug, Clone)]
pub struct ExportOptions {
    /// Output format
    pub format: ExportFormat,

    /// Include metadata in export
    pub include_metadata: bool,

    /// Include audit trail
    pub include_audit_trail: bool,

    /// Encrypt exported data
    pub encrypt_export: bool,

    /// Compression level (0-9, 0 = no compression)
    pub compression_level: u8,

    /// Output file path
    pub output_path: Option<PathBuf>,

    /// Password for encrypted exports
    pub password: Option<String>,
}

/// Exported backup structure
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportedBackup {
    /// Export metadata
    pub export_info: ExportInfo,

    /// Original backup metadata
    pub backup_metadata: BackupMetadata,

    /// Backup entries
    pub entries: Vec<BackupEntry>,

    /// Audit trail (if included)
    pub audit_trail: Option<Vec<AuditEntry>>,
}

/// Export metadata
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportInfo {
    /// Export format used
    pub format: String,

    /// Export timestamp
    pub exported_at: SystemTime,

    /// Exporter version
    pub exporter_version: String,

    /// Total size of exported data
    pub total_size_bytes: u64,

    /// Number of keys exported
    pub key_count: u32,

    /// Checksum of exported data
    pub checksum: Vec<u8>,

    /// Export options used
    pub options: ExportOptionsInfo,
}

/// Export options info (for metadata)
#[derive(Debug, Serialize, Deserialize)]
pub struct ExportOptionsInfo {
    /// Whether metadata was included
    pub included_metadata: bool,

    /// Whether audit trail was included
    pub included_audit_trail: bool,

    /// Whether export was encrypted
    pub encrypted: bool,

    /// Compression level used
    pub compression_level: u8,
}

/// Audit entry for export
#[derive(Debug, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp of the audit event
    pub timestamp: SystemTime,

    /// Event type
    pub event_type: String,

    /// Event description
    pub description: String,

    /// Whether the event was successful
    pub success: bool,

    /// Additional context
    pub context: HashMap<String, String>,
}

/// Backup exporter
pub struct BackupExporter {
    /// Export format handlers
    format_handlers: HashMap<ExportFormat, Box<dyn FormatHandler>>,
}

/// Trait for format-specific export handlers
trait FormatHandler: Send + Sync {
    /// Export backup in specific format
    fn export(
        &self,
        backup: &ExportedBackup,
        options: &ExportOptions,
    ) -> CryptoTEEResult<Vec<u8>>;

    /// Import backup from specific format
    fn import(&self, data: &[u8], options: &ExportOptions) -> CryptoTEEResult<ExportedBackup>;

    /// Get file extension for this format
    fn file_extension(&self) -> &str;

    /// Validate export options for this format
    fn validate_options(&self, options: &ExportOptions) -> CryptoTEEResult<()>;
}

/// JSON format handler
struct JsonFormatHandler;

/// Binary format handler
struct BinaryFormatHandler;

/// PKCS#12 format handler
struct Pkcs12FormatHandler;

/// PEM format handler
struct PemFormatHandler;

/// Encrypted format handler
struct EncryptedFormatHandler;

impl BackupExporter {
    /// Create new backup exporter
    pub fn new() -> Self {
        let mut format_handlers: HashMap<ExportFormat, Box<dyn FormatHandler>> = HashMap::new();

        format_handlers.insert(ExportFormat::Json, Box::new(JsonFormatHandler));
        format_handlers.insert(ExportFormat::Binary, Box::new(BinaryFormatHandler));
        format_handlers.insert(ExportFormat::Pkcs12, Box::new(Pkcs12FormatHandler));
        format_handlers.insert(ExportFormat::Pem, Box::new(PemFormatHandler));
        format_handlers.insert(ExportFormat::Encrypted, Box::new(EncryptedFormatHandler));

        Self { format_handlers }
    }

    /// Export backup to specified format
    pub async fn export_backup(
        &self,
        metadata: &BackupMetadata,
        entries: &[BackupEntry],
        options: &ExportOptions,
    ) -> CryptoTEEResult<Vec<u8>> {
        info!("Exporting backup {} in format {:?}", metadata.backup_id, options.format);

        // Get format handler
        let handler = self.format_handlers.get(&options.format).ok_or_else(|| {
            CryptoTEEError::NotSupported(format!("Export format {:?} not supported", options.format))
        })?;

        // Validate export options
        handler.validate_options(options)?;

        // Create export structure
        let mut exported_backup = ExportedBackup {
            export_info: self.create_export_info(metadata, entries, options),
            backup_metadata: metadata.clone(),
            entries: entries.to_vec(),
            audit_trail: None, // TODO: Implement audit trail collection
        };

        // Add audit trail if requested
        if options.include_audit_trail {
            exported_backup.audit_trail = Some(self.collect_audit_trail(metadata).await?);
        }

        // Export using format handler
        let exported_data = handler.export(&exported_backup, options)?;

        // Write to file if output path specified
        if let Some(output_path) = &options.output_path {
            self.write_export_to_file(&exported_data, output_path, &handler).await?;
        }

        info!(
            "Successfully exported backup {} ({} bytes)",
            metadata.backup_id,
            exported_data.len()
        );

        Ok(exported_data)
    }

    /// Import backup from exported data
    pub async fn import_backup(
        &self,
        data: &[u8],
        format: ExportFormat,
        options: &ExportOptions,
    ) -> CryptoTEEResult<(BackupMetadata, Vec<BackupEntry>)> {
        info!("Importing backup from format {:?}", format);

        // Get format handler
        let handler = self.format_handlers.get(&format).ok_or_else(|| {
            CryptoTEEError::NotSupported(format!("Import format {:?} not supported", format))
        })?;

        // Import using format handler
        let imported_backup = handler.import(data, options)?;

        info!(
            "Successfully imported backup {} with {} keys",
            imported_backup.backup_metadata.backup_id,
            imported_backup.entries.len()
        );

        Ok((imported_backup.backup_metadata, imported_backup.entries))
    }

    /// Export backup to file
    pub async fn export_to_file(
        &self,
        metadata: &BackupMetadata,
        entries: &[BackupEntry],
        output_path: &Path,
        format: ExportFormat,
        options: &ExportOptions,
    ) -> CryptoTEEResult<()> {
        let mut export_options = options.clone();
        export_options.output_path = Some(output_path.to_path_buf());

        self.export_backup(metadata, entries, &export_options).await?;
        Ok(())
    }

    /// Import backup from file
    pub async fn import_from_file(
        &self,
        file_path: &Path,
        format: ExportFormat,
        options: &ExportOptions,
    ) -> CryptoTEEResult<(BackupMetadata, Vec<BackupEntry>)> {
        let data = tokio::fs::read(file_path).await.map_err(|e| {
            CryptoTEEError::BackupError(format!("Failed to read import file {}: {}", file_path.display(), e))
        })?;

        self.import_backup(&data, format, options).await
    }

    /// Create export info
    fn create_export_info(
        &self,
        metadata: &BackupMetadata,
        entries: &[BackupEntry],
        options: &ExportOptions,
    ) -> ExportInfo {
        ExportInfo {
            format: format!("{:?}", options.format),
            exported_at: SystemTime::now(),
            exporter_version: env!("CARGO_PKG_VERSION").to_string(),
            total_size_bytes: metadata.size_bytes,
            key_count: entries.len() as u32,
            checksum: vec![], // TODO: Calculate actual checksum
            options: ExportOptionsInfo {
                included_metadata: options.include_metadata,
                included_audit_trail: options.include_audit_trail,
                encrypted: options.encrypt_export,
                compression_level: options.compression_level,
            },
        }
    }

    /// Collect audit trail for export
    async fn collect_audit_trail(&self, _metadata: &BackupMetadata) -> CryptoTEEResult<Vec<AuditEntry>> {
        // TODO: Implement audit trail collection from audit manager
        Ok(vec![])
    }

    /// Write export data to file
    async fn write_export_to_file(
        &self,
        data: &[u8],
        output_path: &Path,
        handler: &Box<dyn FormatHandler>,
    ) -> CryptoTEEResult<()> {
        // Ensure output directory exists
        if let Some(parent) = output_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                CryptoTEEError::BackupError(format!(
                    "Failed to create output directory {}: {}",
                    parent.display(),
                    e
                ))
            })?;
        }

        // Add appropriate file extension if not present
        let final_path = if output_path.extension().is_none() {
            let mut path = output_path.to_path_buf();
            path.set_extension(handler.file_extension());
            path
        } else {
            output_path.to_path_buf()
        };

        tokio::fs::write(&final_path, data).await.map_err(|e| {
            CryptoTEEError::BackupError(format!("Failed to write export file {}: {}", final_path.display(), e))
        })?;

        debug!("Export written to: {}", final_path.display());
        Ok(())
    }
}

// Format handler implementations

impl FormatHandler for JsonFormatHandler {
    fn export(
        &self,
        backup: &ExportedBackup,
        _options: &ExportOptions,
    ) -> CryptoTEEResult<Vec<u8>> {
        let json = serde_json::to_string_pretty(backup).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Failed to serialize backup to JSON: {}", e))
        })?;

        Ok(json.into_bytes())
    }

    fn import(&self, data: &[u8], _options: &ExportOptions) -> CryptoTEEResult<ExportedBackup> {
        let json_str = String::from_utf8(data.to_vec()).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Invalid UTF-8 in JSON data: {}", e))
        })?;

        serde_json::from_str(&json_str).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Failed to deserialize JSON backup: {}", e))
        })
    }

    fn file_extension(&self) -> &str {
        "json"
    }

    fn validate_options(&self, _options: &ExportOptions) -> CryptoTEEResult<()> {
        Ok(())
    }
}

impl FormatHandler for BinaryFormatHandler {
    fn export(
        &self,
        backup: &ExportedBackup,
        _options: &ExportOptions,
    ) -> CryptoTEEResult<Vec<u8>> {
        bincode::serialize(backup).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Failed to serialize backup to binary: {}", e))
        })
    }

    fn import(&self, data: &[u8], _options: &ExportOptions) -> CryptoTEEResult<ExportedBackup> {
        bincode::deserialize(data).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Failed to deserialize binary backup: {}", e))
        })
    }

    fn file_extension(&self) -> &str {
        "bin"
    }

    fn validate_options(&self, _options: &ExportOptions) -> CryptoTEEResult<()> {
        Ok(())
    }
}

impl FormatHandler for Pkcs12FormatHandler {
    fn export(
        &self,
        _backup: &ExportedBackup,
        _options: &ExportOptions,
    ) -> CryptoTEEResult<Vec<u8>> {
        // TODO: Implement PKCS#12 export
        Err(CryptoTEEError::NotSupported("PKCS#12 export not yet implemented".to_string()))
    }

    fn import(&self, _data: &[u8], _options: &ExportOptions) -> CryptoTEEResult<ExportedBackup> {
        // TODO: Implement PKCS#12 import
        Err(CryptoTEEError::NotSupported("PKCS#12 import not yet implemented".to_string()))
    }

    fn file_extension(&self) -> &str {
        "p12"
    }

    fn validate_options(&self, options: &ExportOptions) -> CryptoTEEResult<()> {
        if options.password.is_none() {
            return Err(CryptoTEEError::ConfigurationError(
                "Password required for PKCS#12 format".to_string(),
            ));
        }
        Ok(())
    }
}

impl FormatHandler for PemFormatHandler {
    fn export(
        &self,
        _backup: &ExportedBackup,
        _options: &ExportOptions,
    ) -> CryptoTEEResult<Vec<u8>> {
        // TODO: Implement PEM export
        Err(CryptoTEEError::NotSupported("PEM export not yet implemented".to_string()))
    }

    fn import(&self, _data: &[u8], _options: &ExportOptions) -> CryptoTEEResult<ExportedBackup> {
        // TODO: Implement PEM import
        Err(CryptoTEEError::NotSupported("PEM import not yet implemented".to_string()))
    }

    fn file_extension(&self) -> &str {
        "pem"
    }

    fn validate_options(&self, _options: &ExportOptions) -> CryptoTEEResult<()> {
        Ok(())
    }
}

impl FormatHandler for EncryptedFormatHandler {
    fn export(
        &self,
        backup: &ExportedBackup,
        options: &ExportOptions,
    ) -> CryptoTEEResult<Vec<u8>> {
        // First serialize to JSON
        let json_data = serde_json::to_vec(backup).map_err(|e| {
            CryptoTEEError::SerializationError(format!("Failed to serialize backup: {}", e))
        })?;

        // Then encrypt if password provided
        if let Some(_password) = &options.password {
            // TODO: Implement encryption with password
            // For now, just return the JSON data
            Ok(json_data)
        } else {
            Err(CryptoTEEError::ConfigurationError(
                "Password required for encrypted format".to_string(),
            ))
        }
    }

    fn import(&self, data: &[u8], options: &ExportOptions) -> CryptoTEEResult<ExportedBackup> {
        if let Some(_password) = &options.password {
            // TODO: Implement decryption with password
            // For now, try to deserialize as JSON
            serde_json::from_slice(data).map_err(|e| {
                CryptoTEEError::SerializationError(format!("Failed to deserialize encrypted backup: {}", e))
            })
        } else {
            Err(CryptoTEEError::ConfigurationError(
                "Password required for encrypted format".to_string(),
            ))
        }
    }

    fn file_extension(&self) -> &str {
        "enc"
    }

    fn validate_options(&self, options: &ExportOptions) -> CryptoTEEResult<()> {
        if options.password.is_none() {
            return Err(CryptoTEEError::ConfigurationError(
                "Password required for encrypted format".to_string(),
            ));
        }
        Ok(())
    }
}

impl Default for ExportOptions {
    fn default() -> Self {
        Self {
            format: ExportFormat::Json,
            include_metadata: true,
            include_audit_trail: false,
            encrypt_export: false,
            compression_level: 0,
            output_path: None,
            password: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        backup::{BackupEntry, EncryptionInfo},
        keys::{KeyHandle, KeyMetadata, KeyUsage},
        types::Algorithm,
    };
    use ring::digest;
    use std::time::SystemTime;
    use tempfile::TempDir;

    fn create_test_backup() -> (BackupMetadata, Vec<BackupEntry>) {
        let metadata = BackupMetadata {
            backup_id: "test_backup".to_string(),
            created_at: SystemTime::now(),
            version: 1,
            key_count: 1,
            size_bytes: 1024,
            format_version: "1.0".to_string(),
            backup_type: BackupType::Full,
            checksum: digest::digest(&digest::SHA256, b"test data").as_ref().to_vec(),
            signature: None,
            encryption_info: None,
        };

        let entry = BackupEntry {
            key_handle: KeyHandle {
                id: "test_key".to_string(),
                algorithm: Algorithm::Ed25519,
                vendor: "test".to_string(),
                hardware_backed: false,
                vendor_data: None,
            },
            metadata: KeyMetadata {
                id: "test_key".to_string(),
                algorithm: Algorithm::Ed25519,
                created_at: SystemTime::now(),
                usage: KeyUsage::default(),
                hardware_backed: false,
                exportable: true,
            },
            encrypted_key_data: b"encrypted_key_data".to_vec(),
            created_at: SystemTime::now(),
            checksum: digest::digest(&digest::SHA256, b"encrypted_key_data").as_ref().to_vec(),
        };

        (metadata, vec![entry])
    }

    #[tokio::test]
    async fn test_json_export_import() {
        let exporter = BackupExporter::new();
        let (metadata, entries) = create_test_backup();

        let options = ExportOptions {
            format: ExportFormat::Json,
            ..Default::default()
        };

        // Test export
        let exported_data = exporter.export_backup(&metadata, &entries, &options).await.unwrap();
        assert!(!exported_data.is_empty());

        // Test import
        let (imported_metadata, imported_entries) = exporter
            .import_backup(&exported_data, ExportFormat::Json, &options)
            .await
            .unwrap();

        assert_eq!(imported_metadata.backup_id, metadata.backup_id);
        assert_eq!(imported_entries.len(), entries.len());
        assert_eq!(imported_entries[0].key_handle.id, entries[0].key_handle.id);
    }

    #[tokio::test]
    async fn test_binary_export_import() {
        let exporter = BackupExporter::new();
        let (metadata, entries) = create_test_backup();

        let options = ExportOptions {
            format: ExportFormat::Binary,
            ..Default::default()
        };

        // Test export
        let exported_data = exporter.export_backup(&metadata, &entries, &options).await.unwrap();
        assert!(!exported_data.is_empty());

        // Test import
        let (imported_metadata, imported_entries) = exporter
            .import_backup(&exported_data, ExportFormat::Binary, &options)
            .await
            .unwrap();

        assert_eq!(imported_metadata.backup_id, metadata.backup_id);
        assert_eq!(imported_entries.len(), entries.len());
    }

    #[tokio::test]
    async fn test_export_to_file() {
        let temp_dir = TempDir::new().unwrap();
        let output_path = temp_dir.path().join("test_backup");

        let exporter = BackupExporter::new();
        let (metadata, entries) = create_test_backup();

        let options = ExportOptions {
            format: ExportFormat::Json,
            ..Default::default()
        };

        // Export to file
        exporter
            .export_to_file(&metadata, &entries, &output_path, ExportFormat::Json, &options)
            .await
            .unwrap();

        // Check file was created with correct extension
        let final_path = temp_dir.path().join("test_backup.json");
        assert!(final_path.exists());

        // Import from file
        let (imported_metadata, imported_entries) = exporter
            .import_from_file(&final_path, ExportFormat::Json, &options)
            .await
            .unwrap();

        assert_eq!(imported_metadata.backup_id, metadata.backup_id);
        assert_eq!(imported_entries.len(), entries.len());
    }

    #[tokio::test]
    async fn test_unsupported_format() {
        let exporter = BackupExporter::new();
        let (metadata, entries) = create_test_backup();

        let options = ExportOptions {
            format: ExportFormat::Pkcs12,
            password: None, // Missing required password
            ..Default::default()
        };

        // Should fail due to missing password
        let result = exporter.export_backup(&metadata, &entries, &options).await;
        assert!(result.is_err());
    }
}