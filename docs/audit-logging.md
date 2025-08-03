# Audit Logging System

The CryptoTEE audit logging system provides comprehensive tracking of all key management operations for compliance and security monitoring.

## Features

- **Complete Operation Tracking**: All key operations (generation, deletion, signing, verification) are automatically logged
- **Chain Integrity**: Events are cryptographically linked using SHA256 hashing
- **Multiple Output Formats**: JSON, CEF, Syslog, and human-readable text
- **Flexible Storage**: In-memory and file-based storage backends
- **Real-time Alerts**: Critical events can trigger webhooks
- **Tamper Detection**: Chain verification ensures log integrity

## Architecture

```
┌─────────────────┐
│  CryptoTEE API  │
└────────┬────────┘
         │ Audit Events
         ▼
┌─────────────────┐
│  Audit Manager  │
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌────────┐ ┌────────┐
│ Logger │ │Storage │
└────────┘ └────────┘
```

## Event Types

- `KeyGenerated` - Key creation events
- `KeyDeleted` - Key deletion events  
- `KeyAccessed` - Key information access
- `KeyImported` - Key import operations
- `SignOperation` - Signing operations
- `VerifyOperation` - Signature verification
- `SystemInitialized` - System startup

## Configuration

The audit system is automatically configured with sensible defaults:

```rust
AuditConfig {
    enabled: true,
    min_severity: AuditSeverity::Info,
    enable_chain_integrity: true,
    retention_days: 365,
    max_memory_events: 10000,
    enable_alerts: true,
    alert_webhook: None,
}
```

## Usage Example

```rust
use crypto_tee::{CryptoTEE, CryptoTEEBuilder};

// Audit logging is automatically enabled
let crypto_tee = CryptoTEEBuilder::new()
    .build()
    .await?;

// All operations are automatically audited
let key = crypto_tee.generate_key("my_key", options).await?;
```

## Log Formats

### JSON Format (Default)
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "timestamp": "2024-01-15T10:30:00Z",
  "event_type": "KEY_GENERATED",
  "severity": "INFO",
  "actor": "system",
  "target": "my_key",
  "success": true,
  "metadata": {
    "algorithm": "EcdsaP256"
  },
  "hash": "a1b2c3d4..."
}
```

### CEF Format
```
CEF:0|CryptoTEE|CryptoTEE|1.0|KeyGenerated|KeyGenerated|3|msg=Success src=system dst=my_key outcome=success
```

### Syslog Format
```
<134>Jan 15 10:30:00 localhost CryptoTEE[12345]: KeyGenerated - Actor: system, Target: Some("my_key"), Success: true
```

## Log Storage

By default, logs are stored in:
- **Console**: Human-readable text output
- **File**: `audit_logs/crypto-tee-audit.jsonl` (JSON Lines format)

## Security Considerations

1. **Chain Integrity**: Each event contains the hash of the previous event
2. **Tamper Detection**: Modified events will fail hash verification
3. **Access Control**: Audit logs should be protected at the filesystem level
4. **Retention**: Configure appropriate retention periods for compliance

## Compliance

The audit logging system helps meet various compliance requirements:
- PCI DSS (logging of cryptographic operations)
- FIPS 140-2 (audit trail requirements)
- SOC 2 (security event logging)
- GDPR (data processing records)

## Future Enhancements

- Remote syslog server support
- Elasticsearch integration
- Audit log encryption
- Automated compliance reports
- Role-based audit filtering