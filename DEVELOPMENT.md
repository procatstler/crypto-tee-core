# CryptoTEE Development Guide

This guide provides detailed information for developers working on CryptoTEE.

## Architecture Overview

CryptoTEE follows a layered architecture:

```
┌─────────────────────────────────────────┐
│          Application Layer              │
├─────────────────────────────────────────┤
│    RFC 9421 HTTP Signatures (L4)       │
├─────────────────────────────────────────┤
│       CryptoTEE Core API (L3)          │
├─────────────────────────────────────────┤
│      Platform Abstraction (L2)          │
├─────────────────────────────────────────┤
│        Vendor TEE Layer (L1)            │
├─────────────────────────────────────────┤
│  Hardware TEE (Knox/SE/QSEE/etc.)      │
└─────────────────────────────────────────┘
```

### Layer Responsibilities

#### Layer 1: Vendor TEE (`crypto-tee-vendor`)
- Direct TEE hardware interfaces
- Vendor-specific implementations
- Mock implementation for testing
- Simulator for development

#### Layer 2: Platform Abstraction (`crypto-tee-platform`)
- Platform detection and selection
- Vendor abstraction
- Software fallback
- Common platform utilities

#### Layer 3: Core API (`crypto-tee`)
- High-level cryptographic API
- Key lifecycle management
- Plugin system
- Error handling

#### Layer 4: RFC 9421 (`crypto-tee-rfc9421`)
- HTTP message signatures
- RFC 9421 compliance
- Integration with web frameworks

## Project Structure

```
crypto-tee-core/
├── crypto-tee-vendor/        # L1: Vendor implementations
│   ├── src/
│   │   ├── traits.rs        # VendorTEE trait definition
│   │   ├── types.rs         # Common types
│   │   ├── mock/            # Mock implementation
│   │   ├── simulator/       # TEE simulator
│   │   ├── samsung/         # Samsung Knox
│   │   ├── apple/           # Apple Secure Enclave
│   │   └── qualcomm/        # Qualcomm QSEE
│   └── tests/
├── crypto-tee-platform/      # L2: Platform layer
│   ├── src/
│   │   ├── traits.rs        # Platform traits
│   │   ├── detector.rs      # Platform detection
│   │   └── fallback.rs      # Software fallback
│   └── tests/
├── crypto-tee/              # L3: Core API
│   ├── src/
│   │   ├── core/           # Core implementation
│   │   ├── plugins/        # Plugin system
│   │   └── types.rs        # Public types
│   ├── tests/
│   └── benches/
├── crypto-tee-rfc9421/      # L4: RFC 9421
│   ├── src/
│   │   ├── adapter.rs      # CryptoTEE adapter
│   │   └── types.rs        # RFC types
│   └── tests/
└── docs/                    # Documentation
```

## Development Workflow

### Setting Up Development Environment

1. **Install Rust toolchain**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup default stable
   rustup component add rustfmt clippy llvm-tools-preview
   ```

2. **Clone and setup**:
   ```bash
   git clone https://github.com/procatstler/crypto-tee-core.git
   cd crypto-tee-core
   cargo build --all-features
   ```

3. **Install development tools**:
   ```bash
   cargo install cargo-audit cargo-deny cargo-tarpaulin
   cargo install cargo-expand cargo-tree cargo-udeps
   ```

### Feature Flags

#### crypto-tee-vendor
- `software-fallback`: Enable software-only implementation
- `simulator`: Enable TEE simulator
- `samsung`: Samsung Knox support
- `apple`: Apple Secure Enclave support
- `qualcomm`: Qualcomm QSEE support

#### crypto-tee-platform
- `software-fallback`: Enable fallback implementation
- `auto-detect`: Automatic platform detection

#### crypto-tee
- `plugins`: Enable plugin system
- `async-std`: Use async-std instead of tokio

### Building for Different Platforms

#### Desktop Development
```bash
# Linux
cargo build --all-features

# macOS with Secure Enclave
cargo build --features apple

# Windows
cargo build --features software-fallback
```

#### Mobile Development
```bash
# Android
export ANDROID_NDK_ROOT=$HOME/Android/Sdk/ndk/25.2.9519653
cargo build --target aarch64-linux-android --features "samsung,qualcomm"

# iOS
cargo build --target aarch64-apple-ios --features apple
```

#### WebAssembly
```bash
cargo build --target wasm32-unknown-unknown --no-default-features --features software-fallback
```

## Testing Strategy

### Unit Tests
Located in `src/**/*.rs` within `#[cfg(test)]` modules:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_functionality() {
        // Test implementation
    }
}
```

### Integration Tests
Located in `tests/` directory:

```bash
# Run all integration tests
cargo test --test integration_tests

# Run specific test
cargo test --test integration_tests test_key_lifecycle
```

### Performance Tests
```bash
# Run benchmarks
cargo bench --bench performance_tests

# Run with profiling
cargo bench --bench performance_tests -- --profile-time=10
```

### Platform-Specific Tests
```bash
# Test Samsung Knox simulation
cargo test --features "simulator,samsung" samsung_

# Test Apple Secure Enclave simulation
cargo test --features "simulator,apple" apple_

# Test Qualcomm QSEE simulation
cargo test --features "simulator,qualcomm" qualcomm_
```

## Debugging

### Logging
Configure logging with `RUST_LOG`:

```bash
# Enable all logs
RUST_LOG=debug cargo test

# Enable specific module logs
RUST_LOG=crypto_tee_vendor::mock=debug cargo test

# Enable trace-level logs
RUST_LOG=trace cargo test test_name
```

### Common Issues

#### 1. Feature Conflicts
```bash
# Error: feature 'samsung' requires 'simulator'
# Solution: Enable required features
cargo build --features "simulator,samsung"
```

#### 2. Platform-Specific Errors
```bash
# Error: Apple Secure Enclave not available
# Solution: Use simulator or mock
cargo test --features simulator
```

#### 3. Async Runtime Conflicts
```bash
# Error: no reactor running
# Solution: Use #[tokio::test] for async tests
#[tokio::test]
async fn test_async() {
    // Test code
}
```

## Performance Optimization

### Profiling
```bash
# CPU profiling with flamegraph
cargo install flamegraph
cargo flamegraph --bench performance_tests

# Memory profiling
valgrind --tool=massif target/release/bench
ms_print massif.out.*
```

### Optimization Guidelines
1. Use caching for public key operations
2. Implement memory pooling for allocations
3. Use constant-time operations for crypto
4. Minimize async overhead
5. Profile before optimizing

### Benchmark Development
```rust
use criterion::{criterion_group, criterion_main, Criterion};

fn bench_operation(c: &mut Criterion) {
    c.bench_function("operation_name", |b| {
        b.iter(|| {
            // Code to benchmark
        });
    });
}

criterion_group!(benches, bench_operation);
criterion_main!(benches);
```

## Security Development

### Security Checklist
- [ ] No sensitive data in logs
- [ ] Input validation on all public APIs
- [ ] Constant-time crypto operations
- [ ] Proper error handling
- [ ] Memory zeroization
- [ ] No panics in library code

### Cryptographic Guidelines
1. Use only approved algorithms
2. Implement proper key lifecycle
3. Use secure random sources
4. Validate all cryptographic inputs
5. Follow NIST/FIPS guidelines

### Memory Safety
```rust
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveData {
    #[zeroize(skip)]  // Skip non-sensitive fields
    id: String,
    secret: Vec<u8>,  // Will be zeroized
}
```

## API Design Guidelines

### Async API Design
```rust
// Prefer async/await
pub async fn operation(&self) -> Result<T> {
    // Implementation
}

// Use tokio for runtime
#[tokio::main]
async fn main() {
    // Application code
}
```

### Error Handling
```rust
// Define specific error types
#[derive(Debug, thiserror::Error)]
pub enum CryptoTEEError {
    #[error("Key not found: {0}")]
    KeyNotFound(String),
    
    #[error("TEE operation failed")]
    TEEError(#[from] VendorError),
}

// Use Result type alias
pub type Result<T> = std::result::Result<T, CryptoTEEError>;
```

### Builder Pattern
```rust
pub struct CryptoTEEBuilder {
    config: Config,
}

impl CryptoTEEBuilder {
    pub fn new() -> Self {
        Self::default()
    }
    
    pub fn with_vendor(mut self, vendor: Vendor) -> Self {
        self.config.vendor = Some(vendor);
        self
    }
    
    pub async fn build(self) -> Result<CryptoTEE> {
        CryptoTEE::new(self.config).await
    }
}
```

## Documentation Standards

### API Documentation
```rust
/// Generate a new cryptographic key
/// 
/// This function creates a new key with the specified parameters
/// and stores it in the TEE.
/// 
/// # Arguments
/// 
/// * `alias` - Unique identifier for the key
/// * `options` - Key generation options
/// 
/// # Returns
/// 
/// Returns a `KeyHandle` that can be used for cryptographic operations.
/// 
/// # Errors
/// 
/// Returns an error if:
/// - The alias already exists
/// - The TEE is not available
/// - Invalid parameters are provided
/// 
/// # Examples
/// 
/// ```no_run
/// # use crypto_tee::*;
/// # async fn example() -> Result<()> {
/// let crypto_tee = CryptoTEE::new().await?;
/// let handle = crypto_tee.generate_key(
///     "my-key",
///     KeyOptions::default()
/// ).await?;
/// # Ok(())
/// # }
/// ```
/// 
/// # Security
/// 
/// Keys are generated using hardware-backed secure random sources
/// when available.
pub async fn generate_key(
    &self,
    alias: &str,
    options: KeyOptions,
) -> Result<KeyHandle> {
    // Implementation
}
```

## Release Engineering

### Pre-release Checklist
1. Run full test suite
2. Run security audit
3. Check documentation
4. Update CHANGELOG.md
5. Bump version numbers
6. Create release branch

### Release Process
```bash
# 1. Update versions
cargo set-version 0.2.0

# 2. Run final checks
cargo test --all-features
cargo audit
cargo doc --all-features

# 3. Create release commit
git commit -am "Release v0.2.0"
git tag -s v0.2.0 -m "Release version 0.2.0"

# 4. Push release
git push origin main --tags

# 5. Publish to crates.io (in order)
cargo publish -p crypto-tee-vendor
cargo publish -p crypto-tee-platform
cargo publish -p crypto-tee
cargo publish -p crypto-tee-rfc9421
```

## Troubleshooting

### Build Issues

#### Missing Dependencies
```bash
# Linux
sudo apt-get install pkg-config libssl-dev

# macOS
brew install openssl

# Windows
# Install Visual Studio Build Tools
```

#### Cross-compilation
```bash
# Install targets
rustup target add aarch64-linux-android
rustup target add aarch64-apple-ios

# Install cross
cargo install cross

# Build with cross
cross build --target aarch64-linux-android
```

### Test Failures

#### Async Runtime
```rust
// Use tokio::test for async tests
#[tokio::test]
async fn test_async() {
    // Test implementation
}

// Configure runtime
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_concurrent() {
    // Test implementation
}
```

#### Platform-specific
```rust
// Skip tests on unsupported platforms
#[test]
#[cfg_attr(not(target_os = "macos"), ignore)]
fn test_secure_enclave() {
    // macOS-only test
}
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

**Last Updated**: December 2024