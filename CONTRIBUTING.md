# Contributing to CryptoTEE

Thank you for your interest in contributing to CryptoTEE! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security](#security)
- [Release Process](#release-process)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read and understand it before contributing.

### Our Standards

- Be respectful and inclusive
- Welcome newcomers and help them get started
- Focus on constructive criticism
- Respect differing viewpoints and experiences
- Accept responsibility and apologize for mistakes

## Getting Started

### Prerequisites

- Rust 1.70 or later (MSRV: 1.70)
- Cargo and rustup
- Git
- Platform-specific requirements:
  - **Linux**: gcc, pkg-config, libssl-dev
  - **macOS**: Xcode Command Line Tools
  - **Windows**: Visual Studio Build Tools

### Initial Setup

1. Fork the repository on GitHub
2. Clone your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/crypto-tee-core.git
   cd crypto-tee-core
   ```

3. Add upstream remote:
   ```bash
   git remote add upstream https://github.com/procatstler/crypto-tee-core.git
   ```

4. Install development tools:
   ```bash
   # Install required components
   rustup component add rustfmt clippy llvm-tools-preview

   # Install additional tools
   cargo install cargo-audit cargo-deny cargo-tarpaulin
   ```

## Development Setup

### Building the Project

```bash
# Build all packages
cargo build --all-features

# Build specific package
cargo build -p crypto-tee

# Build with specific features
cargo build --features "simulator,software-fallback"

# Release build
cargo build --release --all-features
```

### Running Tests

```bash
# Run all tests
cargo test --all-features

# Run tests for specific package
cargo test -p crypto-tee-vendor

# Run tests with output
cargo test --all-features -- --nocapture

# Run specific test
cargo test test_key_generation

# Run integration tests only
cargo test --test integration_tests
```

### Running Benchmarks

```bash
# Run all benchmarks
cargo bench --all-features

# Run specific benchmark
cargo bench --bench performance_tests

# Run optimized benchmarks
cargo bench --bench optimized_performance
```

### Code Quality Checks

```bash
# Format code
cargo fmt --all

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Check documentation
cargo doc --all-features --no-deps

# Security audit
cargo audit

# License check
cargo deny check
```

## How to Contribute

### Reporting Issues

1. Check existing issues to avoid duplicates
2. Use issue templates when available
3. Provide detailed reproduction steps
4. Include system information
5. For security issues, follow our [Security Policy](.github/SECURITY.md)

### Submitting Pull Requests

1. Create a feature branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes following our coding standards

3. Add tests for new functionality

4. Update documentation as needed

5. Commit with descriptive messages:
   ```bash
   git commit -m "Add support for new TEE backend

   - Implement VendorTEE trait for NewBackend
   - Add integration tests
   - Update documentation"
   ```

6. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

7. Create a pull request using our template

### Pull Request Guidelines

- Keep PRs focused and reasonably sized
- One feature or fix per PR
- Include tests for new code
- Update documentation
- Ensure all CI checks pass
- Respond to review feedback promptly

## Coding Standards

### Rust Style Guide

We follow the official Rust style guide with some additions:

```rust
// Use explicit imports
use std::collections::HashMap;
use crate::error::{VendorError, VendorResult};

// Document public APIs
/// Generate a new cryptographic key
/// 
/// # Arguments
/// 
/// * `params` - Key generation parameters
/// 
/// # Returns
/// 
/// Returns a `VendorKeyHandle` on success
pub async fn generate_key(
    &self,
    params: &KeyGenParams,
) -> VendorResult<VendorKeyHandle> {
    // Implementation
}

// Use descriptive variable names
let key_algorithm = Algorithm::Ed25519;

// Prefer early returns
if !self.is_initialized() {
    return Err(VendorError::NotInitialized);
}

// Use error propagation
let key = self.create_key(params)?;
```

### Error Handling

- Use `Result<T, E>` for fallible operations
- Create specific error types
- Provide context in error messages
- Never panic in library code
- Use `expect()` only in tests with descriptive messages

### Security Considerations

- Never log sensitive data
- Use constant-time operations for cryptographic comparisons
- Implement `Zeroize` for sensitive data structures
- Validate all inputs
- Follow principle of least privilege

### Performance Guidelines

- Benchmark performance-critical code
- Use async/await appropriately
- Minimize allocations in hot paths
- Cache expensive computations
- Profile before optimizing

## Testing Guidelines

### Test Organization

```
tests/
├── integration_tests.rs    # Integration tests
├── performance_tests.rs    # Performance tests
└── helpers/               # Test utilities
    └── mod.rs

benches/
├── performance_tests.rs    # Benchmarks
└── optimized_performance.rs

src/
└── module.rs              # Unit tests in #[cfg(test)] modules
```

### Writing Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_generation() {
        // Arrange
        let params = KeyGenParams::default();
        
        // Act
        let result = generate_key(&params);
        
        // Assert
        assert!(result.is_ok());
        assert_eq!(result.unwrap().algorithm, Algorithm::Ed25519);
    }

    #[tokio::test]
    async fn test_async_operation() {
        // Test async code
    }
}
```

### Test Coverage

- Aim for >80% code coverage
- Test error conditions
- Test edge cases
- Use property-based testing for complex logic
- Include integration tests

## Documentation

### Code Documentation

```rust
//! Module-level documentation
//! 
//! This module provides...

/// Function documentation
/// 
/// # Arguments
/// 
/// * `param` - Description
/// 
/// # Returns
/// 
/// Description of return value
/// 
/// # Errors
/// 
/// Returns `Error` when...
/// 
/// # Examples
/// 
/// ```
/// # use crypto_tee::*;
/// let result = function(param)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn function(param: Type) -> Result<ReturnType> {
    // Implementation
}
```

### Documentation Requirements

- All public APIs must be documented
- Include examples for complex APIs
- Document error conditions
- Keep documentation up-to-date
- Use doctests for examples

## Security

### Security Review Process

1. All cryptographic changes require security review
2. Follow secure coding practices
3. Run security scans before submitting
4. Document security considerations
5. Follow responsible disclosure for vulnerabilities

### Security Checklist

- [ ] No sensitive data in logs
- [ ] Input validation implemented
- [ ] Error messages don't leak information
- [ ] Cryptographic operations use approved libraries
- [ ] Memory is properly zeroized
- [ ] No timing side channels
- [ ] Dependencies are secure

## Release Process

### Version Numbering

We follow Semantic Versioning (SemVer):
- MAJOR: Breaking API changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes

### Release Checklist

1. Update version numbers in Cargo.toml files
2. Update CHANGELOG.md
3. Run full test suite
4. Run security audit
5. Update documentation
6. Create release PR
7. Tag release after merge
8. Publish to crates.io

### Publishing Order

Due to dependencies, publish in this order:
1. crypto-tee-vendor
2. crypto-tee-platform
3. crypto-tee
4. crypto-tee-rfc9421

## Development Workflow

### Feature Development

1. Discuss in issue before major changes
2. Create feature branch
3. Implement with tests
4. Update documentation
5. Submit PR for review
6. Address feedback
7. Merge after approval

### Bug Fixes

1. Create issue with reproduction
2. Add failing test
3. Implement fix
4. Verify test passes
5. Submit PR with test

### Review Process

- Code review required for all changes
- Security review for cryptographic changes
- Performance review for critical paths
- Documentation review for API changes

## Platform-Specific Development

### Android (Samsung Knox / Qualcomm QSEE)

```bash
# Setup Android NDK
export ANDROID_NDK_ROOT=/path/to/ndk

# Build for Android
cargo build --target aarch64-linux-android --features "samsung,qualcomm"
```

### iOS/macOS (Apple Secure Enclave)

```bash
# Build for iOS
cargo build --target aarch64-apple-ios --features apple

# Build for macOS
cargo build --features apple
```

### Simulator Development

```bash
# Run with simulator
cargo test --features simulator

# Test specific vendor simulation
cargo test --features "simulator,samsung" samsung_
```

## Troubleshooting

### Common Issues

1. **Build failures**: Check Rust version and dependencies
2. **Test failures**: Ensure features are enabled correctly
3. **Documentation errors**: Run `cargo doc` locally first
4. **Clippy warnings**: Address all warnings before submitting

### Getting Help

- Check existing issues and discussions
- Ask in pull request reviews
- Contact maintainers for guidance

## Recognition

Contributors are recognized in:
- Release notes
- CONTRIBUTORS.md file
- Project documentation

Thank you for contributing to CryptoTEE!

---

**Last Updated**: December 2024
**Maintainer**: @procatstler