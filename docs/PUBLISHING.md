# Publishing Guide

This document describes how to publish CryptoTEE crates to crates.io.

## Prerequisites

1. **Crates.io Account**
   - Create an account at https://crates.io
   - Run `cargo login` and enter your API token

2. **Permissions**
   - You must be an owner of all CryptoTEE crates
   - Request ownership from existing maintainers if needed

3. **Tools**
   - Rust 1.70+ with cargo
   - cargo-audit: `cargo install cargo-audit`
   - cargo-deny: `cargo install cargo-deny`

## Pre-publish Checklist

Run the automated check:
```bash
./scripts/pre-publish-check.sh
```

Manual checks:
- [ ] Version numbers updated in all Cargo.toml files
- [ ] CHANGELOG.md updated with release notes
- [ ] All tests passing on all platforms
- [ ] Documentation builds without warnings
- [ ] Examples run successfully
- [ ] No security advisories
- [ ] Git repository is clean
- [ ] On main branch with latest changes

## Publishing Process

### 1. Version Bump

Update version in workspace Cargo.toml:
```toml
[workspace.package]
version = "0.1.1"  # New version
```

### 2. Update Documentation

1. Update CHANGELOG.md with release notes
2. Update README.md if needed
3. Regenerate API docs: `cargo doc --all-features`

### 3. Final Tests

```bash
# Run full test suite
cargo test --all-features

# Check each package
cargo package --list -p crypto-tee-vendor
cargo package --list -p crypto-tee-platform
cargo package --list -p crypto-tee
cargo package --list -p crypto-tee-rfc9421
```

### 4. Publish to Crates.io

Run the publishing script:
```bash
./scripts/publish.sh
```

Or manually publish in order:
```bash
# Must publish in dependency order
cd crypto-tee-vendor && cargo publish
sleep 30  # Wait for crates.io

cd ../crypto-tee-platform && cargo publish
sleep 30

cd ../crypto-tee && cargo publish
sleep 30

cd ../crypto-tee-rfc9421 && cargo publish
```

### 5. Create GitHub Release

1. Push the version tag:
   ```bash
   git tag -s v0.1.0 -m "Release version 0.1.0"
   git push origin v0.1.0
   ```

2. Create release on GitHub:
   - Go to https://github.com/procatstler/crypto-tee-core/releases
   - Click "Create a new release"
   - Select the tag
   - Copy release notes from CHANGELOG.md
   - Attach any binaries if applicable

### 6. Post-release

1. Announce on:
   - Twitter/X
   - Reddit (r/rust)
   - Rust Users Forum
   - Project Discord/Slack

2. Update dependent projects

3. Monitor for issues:
   - GitHub issues
   - Crates.io reviews
   - Security advisories

## Troubleshooting

### Publishing Errors

**Error: crate version already exists**
- You cannot republish the same version
- Bump the version number and try again

**Error: dependency not found**
- Ensure dependencies are published first
- Wait 30-60 seconds between publishes

**Error: authentication required**
- Run `cargo login`
- Check your crates.io API token

### Yanking a Release

If a critical issue is found:
```bash
cargo yank --vers 0.1.0 -p crypto-tee
```

To un-yank:
```bash
cargo yank --vers 0.1.0 --undo -p crypto-tee
```

## Version Policy

We follow Semantic Versioning:
- MAJOR: Breaking API changes
- MINOR: New features (backward compatible)  
- PATCH: Bug fixes

### What Requires a Major Version Bump

- Removing public APIs
- Changing function signatures
- Changing trait requirements
- Major behavior changes

### What Requires a Minor Version Bump

- Adding new public APIs
- Adding new features
- Adding new dependencies
- Performance improvements

### What Requires a Patch Version Bump

- Bug fixes
- Documentation updates
- Internal refactoring
- Dependency updates (compatible)

## Security Releases

For security issues:
1. Do NOT create public issues
2. Fix the vulnerability
3. Request CVE if needed
4. Publish patched version
5. Announce with security advisory

## Maintenance

### Regular Tasks

- Weekly: Check for security advisories
- Monthly: Update dependencies
- Quarterly: Review and update documentation
- Yearly: Consider API improvements

### Deprecation Policy

1. Mark deprecated in current version
2. Announce in release notes
3. Keep for at least 2 minor versions
4. Remove in next major version

Example:
```rust
#[deprecated(since = "0.2.0", note = "Use new_function instead")]
pub fn old_function() {}
```

## Contact

For publishing questions:
- GitHub Issues
- Email: maintainers@example.com
- Discord: #crypto-tee-dev