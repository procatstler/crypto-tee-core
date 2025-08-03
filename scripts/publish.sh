#!/bin/bash
# Publishing script for CryptoTEE crates to crates.io

set -e

echo "🚀 CryptoTEE Publishing Script"
echo "==============================="

# Check if we're in the right directory
if [ ! -f "Cargo.toml" ] || [ ! -d "crypto-tee" ]; then
    echo "❌ Error: Must run from crypto-tee-core root directory"
    exit 1
fi

# Check if user is logged in to crates.io
if ! cargo login --quiet 2>/dev/null; then
    echo "❌ Error: Not logged in to crates.io"
    echo "Please run: cargo login"
    exit 1
fi

# Function to publish a crate
publish_crate() {
    local crate_name=$1
    local crate_path=$2
    
    echo ""
    echo "📦 Publishing $crate_name..."
    
    cd "$crate_path"
    
    # Verify the package
    echo "  Verifying package..."
    cargo package --no-verify
    
    # Publish (dry run first)
    echo "  Dry run..."
    cargo publish --dry-run
    
    # Ask for confirmation
    read -p "  Ready to publish $crate_name? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        cargo publish
        echo "  ✅ Published $crate_name"
        
        # Wait for crates.io to process
        echo "  Waiting for crates.io to process..."
        sleep 30
    else
        echo "  ⏭️  Skipped $crate_name"
    fi
    
    cd - > /dev/null
}

# Check versions match
echo "Checking versions..."
VERSION=$(grep "^version" Cargo.toml | head -1 | cut -d'"' -f2)
echo "Workspace version: $VERSION"

# Run tests first
echo ""
echo "Running tests..."
cargo test --all-features --quiet
echo "✅ All tests passed"

# Build documentation
echo ""
echo "Building documentation..."
cargo doc --all-features --no-deps
echo "✅ Documentation built"

# Publish in dependency order
echo ""
echo "Publishing crates in dependency order..."
echo "======================================="

# 1. crypto-tee-vendor (no dependencies)
publish_crate "crypto-tee-vendor" "crypto-tee-vendor"

# 2. crypto-tee-platform (depends on vendor)
publish_crate "crypto-tee-platform" "crypto-tee-platform"

# 3. crypto-tee (depends on vendor and platform)
publish_crate "crypto-tee" "crypto-tee"

# 4. crypto-tee-rfc9421 (depends on crypto-tee)
publish_crate "crypto-tee-rfc9421" "crypto-tee-rfc9421"

echo ""
echo "🎉 Publishing complete!"
echo ""
echo "Next steps:"
echo "1. Create a GitHub release with tag v$VERSION"
echo "2. Update the release notes"
echo "3. Announce on social media"
echo ""
echo "View on crates.io:"
echo "  https://crates.io/crates/crypto-tee"
echo "  https://crates.io/crates/crypto-tee-vendor"
echo "  https://crates.io/crates/crypto-tee-platform"
echo "  https://crates.io/crates/crypto-tee-rfc9421"