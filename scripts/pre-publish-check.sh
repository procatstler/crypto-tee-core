#!/bin/bash
# Pre-publish checklist for CryptoTEE

set -e

echo "🔍 CryptoTEE Pre-publish Checklist"
echo "==================================="

ERRORS=0

# Function to check and report
check() {
    local description=$1
    local command=$2
    
    echo -n "Checking $description... "
    
    if eval "$command" > /dev/null 2>&1; then
        echo "✅"
    else
        echo "❌"
        ERRORS=$((ERRORS + 1))
    fi
}

# Version checks
echo ""
echo "Version Information:"
VERSION=$(grep "^version" Cargo.toml | head -1 | cut -d'"' -f2)
echo "  Workspace version: $VERSION"

# Basic checks
echo ""
echo "Basic Checks:"
check "workspace builds" "cargo build --all-features"
check "tests pass" "cargo test --all-features"
check "no clippy warnings" "cargo clippy --all-features -- -D warnings"
check "documentation builds" "cargo doc --all-features --no-deps"
check "examples compile" "cargo build --examples"

# Security checks
echo ""
echo "Security Checks:"
check "no security advisories" "cargo audit"
check "dependencies allowed" "cargo deny check"

# Package checks
echo ""
echo "Package Checks:"
check "crypto-tee-vendor package" "cd crypto-tee-vendor && cargo package --list > /dev/null"
check "crypto-tee-platform package" "cd crypto-tee-platform && cargo package --list > /dev/null"
check "crypto-tee package" "cd crypto-tee && cargo package --list > /dev/null"
check "crypto-tee-rfc9421 package" "cd crypto-tee-rfc9421 && cargo package --list > /dev/null"

# Documentation checks
echo ""
echo "Documentation Checks:"
check "README exists" "test -f README.md"
check "LICENSE exists" "test -f LICENSE"
check "CHANGELOG exists" "test -f CHANGELOG.md"
check "all crates have READMEs" "test -f crypto-tee/README.md"

# Git checks
echo ""
echo "Git Checks:"
check "working directory clean" "git diff --quiet"
check "no untracked files" "test -z \"$(git ls-files --others --exclude-standard)\""
check "on main branch" "test \"$(git branch --show-current)\" = \"main\""

# Final report
echo ""
echo "==============================="
if [ $ERRORS -eq 0 ]; then
    echo "✅ All checks passed!"
    echo ""
    echo "Ready to publish with:"
    echo "  ./scripts/publish.sh"
else
    echo "❌ Found $ERRORS errors"
    echo ""
    echo "Please fix the issues before publishing."
    exit 1
fi