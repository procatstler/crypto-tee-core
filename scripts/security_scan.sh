#!/bin/bash

# CryptoTEE Security Analysis Script
# Performs comprehensive security checks on the codebase

echo "🔒 CryptoTEE Security Analysis"
echo "=============================="
echo

# Check for Cargo.toml security settings
echo "📦 Checking Cargo.toml security settings..."
if grep -r "strip = true" Cargo.toml > /dev/null; then
    echo "✅ Debug symbols stripping enabled"
else
    echo "⚠️  Consider enabling 'strip = true' in release profile"
fi

if grep -r "panic = \"abort\"" Cargo.toml > /dev/null; then
    echo "✅ Panic abort strategy configured"
else
    echo "⚠️  Consider setting 'panic = \"abort\"' for smaller binaries"
fi

echo

# Check for unsafe code
echo "🚨 Unsafe Code Analysis..."
unsafe_count=$(grep -r "unsafe" --include="*.rs" . | grep -v test | grep -v example | wc -l)
echo "   Total unsafe blocks: $unsafe_count"

if [ $unsafe_count -eq 0 ]; then
    echo "✅ No unsafe code found"
elif [ $unsafe_count -lt 20 ]; then
    echo "⚠️  Moderate unsafe usage - requires review"
else
    echo "❌ High unsafe usage - needs security audit"
fi

echo

# Check for error handling patterns
echo "⚠️  Error Handling Analysis..."
unwrap_count=$(grep -r "unwrap()" --include="*.rs" . | grep -v test | grep -v example | wc -l)
expect_count=$(grep -r "expect(" --include="*.rs" . | grep -v test | grep -v example | wc -l)
panic_count=$(grep -r "panic!" --include="*.rs" . | grep -v test | grep -v example | wc -l)

echo "   unwrap() calls: $unwrap_count"
echo "   expect() calls: $expect_count"  
echo "   panic! calls: $panic_count"

total_risky=$((unwrap_count + expect_count + panic_count))

if [ $total_risky -lt 50 ]; then
    echo "✅ Acceptable error handling patterns"
elif [ $total_risky -lt 100 ]; then
    echo "⚠️  Moderate risk - review error handling"
else
    echo "❌ High risk - improve error handling"
fi

echo

# Check for cryptographic best practices
echo "🔐 Cryptographic Implementation Check..."

# Check for hardcoded keys/secrets
hardcoded_secrets=$(grep -ri "key.*=.*[\"'][a-zA-Z0-9+/=]\{20,\}[\"']" --include="*.rs" . | grep -v test | grep -v example | wc -l)
if [ $hardcoded_secrets -eq 0 ]; then
    echo "✅ No hardcoded secrets detected"
else
    echo "❌ Potential hardcoded secrets found: $hardcoded_secrets"
fi

# Check for secure random usage
if grep -r "SystemRandom\|SecureRandom" --include="*.rs" . > /dev/null; then
    echo "✅ Secure random number generation used"
else
    echo "⚠️  Verify secure random number generation"
fi

# Check for zeroize usage
if grep -r "zeroize\|Zeroize" --include="*.rs" . > /dev/null; then
    echo "✅ Memory zeroization implemented"
else
    echo "⚠️  Consider implementing memory zeroization"
fi

echo

# Check dependencies for known vulnerabilities
echo "📋 Dependency Security Check..."
if command -v cargo-audit &> /dev/null; then
    echo "Running cargo audit..."
    if cargo audit --quiet 2>/dev/null; then
        echo "✅ No known vulnerabilities in dependencies"
    else
        echo "❌ Vulnerabilities found in dependencies"
    fi
else
    echo "⚠️  cargo-audit not installed - run 'cargo install cargo-audit'"
fi

echo

# Check for debug information leakage
echo "🔍 Information Disclosure Check..."
debug_logs=$(grep -r "debug!\|trace!" --include="*.rs" . | grep -E "(key|secret|token|password|private)" | wc -l)
if [ $debug_logs -eq 0 ]; then
    echo "✅ No sensitive data in debug logs"
else
    echo "⚠️  Potential sensitive data in debug logs: $debug_logs"
fi

echo

# Check for timing attack vulnerabilities
echo "⏱️  Timing Attack Analysis..."
if grep -r "constant_time\|ConstantTime" --include="*.rs" . > /dev/null; then
    echo "✅ Constant-time operations detected"
else
    echo "⚠️  Consider constant-time comparisons for sensitive operations"
fi

echo

# Platform-specific security checks
echo "🏗️  Platform Security Analysis..."

# Android specific
if [ -d "crypto-tee-vendor/src/samsung" ] || [ -d "crypto-tee-vendor/src/qualcomm" ]; then
    echo "📱 Android Security:"
    if grep -r "requireUserAuth\|biometric" --include="*.rs" . > /dev/null; then
        echo "   ✅ User authentication requirements found"
    fi
    if grep -r "StrongBox\|TEE" --include="*.rs" . > /dev/null; then
        echo "   ✅ Hardware security module integration"
    fi
fi

# iOS specific  
if [ -d "crypto-tee-vendor/src/apple" ]; then
    echo "🍎 iOS Security:"
    if grep -r "SecureEnclave\|TouchID\|FaceID" --include="*.rs" . > /dev/null; then
        echo "   ✅ Secure Enclave integration found"
    fi
    if grep -r "kSecAccessControl" --include="*.rs" . > /dev/null; then
        echo "   ✅ Access control implementation"
    fi
fi

echo

# Generate security score
echo "📊 Security Score Calculation..."
score=100

# Deduct points for issues
if [ $unsafe_count -gt 0 ]; then
    score=$((score - unsafe_count * 2))
fi

if [ $total_risky -gt 50 ]; then
    score=$((score - 10))
fi

if [ $hardcoded_secrets -gt 0 ]; then
    score=$((score - 20))
fi

if [ $debug_logs -gt 0 ]; then
    score=$((score - 5))
fi

# Ensure score doesn't go below 0
if [ $score -lt 0 ]; then
    score=0
fi

echo "Overall Security Score: $score/100"

if [ $score -ge 90 ]; then
    echo "🟢 Excellent security posture"
elif [ $score -ge 75 ]; then
    echo "🟡 Good security with minor issues"
elif [ $score -ge 60 ]; then
    echo "🟠 Moderate security - improvements needed"
else
    echo "🔴 Poor security - immediate attention required"
fi

echo
echo "Security analysis complete. Review findings above."
echo "For detailed analysis, see SECURITY_AUDIT.md"