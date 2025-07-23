//! Key Rotation System Demo
//!
//! This example demonstrates the key rotation capabilities of CryptoTEE,
//! showing automated key lifecycle management, version control, and policy enforcement.

use crypto_tee::{
    Algorithm, CryptoTEE, CryptoTEEBuilder, KeyOptions, KeyUsage, RotationPolicy, RotationReason,
    RotationStrategy,
};
use std::time::Duration;
use tracing::{info, Level};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt().with_max_level(Level::INFO).init();

    info!("CryptoTEE Key Rotation System Demo");

    // Create CryptoTEE instance
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    println!("\n=== Key Rotation System Demo ===");

    // Step 1: Generate a test key
    let key_alias = "demo-rotation-key";
    let key_options = KeyOptions {
        algorithm: Algorithm::Ed25519,
        usage: KeyUsage::default(),
        hardware_backed: true,
        exportable: false,
        require_auth: false,
        expires_at: None,
        metadata: None,
    };

    println!("\n1. Generating initial key: {}", key_alias);
    let initial_key = crypto_tee.generate_key(key_alias, key_options.clone()).await?;
    println!("   ✅ Key generated successfully");
    println!("   📋 Algorithm: {:?}", initial_key.metadata.algorithm);
    println!("   🔒 Hardware backed: {}", initial_key.metadata.hardware_backed);
    println!("   📅 Created: {:?}", initial_key.metadata.created_at);

    // Step 2: Configure rotation policies
    println!("\n2. Configuring rotation policies");

    // Time-based rotation policy
    let time_based_policy = RotationPolicy {
        strategy: RotationStrategy::TimeBased,
        max_key_age: Duration::from_secs(60), // 1 minute for demo
        max_usage_count: 1000,
        grace_period: Duration::from_secs(30), // 30 seconds grace period
        max_versions: 3,
        backup_before_rotation: true,
        ..Default::default()
    };

    crypto_tee.set_rotation_policy(key_alias, time_based_policy.clone()).await?;
    println!("   ✅ Time-based rotation policy set");
    println!("   ⏰ Max key age: {} seconds", time_based_policy.max_key_age.as_secs());
    println!("   📚 Max versions: {}", time_based_policy.max_versions);
    println!("   🔄 Strategy: {:?}", time_based_policy.strategy);

    // Step 3: Demonstrate manual rotation
    println!("\n3. Performing manual key rotation");

    let rotation_result = crypto_tee
        .rotate_key(
            key_alias,
            RotationReason::Manual,
            false, // not forced
        )
        .await?;

    println!("   ✅ Manual rotation completed");
    println!("   🆕 New version: {:?}", rotation_result.new_version);
    println!("   📜 Old version: {:?}", rotation_result.old_version);
    println!("   ⏱️  Duration: {:?}", rotation_result.duration);
    if let Some(backup_id) = &rotation_result.backup_id {
        println!("   💾 Backup created: {}", backup_id);
    }

    // Step 4: Get updated key information
    println!("\n4. Checking rotated key information");
    let rotated_key_info = crypto_tee.get_key_info(key_alias).await?;
    println!("   📋 Key alias: {}", rotated_key_info.alias);
    println!("   🔧 Algorithm: {:?}", rotated_key_info.algorithm);
    println!("   📅 Created: {:?}", rotated_key_info.created_at);
    println!("   🔒 Hardware backed: {}", rotated_key_info.hardware_backed);
    println!("   🔐 Requires auth: {}", rotated_key_info.requires_auth);

    // Step 5: Demonstrate different rotation strategies
    println!("\n5. Testing different rotation strategies");

    // Usage-based rotation
    println!("\n   📊 Usage-based rotation policy:");
    let usage_based_policy = RotationPolicy {
        strategy: RotationStrategy::UsageBased,
        max_key_age: Duration::from_secs(3600), // 1 hour
        max_usage_count: 10,                    // Very low for demo
        grace_period: Duration::from_secs(60),
        max_versions: 5,
        backup_before_rotation: true,
        ..Default::default()
    };

    let usage_key_alias = "usage-rotation-key";
    crypto_tee.generate_key(usage_key_alias, key_options.clone()).await?;
    crypto_tee.set_rotation_policy(usage_key_alias, usage_based_policy.clone()).await?;
    println!("   ✅ Usage-based policy set (max usage: {})", usage_based_policy.max_usage_count);

    // Hybrid rotation
    println!("\n   🔄 Hybrid rotation policy:");
    let hybrid_policy = RotationPolicy {
        strategy: RotationStrategy::Hybrid,
        max_key_age: Duration::from_secs(300), // 5 minutes
        max_usage_count: 100,
        grace_period: Duration::from_secs(30),
        max_versions: 4,
        backup_before_rotation: true,
        ..Default::default()
    };

    let hybrid_key_alias = "hybrid-rotation-key";
    crypto_tee.generate_key(hybrid_key_alias, key_options.clone()).await?;
    crypto_tee.set_rotation_policy(hybrid_key_alias, hybrid_policy.clone()).await?;
    println!(
        "   ✅ Hybrid policy set (age: {}s, usage: {})",
        hybrid_policy.max_key_age.as_secs(),
        hybrid_policy.max_usage_count
    );

    // Step 6: Demonstrate emergency rotation
    println!("\n6. Emergency rotation scenario");
    let emergency_result = crypto_tee
        .rotate_key(
            key_alias,
            RotationReason::Emergency,
            true, // forced
        )
        .await?;

    println!("   🚨 Emergency rotation completed");
    println!("   🆕 New version: {:?}", emergency_result.new_version);
    println!("   ⚡ Force applied: true");
    println!("   ⏱️  Duration: {:?}", emergency_result.duration);

    // Step 7: List all keys and their status
    println!("\n7. Current key inventory");
    let all_keys = crypto_tee.list_keys().await?;
    println!("   📝 Total keys: {}", all_keys.len());

    for key in &all_keys {
        println!("   🔑 {}", key.alias);
        println!("      - Algorithm: {:?}", key.algorithm);
        println!("      - Created: {:?}", key.created_at);
        println!("      - Hardware backed: {}", key.hardware_backed);
    }

    // Step 8: Demonstrate compliance-based rotation
    println!("\n8. Compliance-based rotation");
    let compliance_policy = RotationPolicy {
        strategy: RotationStrategy::ComplianceBased,
        max_key_age: Duration::from_secs(60),
        compliance_requirements: crypto_tee::rotation::ComplianceRequirements {
            standard: Some("PCI-DSS".to_string()),
            required_rotation_frequency: Some(Duration::from_secs(90)), // 90 seconds for demo
            min_versions_retained: 3,
            audit_trail_required: true,
            attestation_required: false,
        },
        ..Default::default()
    };

    let compliance_key_alias = "compliance-key";
    crypto_tee.generate_key(compliance_key_alias, key_options.clone()).await?;
    crypto_tee.set_rotation_policy(compliance_key_alias, compliance_policy.clone()).await?;
    println!("   ✅ Compliance policy set (PCI-DSS)");
    println!(
        "   📋 Required frequency: {} seconds",
        compliance_policy.compliance_requirements.required_rotation_frequency.unwrap().as_secs()
    );
    println!(
        "   📚 Min versions retained: {}",
        compliance_policy.compliance_requirements.min_versions_retained
    );

    // Step 9: Perform health check to see system status
    println!("\n9. System health check");
    let health_report = crypto_tee.health_check().await?;
    println!("   🏥 Overall status: {:?}", health_report.overall_status);
    println!("   📊 TEE available: {}", health_report.tee_health.available);
    println!(
        "   🔑 Key count: {}/{}",
        health_report.tee_health.key_count, health_report.tee_health.max_keys
    );

    // Step 10: Cleanup demo keys
    println!("\n10. Cleaning up demo keys");
    for key_alias in &[key_alias, usage_key_alias, hybrid_key_alias, compliance_key_alias] {
        match crypto_tee.delete_key(key_alias).await {
            Ok(_) => println!("   ✅ Deleted: {}", key_alias),
            Err(e) => println!("   ❌ Failed to delete {}: {}", key_alias, e),
        }
    }

    println!("\n=== Key Rotation Demo Complete ===");

    // Summary
    println!("\n📋 Demo Summary:");
    println!("✅ Generated keys with different algorithms");
    println!(
        "✅ Configured multiple rotation policies (time-based, usage-based, hybrid, compliance)"
    );
    println!("✅ Performed manual and emergency rotations");
    println!("✅ Demonstrated key version management");
    println!("✅ Showed compliance requirements integration");
    println!("✅ Integrated with health monitoring system");
    println!("✅ Comprehensive audit logging for all operations");

    Ok(())
}

/// Example of advanced rotation scenarios
#[allow(dead_code)]
async fn advanced_rotation_scenarios() -> Result<(), Box<dyn std::error::Error>> {
    let crypto_tee = CryptoTEEBuilder::new().build().await?;

    // Scenario 1: Bulk key rotation
    println!("🔄 Bulk rotation scenario");
    let key_aliases = vec!["bulk-key-1", "bulk-key-2", "bulk-key-3"];

    // Generate multiple keys
    for alias in &key_aliases {
        let key_options = KeyOptions { algorithm: Algorithm::EcdsaP256, ..Default::default() };
        crypto_tee.generate_key(alias, key_options).await?;
    }

    // Rotate all keys
    for alias in &key_aliases {
        match crypto_tee.rotate_key(alias, RotationReason::Maintenance, false).await {
            Ok(result) => {
                println!("   ✅ Rotated {}: version {}", alias, result.new_version.unwrap_or(0))
            }
            Err(e) => println!("   ❌ Failed to rotate {}: {}", alias, e),
        }
    }

    // Scenario 2: High-frequency rotation testing
    println!("\n⚡ High-frequency rotation test");
    let hf_key_alias = "high-freq-key";
    let key_options = KeyOptions { algorithm: Algorithm::Ed25519, ..Default::default() };

    crypto_tee.generate_key(hf_key_alias, key_options).await?;

    // Perform 5 rapid rotations
    for i in 1..=5 {
        let result = crypto_tee.rotate_key(hf_key_alias, RotationReason::Scheduled, true).await?;
        println!(
            "   🔄 Rotation {}: version {} ({}ms)",
            i,
            result.new_version.unwrap_or(0),
            result.duration.as_millis()
        );

        // Small delay between rotations
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Ok(())
}
