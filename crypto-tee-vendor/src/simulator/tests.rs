//! Tests for TEE simulators

use super::*;
use crate::types::*;
use tokio::time::Duration;

#[tokio::test]
async fn test_generic_simulator_basic_operations() {
    let config = SimulationConfig::default();
    let simulator = base::GenericTEESimulator::new(config);

    // Test probe
    let capabilities = simulator.probe().await.expect("Simulator test should succeed");
    assert!(!capabilities.algorithms.is_empty());
    assert!(capabilities.hardware_backed);

    // Test key generation
    let key_params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: true,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key_handle =
        simulator.generate_key(&key_params).await.expect("Simulator test should succeed");
    assert!(key_handle.id.contains("sim_key_"));
    assert_eq!(key_handle.algorithm, Algorithm::Ed25519);

    // Test signing
    let test_data = b"test message for signing";
    let signature =
        simulator.sign(&key_handle, test_data).await.expect("Simulator test should succeed");
    assert!(!signature.data.is_empty());
    assert_eq!(signature.algorithm, Algorithm::Ed25519);

    // Test verification
    let valid = simulator
        .verify(&key_handle, test_data, &signature)
        .await
        .expect("Simulator test should succeed");
    assert!(valid);

    // Test deletion
    simulator.delete_key(&key_handle).await.expect("Simulator test should succeed");

    // Verify key is deleted
    let result = simulator.sign(&key_handle, test_data).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_samsung_simulator() {
    let config = SimulationConfig::default();
    let simulator = samsung::SamsungTEESimulator::new(config);

    let capabilities = simulator.probe().await.expect("Simulator test should succeed");
    assert!(capabilities.hardware_backed);
    assert!(capabilities.attestation);

    // Test Knox-specific key generation using available types
    #[cfg(feature = "simulator-samsung")]
    let samsung_params = super::samsung::KnoxParams {
        use_knox_vault: true,
        require_user_auth: false,
        auth_validity_seconds: None,
        use_trustzone: true,
        enable_attestation: false,
        container_id: None,
    };

    let key_params = KeyGenParams {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: true,
        exportable: false,
        usage: KeyUsage::default(),
        #[cfg(feature = "simulator-samsung")]
        vendor_params: Some(VendorParams::Samsung(samsung_params)),
        #[cfg(not(feature = "simulator-samsung"))]
        vendor_params: Some(VendorParams::Generic { hardware_backed: true, require_auth: false }),
    };

    let key_handle =
        simulator.generate_key(&key_params).await.expect("Simulator test should succeed");
    assert!(key_handle.id.contains("knox_"));
    assert_eq!(key_handle.vendor, "TEE Simulator");
}

#[tokio::test]
async fn test_apple_simulator() {
    let config = SimulationConfig::default();
    let simulator = apple::AppleTEESimulator::new(config);

    let capabilities = simulator.probe().await.expect("Simulator test should succeed");
    assert_eq!(capabilities.name, "Apple Secure Enclave Simulator");
    assert!(capabilities.features.biometric_bound);

    // Test that key import is not supported
    let key_params = KeyGenParams {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: true,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let result = simulator.import_key(b"dummy_key_data", &key_params).await;
    assert!(result.is_err());

    // Test Secure Enclave key generation
    let key_handle =
        simulator.generate_key(&key_params).await.expect("Simulator test should succeed");
    assert!(key_handle.id.contains("se_"));
    assert_eq!(key_handle.vendor, "TEE Simulator");
}

#[tokio::test]
async fn test_qualcomm_simulator() {
    let config = SimulationConfig::default();
    let simulator = qualcomm::QualcommTEESimulator::new(config);

    let capabilities = simulator.probe().await.expect("Simulator test should succeed");
    assert_eq!(capabilities.name, "Qualcomm QSEE Simulator");
    assert!(capabilities.algorithms.len() >= 6); // Should support many algorithms

    // Test QSEE key generation
    let key_params = KeyGenParams {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: true,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key_handle =
        simulator.generate_key(&key_params).await.expect("Simulator test should succeed");
    assert!(key_handle.id.contains("qsee_"));
    assert_eq!(key_handle.vendor, "TEE Simulator");
}

#[tokio::test]
async fn test_simulator_factory() {
    let config = SimulationConfig::default();

    // Test creating different simulators
    let samsung_sim = SimulatorFactory::create_samsung_simulator(config.clone());
    assert_eq!(samsung_sim.simulator_type(), SimulatorType::Samsung);

    let apple_sim = SimulatorFactory::create_apple_simulator(config.clone());
    assert_eq!(apple_sim.simulator_type(), SimulatorType::Apple);

    let qualcomm_sim = SimulatorFactory::create_qualcomm_simulator(config.clone());
    assert_eq!(qualcomm_sim.simulator_type(), SimulatorType::Qualcomm);

    let generic_sim = SimulatorFactory::create_generic_simulator(config);
    assert_eq!(generic_sim.simulator_type(), SimulatorType::Generic);
}

#[tokio::test]
async fn test_error_injection() {
    let config = SimulationConfig {
        error_injection_rate: 0.0, // Start with no errors
        ..Default::default()
    };

    let mut simulator = base::GenericTEESimulator::new(config);

    // Configure simulator
    let error_config = SimulationConfig { error_injection_rate: 0.0, ..Default::default() };
    simulator.configure_simulation(error_config).await.expect("Simulator test should succeed");

    // Inject a specific error
    simulator
        .inject_error(SimulatedErrorType::HardwareFailure)
        .await
        .expect("Simulator test should succeed");

    // Next operation should fail
    let key_params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: true,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let result = simulator.generate_key(&key_params).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_simulation_stats() {
    let config = SimulationConfig::default();
    let simulator = base::GenericTEESimulator::new(config);

    // Get initial stats
    let initial_stats =
        simulator.get_simulation_stats().await.expect("Simulator test should succeed");
    assert_eq!(initial_stats.total_operations, 0);

    // Perform some operations
    let key_params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: true,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let key_handle =
        simulator.generate_key(&key_params).await.expect("Simulator test should succeed");
    let test_data = b"test data";
    let _signature =
        simulator.sign(&key_handle, test_data).await.expect("Simulator test should succeed");

    // Check stats updated
    let updated_stats =
        simulator.get_simulation_stats().await.expect("Simulator test should succeed");
    assert!(updated_stats.total_operations > initial_stats.total_operations);
    assert!(updated_stats.successful_operations > 0);
    assert_eq!(updated_stats.active_keys, 1);
}

#[tokio::test]
async fn test_attestation_simulation() {
    let config = SimulationConfig::default();
    let simulator = base::GenericTEESimulator::new(config);

    let attestation =
        simulator.simulate_attestation().await.expect("Simulator test should succeed");

    assert!(!attestation.certificate_chain.is_empty());
    assert!(attestation.hardware_verified);
    assert!(!attestation.device_identity.device_id.is_empty());
    assert_eq!(attestation.security_level, SecurityLevel::TrustedExecutionEnvironment);
}

#[tokio::test]
async fn test_performance_simulation() {
    let performance_config = PerformanceConfig {
        key_gen_delay_ms: 100,
        sign_delay_ms: 50,
        verify_delay_ms: 25,
        jitter_factor: 0.0, // No jitter for predictable timing
    };

    let config = SimulationConfig { performance_config, ..Default::default() };

    let simulator = base::GenericTEESimulator::new(config);

    let key_params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: true,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    // Measure key generation time
    let start = std::time::Instant::now();
    let key_handle =
        simulator.generate_key(&key_params).await.expect("Simulator test should succeed");
    let key_gen_time = start.elapsed();

    // Should take at least the configured delay
    assert!(key_gen_time >= Duration::from_millis(100));

    // Measure signing time
    let test_data = b"test data";
    let start = std::time::Instant::now();
    let _signature =
        simulator.sign(&key_handle, test_data).await.expect("Simulator test should succeed");
    let sign_time = start.elapsed();

    assert!(sign_time >= Duration::from_millis(50));
}

#[tokio::test]
async fn test_simulator_reset() {
    let config = SimulationConfig::default();
    let mut simulator = base::GenericTEESimulator::new(config);

    // Create some keys and perform operations
    let key_params = KeyGenParams {
        algorithm: Algorithm::Ed25519,
        hardware_backed: true,
        exportable: false,
        usage: KeyUsage::default(),
        vendor_params: None,
    };

    let _key1 = simulator.generate_key(&key_params).await.expect("Simulator test should succeed");
    let _key2 = simulator.generate_key(&key_params).await.expect("Simulator test should succeed");

    let stats_before =
        simulator.get_simulation_stats().await.expect("Simulator test should succeed");
    assert!(stats_before.total_operations > 0);
    assert_eq!(stats_before.active_keys, 2);

    // Reset simulator
    simulator.reset_simulator().await.expect("Simulator test should succeed");

    let stats_after =
        simulator.get_simulation_stats().await.expect("Simulator test should succeed");
    assert_eq!(stats_after.total_operations, 0);
    assert_eq!(stats_after.active_keys, 0);
}
