//! TEE Hardware Simulators
//!
//! This module provides realistic simulations of various TEE hardware implementations,
//! enabling comprehensive testing and development without requiring actual hardware.

pub mod apple;
pub mod attestation;
pub mod base;
pub mod errors;
pub mod qualcomm;
pub mod samsung;
pub mod secure_storage;

use crate::error::VendorResult;
use crate::traits::VendorTEE;
// Imports managed per-module to avoid unused warnings

#[cfg(test)]
mod tests;

/// TEE Simulator trait extending VendorTEE with simulation-specific features
#[async_trait::async_trait]
pub trait TEESimulator: VendorTEE + Send + Sync {
    /// Get simulator type
    fn simulator_type(&self) -> SimulatorType;

    /// Configure simulation parameters
    async fn configure_simulation(&mut self, config: SimulationConfig) -> VendorResult<()>;

    /// Inject simulated hardware errors
    async fn inject_error(&mut self, error_type: SimulatedErrorType) -> VendorResult<()>;

    /// Get simulation statistics
    async fn get_simulation_stats(&self) -> VendorResult<SimulationStats>;

    /// Reset simulator state
    async fn reset_simulator(&mut self) -> VendorResult<()>;

    /// Simulate hardware attestation
    async fn simulate_attestation(&self) -> VendorResult<SimulatedAttestation>;
}

/// Types of TEE simulators
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulatorType {
    Samsung,
    Apple,
    Qualcomm,
    Generic,
}

/// Simulation configuration parameters
#[derive(Debug, Clone)]
pub struct SimulationConfig {
    /// Enable hardware security features
    pub hardware_security_enabled: bool,

    /// Maximum number of keys to store
    pub max_key_slots: u32,

    /// Simulate biometric authentication
    pub biometric_auth_enabled: bool,

    /// Enable secure deletion simulation
    pub secure_deletion_enabled: bool,

    /// Attestation key configuration
    pub attestation_config: Option<AttestationConfig>,

    /// Error injection probability (0.0 - 1.0)
    pub error_injection_rate: f32,

    /// Performance simulation parameters
    pub performance_config: PerformanceConfig,
}

/// Attestation simulation configuration
#[derive(Debug, Clone)]
pub struct AttestationConfig {
    /// Root certificate chain
    pub root_ca_enabled: bool,

    /// Device-specific certificate
    pub device_cert_enabled: bool,

    /// Include hardware verification
    pub hardware_verification: bool,
}

/// Performance simulation parameters
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Key generation delay (milliseconds)
    pub key_gen_delay_ms: u64,

    /// Signing operation delay (milliseconds)
    pub sign_delay_ms: u64,

    /// Verification delay (milliseconds)
    pub verify_delay_ms: u64,

    /// Random jitter factor (0.0 - 1.0)
    pub jitter_factor: f32,
}

/// Types of errors that can be simulated
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimulatedErrorType {
    /// Hardware communication failure
    HardwareFailure,

    /// Insufficient permissions
    PermissionDenied,

    /// Resource exhaustion
    ResourceExhausted,

    /// Authentication failure
    AuthenticationFailed,

    /// Key storage corruption
    StorageCorruption,

    /// Secure element malfunction
    SecureElementError,

    /// Network connectivity issues (for remote attestation)
    NetworkError,
}

/// Simulation runtime statistics
#[derive(Debug, Clone)]
pub struct SimulationStats {
    /// Total operations performed
    pub total_operations: u64,

    /// Successful operations
    pub successful_operations: u64,

    /// Failed operations
    pub failed_operations: u64,

    /// Keys currently stored
    pub active_keys: u32,

    /// Maximum keys reached
    pub peak_key_count: u32,

    /// Errors injected
    pub injected_errors: u64,

    /// Average operation time (milliseconds)
    pub avg_operation_time_ms: f64,

    /// Security violations detected
    pub security_violations: u64,
}

/// Simulated attestation result
#[derive(Debug, Clone)]
pub struct SimulatedAttestation {
    /// Attestation certificate chain
    pub certificate_chain: Vec<Vec<u8>>,

    /// Hardware verification result
    pub hardware_verified: bool,

    /// Device identity
    pub device_identity: DeviceIdentity,

    /// Security level achieved
    pub security_level: SecurityLevel,

    /// Timestamp of attestation
    pub timestamp: std::time::SystemTime,
}

/// Device identity information
#[derive(Debug, Clone)]
pub struct DeviceIdentity {
    /// Unique device identifier
    pub device_id: String,

    /// Hardware model
    pub hardware_model: String,

    /// Firmware version
    pub firmware_version: String,

    /// Security patch level
    pub security_patch_level: String,
}

/// Security level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SecurityLevel {
    /// Software implementation only
    Software = 0,

    /// Trusted execution environment
    TrustedExecutionEnvironment = 100,

    /// Hardware security module
    HardwareSecurityModule = 200,

    /// Secure element with certification
    CertifiedSecureElement = 300,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            hardware_security_enabled: true,
            max_key_slots: 32,
            biometric_auth_enabled: false,
            secure_deletion_enabled: true,
            attestation_config: Some(AttestationConfig::default()),
            error_injection_rate: 0.0,
            performance_config: PerformanceConfig::default(),
        }
    }
}

impl Default for AttestationConfig {
    fn default() -> Self {
        Self { root_ca_enabled: true, device_cert_enabled: true, hardware_verification: true }
    }
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self { key_gen_delay_ms: 50, sign_delay_ms: 10, verify_delay_ms: 5, jitter_factor: 0.1 }
    }
}

impl Default for SimulationStats {
    fn default() -> Self {
        Self {
            total_operations: 0,
            successful_operations: 0,
            failed_operations: 0,
            active_keys: 0,
            peak_key_count: 0,
            injected_errors: 0,
            avg_operation_time_ms: 0.0,
            security_violations: 0,
        }
    }
}

/// Factory for creating TEE simulators
pub struct SimulatorFactory;

impl SimulatorFactory {
    /// Create a Samsung TEE simulator
    pub fn create_samsung_simulator(config: SimulationConfig) -> Box<dyn TEESimulator> {
        Box::new(samsung::SamsungTEESimulator::new(config))
    }

    /// Create an Apple TEE simulator
    pub fn create_apple_simulator(config: SimulationConfig) -> Box<dyn TEESimulator> {
        Box::new(apple::AppleTEESimulator::new(config))
    }

    /// Create a Qualcomm TEE simulator
    pub fn create_qualcomm_simulator(config: SimulationConfig) -> Box<dyn TEESimulator> {
        Box::new(qualcomm::QualcommTEESimulator::new(config))
    }

    /// Create a generic TEE simulator
    pub fn create_generic_simulator(config: SimulationConfig) -> Box<dyn TEESimulator> {
        Box::new(base::GenericTEESimulator::new(config))
    }

    /// Auto-detect and create appropriate simulator for current platform
    pub fn create_platform_simulator() -> Box<dyn TEESimulator> {
        let config = SimulationConfig::default();

        #[cfg(target_os = "android")]
        return Self::create_samsung_simulator(config);

        #[cfg(target_os = "ios")]
        return Self::create_apple_simulator(config);

        // Default to generic for other platforms
        Self::create_generic_simulator(config)
    }
}
