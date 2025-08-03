//! Simulator-specific error types and error injection mechanisms

use crate::error::VendorError;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use thiserror::Error;

/// Simulation-specific errors
#[derive(Error, Debug)]
pub enum SimulatorError {
    #[error("Simulation configuration error: {0}")]
    ConfigurationError(String),

    #[error("Simulator not initialized")]
    NotInitialized,

    #[error("Simulation limit exceeded: {0}")]
    LimitExceeded(String),

    #[error("Vendor-specific simulation error: {0}")]
    VendorSpecific(String),

    #[error("Hardware simulation failed: {0}")]
    HardwareSimulation(String),

    #[error("Attestation simulation failed: {0}")]
    AttestationFailed(String),
}

impl From<SimulatorError> for VendorError {
    fn from(err: SimulatorError) -> Self {
        match err {
            SimulatorError::ConfigurationError(msg) => VendorError::ConfigurationError(msg),
            SimulatorError::NotInitialized => {
                VendorError::NotInitialized("Simulator not initialized".to_string())
            }
            SimulatorError::LimitExceeded(msg) => VendorError::NotSupported(msg),
            SimulatorError::VendorSpecific(msg) => VendorError::HardwareError(msg),
            SimulatorError::HardwareSimulation(msg) => VendorError::HardwareError(msg),
            SimulatorError::AttestationFailed(msg) => VendorError::AttestationFailed(msg),
        }
    }
}

/// Error injection service for realistic error simulation
#[derive(Debug)]
pub struct ErrorInjectionService {
    /// Configured error scenarios
    scenarios: Arc<Mutex<Vec<ErrorScenario>>>,

    /// Error history for analysis
    error_history: Arc<Mutex<VecDeque<ErrorEvent>>>,

    /// Maximum history size
    max_history: usize,
}

/// Error scenario configuration
#[derive(Debug, Clone)]
pub struct ErrorScenario {
    /// Error type to inject
    pub error_type: super::SimulatedErrorType,

    /// Trigger condition
    pub trigger: ErrorTrigger,

    /// How many times to trigger
    pub max_occurrences: Option<u32>,

    /// Current occurrence count
    pub current_count: u32,

    /// Scenario enabled
    pub enabled: bool,
}

/// When to trigger an error
#[derive(Debug, Clone)]
pub enum ErrorTrigger {
    /// Random probability (0.0 - 1.0)
    Random(f32),

    /// After N operations
    AfterOperations(u64),

    /// At specific time
    AtTime(SystemTime),

    /// During operation burst (operations per second)
    DuringBurst { threshold: u32, window: Duration },

    /// When storage is above threshold
    StorageThreshold(f32),

    /// On specific operation type
    OnOperation(String),
}

/// Error event for history tracking
#[derive(Debug, Clone)]
pub struct ErrorEvent {
    /// When the error occurred
    pub timestamp: SystemTime,

    /// Type of error
    pub error_type: super::SimulatedErrorType,

    /// Trigger that caused it
    pub trigger: ErrorTrigger,

    /// Operation that was being performed
    pub operation: String,

    /// Additional context
    pub context: String,
}

/// Hardware fault simulation
#[derive(Debug, Clone)]
pub struct HardwareFault {
    /// Fault type
    pub fault_type: HardwareFaultType,

    /// Severity level
    pub severity: FaultSeverity,

    /// Recovery time (if recoverable)
    pub recovery_time: Option<Duration>,

    /// Fault description
    pub description: String,
}

/// Types of hardware faults
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HardwareFaultType {
    /// Temperature too high
    Overheating,

    /// Power supply issues
    PowerFault,

    /// Memory corruption
    MemoryFault,

    /// Clock signal issues
    ClockFault,

    /// Secure element communication failure
    SecureElementFault,

    /// Random number generator failure
    RngFault,

    /// Cryptographic accelerator fault
    CryptoFault,
}

/// Fault severity levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum FaultSeverity {
    /// Warning level - operation can continue
    Warning = 1,

    /// Error level - operation fails but system stable
    Error = 2,

    /// Critical level - system may be compromised
    Critical = 3,

    /// Fatal level - immediate shutdown required
    Fatal = 4,
}

impl ErrorInjectionService {
    /// Create new error injection service
    pub fn new(max_history: usize) -> Self {
        Self {
            scenarios: Arc::new(Mutex::new(Vec::new())),
            error_history: Arc::new(Mutex::new(VecDeque::new())),
            max_history,
        }
    }

    /// Add error scenario
    pub fn add_scenario(&self, scenario: ErrorScenario) {
        let mut scenarios = self.scenarios.lock().unwrap();
        scenarios.push(scenario);
    }

    /// Check if any error should be triggered
    pub fn check_error_trigger(&self, operation: &str, context: &str) -> Option<VendorError> {
        let mut scenarios = self.scenarios.lock().unwrap();

        for scenario in scenarios.iter_mut() {
            if !scenario.enabled {
                continue;
            }

            if let Some(max) = scenario.max_occurrences {
                if scenario.current_count >= max {
                    continue;
                }
            }

            let should_trigger = match &scenario.trigger {
                ErrorTrigger::Random(probability) => rand::random::<f32>() < *probability,
                ErrorTrigger::OnOperation(op) => operation == op,
                // TODO: Implement other trigger types
                _ => false,
            };

            if should_trigger {
                scenario.current_count += 1;

                let error_event = ErrorEvent {
                    timestamp: SystemTime::now(),
                    error_type: scenario.error_type,
                    trigger: scenario.trigger.clone(),
                    operation: operation.to_string(),
                    context: context.to_string(),
                };

                self.record_error(error_event);
                return Some(self.convert_to_vendor_error(scenario.error_type));
            }
        }

        None
    }

    /// Record error in history
    fn record_error(&self, event: ErrorEvent) {
        let mut history = self.error_history.lock().unwrap();

        if history.len() >= self.max_history {
            history.pop_front();
        }

        history.push_back(event);
    }

    /// Convert simulated error to vendor error
    fn convert_to_vendor_error(&self, error_type: super::SimulatedErrorType) -> VendorError {
        use super::SimulatedErrorType::*;

        match error_type {
            HardwareFailure => {
                VendorError::HardwareError("Simulated hardware communication failure".to_string())
            }
            PermissionDenied => {
                VendorError::PermissionDenied("Simulated insufficient permissions".to_string())
            }
            ResourceExhausted => {
                VendorError::NotSupported("Simulated resource exhaustion".to_string())
            }
            AuthenticationFailed => {
                VendorError::AuthenticationFailed("Simulated authentication failure".to_string())
            }
            StorageCorruption => {
                VendorError::KeyCorrupted("Simulated storage corruption".to_string())
            }
            SecureElementError => {
                VendorError::HardwareError("Simulated secure element malfunction".to_string())
            }
            NetworkError => {
                VendorError::HardwareError("Simulated network connectivity issue".to_string())
            }
        }
    }

    /// Get error history
    pub fn get_error_history(&self) -> Vec<ErrorEvent> {
        let history = self.error_history.lock().unwrap();
        history.iter().cloned().collect()
    }

    /// Clear error history
    pub fn clear_history(&self) {
        let mut history = self.error_history.lock().unwrap();
        history.clear();
    }

    /// Reset all scenarios
    pub fn reset_scenarios(&self) {
        let mut scenarios = self.scenarios.lock().unwrap();
        for scenario in scenarios.iter_mut() {
            scenario.current_count = 0;
        }
    }

    /// Get error statistics
    pub fn get_statistics(&self) -> ErrorStatistics {
        let history = self.error_history.lock().unwrap();
        let scenarios = self.scenarios.lock().unwrap();

        let total_errors = history.len();
        let mut error_by_type = std::collections::HashMap::new();

        for event in history.iter() {
            *error_by_type.entry(event.error_type).or_insert(0) += 1;
        }

        ErrorStatistics {
            total_errors: total_errors as u64,
            errors_by_type: error_by_type,
            active_scenarios: scenarios.iter().filter(|s| s.enabled).count() as u32,
            total_scenarios: scenarios.len() as u32,
        }
    }
}

/// Error injection statistics
#[derive(Debug, Clone)]
pub struct ErrorStatistics {
    /// Total errors injected
    pub total_errors: u64,

    /// Errors by type
    pub errors_by_type: std::collections::HashMap<super::SimulatedErrorType, u32>,

    /// Number of active scenarios
    pub active_scenarios: u32,

    /// Total number of scenarios
    pub total_scenarios: u32,
}

impl ErrorScenario {
    /// Create a new random error scenario
    pub fn random(error_type: super::SimulatedErrorType, probability: f32) -> Self {
        Self {
            error_type,
            trigger: ErrorTrigger::Random(probability),
            max_occurrences: None,
            current_count: 0,
            enabled: true,
        }
    }

    /// Create scenario that triggers on specific operation
    pub fn on_operation(error_type: super::SimulatedErrorType, operation: &str) -> Self {
        Self {
            error_type,
            trigger: ErrorTrigger::OnOperation(operation.to_string()),
            max_occurrences: Some(1),
            current_count: 0,
            enabled: true,
        }
    }

    /// Create scenario that triggers after N operations
    pub fn after_operations(error_type: super::SimulatedErrorType, count: u64) -> Self {
        Self {
            error_type,
            trigger: ErrorTrigger::AfterOperations(count),
            max_occurrences: Some(1),
            current_count: 0,
            enabled: true,
        }
    }
}

impl HardwareFault {
    /// Create a critical hardware fault
    pub fn critical(fault_type: HardwareFaultType, description: String) -> Self {
        Self { fault_type, severity: FaultSeverity::Critical, recovery_time: None, description }
    }

    /// Create a recoverable hardware fault
    pub fn recoverable(
        fault_type: HardwareFaultType,
        description: String,
        recovery_time: Duration,
    ) -> Self {
        Self {
            fault_type,
            severity: FaultSeverity::Error,
            recovery_time: Some(recovery_time),
            description,
        }
    }

    /// Check if fault is recoverable
    pub fn is_recoverable(&self) -> bool {
        self.recovery_time.is_some() && self.severity < FaultSeverity::Critical
    }

    /// Get recovery time
    pub fn recovery_time(&self) -> Option<Duration> {
        self.recovery_time
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_injection_service() {
        let service = ErrorInjectionService::new(10);

        let scenario = ErrorScenario::random(
            super::super::SimulatedErrorType::HardwareFailure,
            1.0, // Always trigger
        );

        service.add_scenario(scenario);

        let error = service.check_error_trigger("test_operation", "test_context");
        assert!(error.is_some());

        let stats = service.get_statistics();
        assert_eq!(stats.total_errors, 1);
        assert_eq!(stats.active_scenarios, 1);
    }

    #[test]
    fn test_error_scenario_creation() {
        let scenario = ErrorScenario::on_operation(
            super::super::SimulatedErrorType::AuthenticationFailed,
            "sign",
        );

        assert!(scenario.enabled);
        assert_eq!(scenario.max_occurrences, Some(1));
        assert_eq!(scenario.current_count, 0);
    }

    #[test]
    fn test_hardware_fault() {
        let fault = HardwareFault::critical(
            HardwareFaultType::Overheating,
            "Temperature exceeded safe limits".to_string(),
        );

        assert!(!fault.is_recoverable());
        assert_eq!(fault.severity, FaultSeverity::Critical);
    }
}
