//! Biometric Authentication for Apple Devices
//!
//! This module provides Touch ID and Face ID authentication
//! for Secure Enclave key operations.

use crate::error::{VendorError, VendorResult};

// use security_framework::access_control::SecAccessControl; // Currently unused

/// Biometric authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BiometricType {
    /// Touch ID fingerprint authentication
    TouchID,

    /// Face ID facial recognition
    FaceID,

    /// Either Touch ID or Face ID (device dependent)
    Any,
}

/// Biometric authentication context
pub struct BiometricContext {
    context_type: BiometricType,
}

impl BiometricContext {
    /// Create new biometric context
    pub fn new(biometric_type: BiometricType) -> Self {
        Self { context_type: biometric_type }
    }

    /// Check if biometric authentication is available
    pub fn is_available(&self) -> VendorResult<bool> {
        #[cfg(target_os = "ios")]
        {
            self.check_ios_biometric_availability()
        }

        #[cfg(target_os = "macos")]
        {
            self.check_macos_biometric_availability()
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Ok(false)
        }
    }

    #[cfg(target_os = "ios")]
    fn check_ios_biometric_availability(&self) -> VendorResult<bool> {
        use objc::runtime::Object;
        use objc::{class, msg_send, sel, sel_impl};

        // SAFETY: This is safe because:
        // 1. LAContext is a standard LocalAuthentication framework class
        // 2. Null pointer checking is performed after allocation
        // 3. objc crate maintains Objective-C runtime safety
        unsafe {
            let la_context_class = class!(LAContext);
            let context: *mut Object = msg_send![la_context_class, new];

            if context.is_null() {
                return Ok(false);
            }

            let policy = match self.context_type {
                BiometricType::TouchID | BiometricType::FaceID | BiometricType::Any => {
                    2 // LAPolicyDeviceOwnerAuthenticationWithBiometrics
                }
            };

            let mut error: *mut Object = std::ptr::null_mut();
            let can_evaluate: bool = msg_send![
                context,
                canEvaluatePolicy:policy
                error:&mut error
            ];

            // Release context
            let _: () = msg_send![context, release];

            Ok(can_evaluate)
        }
    }

    #[cfg(target_os = "macos")]
    fn check_macos_biometric_availability(&self) -> VendorResult<bool> {
        match self.context_type {
            BiometricType::TouchID | BiometricType::Any => {
                // Check for Touch ID support on macOS
                use std::process::Command;

                let output = Command::new("system_profiler")
                    .arg("SPiBridgeDataType")
                    .output()
                    .map_err(|e| {
                        VendorError::InitializationError(format!("Failed to check Touch ID: {e}"))
                    })?;

                let has_touch_id = String::from_utf8_lossy(&output.stdout).contains("Touch ID");

                Ok(has_touch_id)
            }
            BiometricType::FaceID => {
                // Face ID is not available on macOS
                Ok(false)
            }
        }
    }

    /// Get biometric type available on device
    pub fn get_available_type() -> VendorResult<Option<BiometricType>> {
        #[cfg(target_os = "ios")]
        {
            use objc::runtime::Object;
            use objc::{class, msg_send, sel, sel_impl};

            unsafe {
                let la_context_class = class!(LAContext);
                let context: *mut Object = msg_send![la_context_class, new];

                if context.is_null() {
                    return Ok(None);
                }

                let biometry_type: i32 = msg_send![context, biometryType];

                // Release context
                let _: () = msg_send![context, release];

                match biometry_type {
                    0 => Ok(None),                         // LABiometryTypeNone
                    1 => Ok(Some(BiometricType::TouchID)), // LABiometryTypeTouchID
                    2 => Ok(Some(BiometricType::FaceID)),  // LABiometryTypeFaceID
                    _ => Ok(None),
                }
            }
        }

        #[cfg(target_os = "macos")]
        {
            // Check for Touch ID on macOS
            let touch_id_context = BiometricContext::new(BiometricType::TouchID);
            if touch_id_context.is_available()? {
                Ok(Some(BiometricType::TouchID))
            } else {
                Ok(None)
            }
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Ok(None)
        }
    }

    /// Evaluate biometric authentication policy
    #[cfg(target_os = "ios")]
    pub fn evaluate_policy(&self, reason: &str) -> VendorResult<bool> {
        use objc::block::ConcreteBlock;
        use objc::runtime::{Object, BOOL, NO};
        use objc::{class, msg_send, sel, sel_impl};
        use std::sync::mpsc;
        use std::sync::{Arc, Mutex};
        use std::time::Duration;

        unsafe {
            let la_context_class = class!(LAContext);
            let context: *mut Object = msg_send![la_context_class, new];

            if context.is_null() {
                return Err(VendorError::AuthenticationFailed(
                    "Failed to create LAContext".to_string(),
                ));
            }

            let policy = 2; // LAPolicyDeviceOwnerAuthenticationWithBiometrics

            let reason_cstring = std::ffi::CString::new(reason).unwrap();
            let reason_nsstring: *mut Object = msg_send![
                class!(NSString),
                stringWithUTF8String:reason_cstring.as_ptr()
            ];

            let (tx, rx) = mpsc::channel();
            let tx = Arc::new(Mutex::new(tx));

            // Create block for completion handler
            let tx_clone = tx.clone();
            let block = ConcreteBlock::new(move |success: BOOL, _error: *mut Object| {
                let _ = tx_clone.lock().unwrap().send(success != NO);
            });
            let block_ref: &ConcreteBlock<(BOOL, *mut Object), ()> = &block;

            let _: () = msg_send![
                context,
                evaluatePolicy:policy
                localizedReason:reason_nsstring
                reply:block_ref
            ];

            // Wait for authentication result (with timeout)
            match rx.recv_timeout(Duration::from_secs(60)) {
                Ok(success) => {
                    let _: () = msg_send![context, release];
                    Ok(success)
                }
                Err(_) => {
                    let _: () = msg_send![context, release];
                    Err(VendorError::AuthenticationFailed(
                        "Biometric authentication timed out".to_string(),
                    ))
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    pub fn evaluate_policy(&self, _reason: &str) -> VendorResult<bool> {
        // On macOS, biometric authentication is handled through
        // the keychain access control when the key is used
        Ok(true)
    }
}

/// Biometric enrollment status
#[derive(Debug, Clone)]
pub struct BiometricEnrollment {
    /// Whether biometric authentication is enrolled
    pub is_enrolled: bool,

    /// Type of biometric enrolled
    pub biometric_type: Option<BiometricType>,

    /// Number of enrolled fingerprints (Touch ID only)
    pub enrolled_count: Option<u32>,
}

impl BiometricEnrollment {
    /// Check biometric enrollment status
    pub fn check_enrollment() -> VendorResult<Self> {
        #[cfg(target_os = "ios")]
        {
            use objc::runtime::Object;
            use objc::{class, msg_send, sel, sel_impl};

            unsafe {
                let la_context_class = class!(LAContext);
                let context: *mut Object = msg_send![la_context_class, new];

                if context.is_null() {
                    return Ok(Self {
                        is_enrolled: false,
                        biometric_type: None,
                        enrolled_count: None,
                    });
                }

                let policy = 2; // LAPolicyDeviceOwnerAuthenticationWithBiometrics
                let mut error: *mut Object = std::ptr::null_mut();

                let can_evaluate: bool = msg_send![
                    context,
                    canEvaluatePolicy:policy
                    error:&mut error
                ];

                let biometry_type: i32 = msg_send![context, biometryType];

                let _: () = msg_send![context, release];

                let biometric_type = match biometry_type {
                    1 => Some(BiometricType::TouchID),
                    2 => Some(BiometricType::FaceID),
                    _ => None,
                };

                Ok(Self {
                    is_enrolled: can_evaluate && error.is_null(),
                    biometric_type,
                    enrolled_count: None, // iOS doesn't expose enrolled count
                })
            }
        }

        #[cfg(target_os = "macos")]
        {
            let available_type = BiometricContext::get_available_type()?;

            Ok(Self {
                is_enrolled: available_type.is_some(),
                biometric_type: available_type,
                enrolled_count: None,
            })
        }

        #[cfg(not(any(target_os = "ios", target_os = "macos")))]
        {
            Ok(Self { is_enrolled: false, biometric_type: None, enrolled_count: None })
        }
    }
}
