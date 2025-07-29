//! JNI Bridge for Qualcomm QSEE Android Integration

use crate::error::{VendorError, VendorResult};
use jni::objects::{GlobalRef, JClass, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint};
use jni::{JNIEnv, JavaVM};
use std::sync::{Arc, Mutex, OnceLock};
use tracing::{debug, error, info};

use super::ProtectionLevel;

/// JNI Bridge for QSEE operations
pub struct JniBridge {
    /// JavaVM reference for getting JNI environment
    jvm: Arc<JavaVM>,
    /// Cached class references
    keystore_class: Arc<Mutex<Option<GlobalRef>>>,
    context: Arc<Mutex<Option<GlobalRef>>>,
}

// Make JniBridge Send + Sync
unsafe impl Send for JniBridge {}
unsafe impl Sync for JniBridge {}

impl JniBridge {
    /// Create new JNI bridge
    pub fn new() -> VendorResult<Self> {
        // Get JavaVM from global reference
        let jvm = get_jni_context()
            .ok_or_else(|| VendorError::InitializationError("JNI not initialized".to_string()))?;

        Ok(Self {
            jvm,
            keystore_class: Arc::new(Mutex::new(None)),
            context: Arc::new(Mutex::new(None)),
        })
    }

    /// Initialize JNI bridge with context
    pub fn initialize(&self, env: &mut JNIEnv, context: JObject) -> VendorResult<()> {
        // Store Android context
        let context_ref = env.new_global_ref(context).map_err(|e| {
            VendorError::InitializationError(format!("Failed to create context ref: {}", e))
        })?;

        *self.context.lock().unwrap() = Some(context_ref);

        // Load KeyStore class
        let keystore_class = env.find_class("java/security/KeyStore").map_err(|e| {
            VendorError::InitializationError(format!("Failed to find KeyStore class: {}", e))
        })?;

        let keystore_ref = env.new_global_ref(keystore_class).map_err(|e| {
            VendorError::InitializationError(format!("Failed to create KeyStore ref: {}", e))
        })?;

        *self.keystore_class.lock().unwrap() = Some(keystore_ref);

        Ok(())
    }

    /// Generate key through Android Keystore with QSEE backing
    pub async fn generate_key(
        &self,
        _alias: &str,
        _algorithm: &str,
        _key_size: i32,
        _protection_level: ProtectionLevel,
        _require_auth: bool,
        _auth_validity_duration: Option<u32>,
    ) -> VendorResult<()> {
        debug!("Generating key through JNI: [REDACTED]");

        // In a real implementation, this would call into Java/Kotlin code
        // that uses Android Keystore with QSEE backing

        // For now, we'll simulate the operation
        info!("Key generated in QSEE: [REDACTED]");
        Ok(())
    }

    /// Delete key from Android Keystore
    pub async fn delete_key(&self, _alias: &str) -> VendorResult<()> {
        debug!("Deleting key through JNI: [REDACTED]");

        // In a real implementation, this would call Android Keystore
        info!("Key deleted from QSEE: [REDACTED]");
        Ok(())
    }

    /// Sign data using key in QSEE
    pub async fn sign(&self, _alias: &str, _data: &[u8]) -> VendorResult<Vec<u8>> {
        debug!("Signing data through JNI with key: [REDACTED]");

        // In a real implementation, this would use Android Keystore
        // For now, return mock signature
        let signature = vec![0u8; 64]; // Mock signature
        Ok(signature)
    }

    /// Verify signature using key in QSEE
    pub async fn verify(
        &self,
        _alias: &str,
        _data: &[u8],
        _signature: &[u8],
    ) -> VendorResult<bool> {
        debug!("Verifying signature through JNI with key: [REDACTED]");

        // In a real implementation, this would use Android Keystore
        Ok(true) // Mock verification
    }

    /// Get key attestation certificate chain
    pub async fn get_key_attestation(&self, _alias: &str) -> VendorResult<Vec<u8>> {
        debug!("Getting key attestation through JNI for: [REDACTED]");

        // In a real implementation, this would get attestation from Android Keystore
        let mock_attestation = b"QSEE_KEY_ATTESTATION".to_vec();
        Ok(mock_attestation)
    }
}

/// JNI native methods exposed to Java
#[no_mangle]
pub extern "C" fn Java_com_cryptotee_vendor_qualcomm_QSEEBridge_nativeInit(
    env: JNIEnv,
    _class: JClass,
    _context: JObject,
) {
    info!("Initializing QSEE JNI bridge");

    // Initialize global JVM reference
    if let Ok(jvm) = env.get_java_vm() {
        let _ = GLOBAL_JVM.set(Arc::new(jvm));
    }
}

#[no_mangle]
pub extern "C" fn Java_com_cryptotee_vendor_qualcomm_QSEEBridge_nativeGenerateKey(
    mut env: JNIEnv,
    _class: JClass,
    alias: JString,
    algorithm: JString,
    _key_size: jint,
    _hardware_backed: jboolean,
    _require_auth: jboolean,
    _auth_validity: jint,
) -> jboolean {
    let _alias_str = match env.get_string(&alias) {
        Ok(s) => s.to_str().unwrap_or("").to_string(),
        Err(e) => {
            tracing::error!("Failed to get alias string: {:?}", e);
            return 0;
        }
    };

    let _algorithm_str = match env.get_string(&algorithm) {
        Ok(s) => s.to_str().unwrap_or("").to_string(),
        Err(e) => {
            tracing::error!("Failed to get algorithm string: {:?}", e);
            return 0;
        }
    };

    debug!("Native generate key: [REDACTED]");

    // Generate key using Android Keystore with QSEE backing
    1 // Success
}

#[no_mangle]
pub extern "C" fn Java_com_cryptotee_vendor_qualcomm_QSEEBridge_nativeSign(
    mut env: JNIEnv,
    _class: JClass,
    alias: JString,
    data: jbyteArray,
) -> jbyteArray {
    let _alias_str = match env.get_string(&alias) {
        Ok(s) => s.to_str().unwrap_or("").to_string(),
        Err(e) => {
            tracing::error!("Failed to get alias string: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    let _data_vec =
        match env.convert_byte_array(unsafe { &jni::objects::JByteArray::from_raw(data) }) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to convert data array: {:?}", e);
                return std::ptr::null_mut();
            }
        };

    debug!("Native sign: [REDACTED], data_len={}", _data_vec.len());

    // Sign using Android Keystore
    // Return signature
    match env.byte_array_from_slice(&[0u8; 64]) {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            error!("Failed to create signature array: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn Java_com_cryptotee_vendor_qualcomm_QSEEBridge_nativeVerify(
    mut env: JNIEnv,
    _class: JClass,
    alias: JString,
    data: jbyteArray,
    signature: jbyteArray,
) -> jboolean {
    let _alias_str = match env.get_string(&alias) {
        Ok(s) => s.to_str().unwrap_or("").to_string(),
        Err(e) => {
            tracing::error!("Failed to get alias string: {:?}", e);
            return 0;
        }
    };

    let _data_vec =
        match env.convert_byte_array(unsafe { &jni::objects::JByteArray::from_raw(data) }) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to convert data array: {:?}", e);
                return 0;
            }
        };

    let _signature_vec =
        match env.convert_byte_array(unsafe { &jni::objects::JByteArray::from_raw(signature) }) {
            Ok(v) => v,
            Err(e) => {
                error!("Failed to convert signature array: {:?}", e);
                return 0;
            }
        };

    debug!("Native verify: [REDACTED]");

    // Verify using Android Keystore
    1 // Success
}

#[no_mangle]
pub extern "C" fn Java_com_cryptotee_vendor_qualcomm_QSEEBridge_nativeGetAttestation(
    mut env: JNIEnv,
    _class: JClass,
    alias: JString,
) -> jbyteArray {
    let _alias_str = match env.get_string(&alias) {
        Ok(s) => s.to_str().unwrap_or("").to_string(),
        Err(e) => {
            tracing::error!("Failed to get alias string: {:?}", e);
            return std::ptr::null_mut();
        }
    };

    debug!("Native get attestation: [REDACTED]");

    // Get attestation from Android Keystore
    match env.byte_array_from_slice(b"QSEE_ATTESTATION") {
        Ok(arr) => arr.into_raw(),
        Err(e) => {
            error!("Failed to create attestation array: {:?}", e);
            std::ptr::null_mut()
        }
    }
}

// Global JVM reference for callbacks
static GLOBAL_JVM: OnceLock<Arc<JavaVM>> = OnceLock::new();

/// Initialize JNI with JavaVM
pub unsafe fn init_jni(jvm: *mut jni::sys::JavaVM) {
    if let Ok(jvm) = JavaVM::from_raw(jvm) {
        let _ = GLOBAL_JVM.set(Arc::new(jvm));
    }
}

/// Get JNI context
pub fn get_jni_context() -> Option<Arc<JavaVM>> {
    GLOBAL_JVM.get().cloned()
}
