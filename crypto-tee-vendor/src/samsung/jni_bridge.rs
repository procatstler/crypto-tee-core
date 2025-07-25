//! JNI Bridge for Samsung Knox SDK
//!
//! This module provides the JNI interface to communicate with Samsung Knox SDK
//! Java APIs from Rust code.

use crate::error::{VendorError, VendorResult};
use jni::{
    objects::{GlobalRef, JObject, JValue},
    sys::{jbyteArray, jobject},
    JNIEnv, JavaVM,
};
use std::sync::{Arc, Mutex, OnceLock};
use subtle::ConstantTimeEq;

/// JNI context for Knox operations
pub struct KnoxJniContext {
    pub jvm: Arc<JavaVM>,
    knox_crypto_class: Arc<Mutex<Option<GlobalRef>>>,
    context: Arc<Mutex<Option<GlobalRef>>>,
}

// Make KnoxJniContext Send + Sync
unsafe impl Send for KnoxJniContext {}
unsafe impl Sync for KnoxJniContext {}

impl KnoxJniContext {
    /// Perform constant-time comparison for verification results
    fn constant_time_verify_result(result: bool) -> bool {
        let result_byte = if result { 1u8 } else { 0u8 };
        let expected_byte = 1u8;
        result_byte.ct_eq(&expected_byte).into()
    }

    /// Create new JNI context
    pub fn new(jvm: Arc<JavaVM>) -> Self {
        Self {
            jvm,
            knox_crypto_class: Arc::new(Mutex::new(None)),
            context: Arc::new(Mutex::new(None)),
        }
    }

    /// Initialize Knox SDK classes
    pub fn initialize(&self, env: &mut JNIEnv, context: JObject) -> VendorResult<()> {
        // Load Knox SDK classes
        let knox_crypto_class =
            env.find_class("com/samsung/android/knox/keystore/KnoxKeyGenParameterSpec").map_err(
                |e| VendorError::InitializationError(format!("Failed to find Knox class: {}", e)),
            )?;

        // Store references
        let knox_crypto_class = env.new_global_ref(knox_crypto_class).map_err(|e| {
            VendorError::InitializationError(format!("Failed to create global ref: {}", e))
        })?;

        let context = env.new_global_ref(context).map_err(|e| {
            VendorError::InitializationError(format!("Failed to create context ref: {}", e))
        })?;

        *self.knox_crypto_class.lock().unwrap() = Some(knox_crypto_class);
        *self.context.lock().unwrap() = Some(context);

        Ok(())
    }

    /// Check if Knox is available
    pub fn is_knox_available(&self, env: &mut JNIEnv) -> VendorResult<bool> {
        let knox_version_class = env
            .find_class("com/samsung/android/knox/EnterpriseDeviceManager")
            .map_err(|_| VendorError::NotAvailable)?;

        let version_method = env
            .get_static_method_id(knox_version_class, "getAPILevel", "()I")
            .map_err(|_| VendorError::NotAvailable)?;

        let api_level = unsafe {
            env.call_static_method_unchecked(
                knox_version_class,
                version_method,
                jni::signature::ReturnType::Primitive(jni::signature::Primitive::Int),
                &[],
            )
        }
        .map_err(|_| VendorError::NotAvailable)?;

        match api_level {
            JValue::Int(level) => Ok(level >= 30), // Knox 3.0 or higher
            _ => Ok(false),
        }
    }

    /// Generate key using Knox
    pub fn generate_key(
        &self,
        env: &mut JNIEnv,
        alias: &str,
        algorithm: &str,
        key_size: i32,
        use_knox_vault: bool,
    ) -> VendorResult<()> {
        let alias_jstring = env
            .new_string(alias)
            .map_err(|e| VendorError::KeyGeneration(format!("Failed to create string: {}", e)))?;

        // Create KnoxKeyGenParameterSpec.Builder
        let builder_class = env
            .find_class("com/samsung/android/knox/keystore/KnoxKeyGenParameterSpec$Builder")
            .map_err(|e| {
                VendorError::KeyGeneration(format!("Failed to find Builder class: {}", e))
            })?;

        let builder_constructor =
            env.get_method_id(builder_class, "<init>", "(Ljava/lang/String;I)V").map_err(|e| {
                VendorError::KeyGeneration(format!("Failed to find constructor: {}", e))
            })?;

        let purposes = 12; // Sign | Verify
        let builder = unsafe {
            env.new_object_unchecked(
                builder_class,
                builder_constructor,
                &[JValue::Object(&alias_jstring), JValue::Int(purposes)],
            )
        }
        .map_err(|e| VendorError::KeyGeneration(format!("Failed to create builder: {}", e)))?;

        // Set key algorithm
        let set_algorithm_method = env.get_method_id(
            builder_class,
            "setKeyAlgorithm",
            "(Ljava/lang/String;)Lcom/samsung/android/knox/keystore/KnoxKeyGenParameterSpec$Builder;"
        ).map_err(|e| VendorError::KeyGeneration(format!("Failed to find setKeyAlgorithm: {}", e)))?;

        let algorithm_jstring = env.new_string(algorithm).map_err(|e| {
            VendorError::KeyGeneration(format!("Failed to create algorithm string: {}", e))
        })?;

        unsafe {
            env.call_method_unchecked(
                &builder,
                set_algorithm_method,
                jni::signature::ReturnType::Object,
                &[JValue::Object(&algorithm_jstring)],
            )
        }
        .map_err(|e| VendorError::KeyGeneration(format!("Failed to set algorithm: {}", e)))?;

        // Set key size
        let set_key_size_method = env
            .get_method_id(
                builder_class,
                "setKeySize",
                "(I)Lcom/samsung/android/knox/keystore/KnoxKeyGenParameterSpec$Builder;",
            )
            .map_err(|e| VendorError::KeyGeneration(format!("Failed to find setKeySize: {}", e)))?;

        unsafe {
            env.call_method_unchecked(
                &builder,
                set_key_size_method,
                jni::signature::ReturnType::Object,
                &[JValue::Int(key_size)],
            )
        }
        .map_err(|e| VendorError::KeyGeneration(format!("Failed to set key size: {}", e)))?;

        // Set Knox Vault if requested
        if use_knox_vault {
            let set_knox_vault_method = env
                .get_method_id(
                    builder_class,
                    "setUseKnoxVault",
                    "(Z)Lcom/samsung/android/knox/keystore/KnoxKeyGenParameterSpec$Builder;",
                )
                .map_err(|e| {
                    VendorError::KeyGeneration(format!("Failed to find setUseKnoxVault: {}", e))
                })?;

            unsafe {
                env.call_method_unchecked(
                    &builder,
                    set_knox_vault_method,
                    jni::signature::ReturnType::Object,
                    &[JValue::Bool(1)],
                )
            }
            .map_err(|e| VendorError::KeyGeneration(format!("Failed to set Knox Vault: {}", e)))?;
        }

        // Build spec
        let build_method = env
            .get_method_id(
                builder_class,
                "build",
                "()Lcom/samsung/android/knox/keystore/KnoxKeyGenParameterSpec;",
            )
            .map_err(|e| {
                VendorError::KeyGeneration(format!("Failed to find build method: {}", e))
            })?;

        let spec = unsafe {
            env.call_method_unchecked(
                &builder,
                build_method,
                jni::signature::ReturnType::Object,
                &[],
            )
        }
        .map_err(|e| VendorError::KeyGeneration(format!("Failed to build spec: {}", e)))?;

        // Generate key using KeyGenerator
        let key_generator_class = env.find_class("javax/crypto/KeyGenerator").map_err(|e| {
            VendorError::KeyGeneration(format!("Failed to find KeyGenerator: {}", e))
        })?;

        let get_instance_method = env
            .get_static_method_id(
                key_generator_class,
                "getInstance",
                "(Ljava/lang/String;Ljava/lang/String;)Ljavax/crypto/KeyGenerator;",
            )
            .map_err(|e| {
                VendorError::KeyGeneration(format!("Failed to find getInstance: {}", e))
            })?;

        let provider_jstring = env.new_string("AndroidKeyStore").map_err(|e| {
            VendorError::KeyGeneration(format!("Failed to create provider string: {}", e))
        })?;

        let key_generator = unsafe {
            env.call_static_method_unchecked(
                key_generator_class,
                get_instance_method,
                jni::signature::ReturnType::Object,
                &[JValue::Object(&algorithm_jstring), JValue::Object(&provider_jstring)],
            )
        }
        .map_err(|e| {
            VendorError::KeyGeneration(format!("Failed to get KeyGenerator instance: {}", e))
        })?;

        // Initialize and generate key
        let init_method = env
            .get_method_id(
                key_generator_class,
                "init",
                "(Ljava/security/spec/AlgorithmParameterSpec;)V",
            )
            .map_err(|e| {
                VendorError::KeyGeneration(format!("Failed to find init method: {}", e))
            })?;

        if let JValue::Object(spec_obj) = spec {
            let key_gen_obj = key_generator.l().unwrap();
            unsafe {
                env.call_method_unchecked(
                    &key_gen_obj,
                    init_method,
                    jni::signature::ReturnType::Primitive(jni::signature::Primitive::Void),
                    &[JValue::Object(&spec_obj)],
                )
            }
            .map_err(|e| {
                VendorError::KeyGeneration(format!("Failed to init key generator: {}", e))
            })?;

            let generate_key_method = env
                .get_method_id(key_generator_class, "generateKey", "()Ljavax/crypto/SecretKey;")
                .map_err(|e| {
                    VendorError::KeyGeneration(format!("Failed to find generateKey: {}", e))
                })?;

            unsafe {
                env.call_method_unchecked(
                    &key_gen_obj,
                    generate_key_method,
                    jni::signature::ReturnType::Object,
                    &[],
                )
            }
            .map_err(|e| VendorError::KeyGeneration(format!("Failed to generate key: {}", e)))?;
        }

        Ok(())
    }

    /// Sign data using Knox key
    pub fn sign_data(&self, env: &mut JNIEnv, alias: &str, data: &[u8]) -> VendorResult<Vec<u8>> {
        // Load key from Android KeyStore
        let keystore_class = env
            .find_class("java/security/KeyStore")
            .map_err(|e| VendorError::SigningError(format!("Failed to find KeyStore: {}", e)))?;

        let get_instance_method = env
            .get_static_method_id(
                keystore_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
            )
            .map_err(|e| VendorError::SigningError(format!("Failed to find getInstance: {}", e)))?;

        let provider_jstring = env.new_string("AndroidKeyStore").map_err(|e| {
            VendorError::SigningError(format!("Failed to create provider string: {}", e))
        })?;

        let keystore = unsafe {
            env.call_static_method_unchecked(
                keystore_class,
                get_instance_method,
                jni::signature::ReturnType::Object,
                &[JValue::Object(&provider_jstring)],
            )
        }
        .map_err(|e| {
            VendorError::SigningError(format!("Failed to get KeyStore instance: {}", e))
        })?;

        // Load keystore
        let load_method = env
            .get_method_id(keystore_class, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V")
            .map_err(|e| VendorError::SigningError(format!("Failed to find load method: {}", e)))?;

        let keystore_obj = keystore.l().unwrap();
        unsafe {
            env.call_method_unchecked(
                &keystore_obj,
                load_method,
                jni::signature::ReturnType::Primitive(jni::signature::Primitive::Void),
                &[JValue::Object(JObject::null())],
            )
        }
        .map_err(|e| VendorError::SigningError(format!("Failed to load keystore: {}", e)))?;

        // Get key
        let get_key_method = env
            .get_method_id(keystore_class, "getKey", "(Ljava/lang/String;[C)Ljava/security/Key;")
            .map_err(|e| VendorError::SigningError(format!("Failed to find getKey: {}", e)))?;

        let alias_jstring = env.new_string(alias).map_err(|e| {
            VendorError::SigningError(format!("Failed to create alias string: {}", e))
        })?;

        let key = unsafe {
            env.call_method_unchecked(
                &keystore_obj,
                get_key_method,
                jni::signature::ReturnType::Object,
                &[JValue::Object(&alias_jstring), JValue::Object(JObject::null())],
            )
        }
        .map_err(|e| VendorError::SigningError(format!("Failed to get key: {}", e)))?;

        // Create signature object
        let signature_class = env.find_class("java/security/Signature").map_err(|e| {
            VendorError::SigningError(format!("Failed to find Signature class: {}", e))
        })?;

        let get_signature_method = env
            .get_static_method_id(
                signature_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/Signature;",
            )
            .map_err(|e| VendorError::SigningError(format!("Failed to find getInstance: {}", e)))?;

        let algorithm_jstring = env.new_string("SHA256withECDSA").map_err(|e| {
            VendorError::SigningError(format!("Failed to create algorithm string: {}", e))
        })?;

        let signature = unsafe {
            env.call_static_method_unchecked(
                signature_class,
                get_signature_method,
                jni::signature::ReturnType::Object,
                &[JValue::Object(&algorithm_jstring)],
            )
        }
        .map_err(|e| {
            VendorError::SigningError(format!("Failed to get Signature instance: {}", e))
        })?;

        // Initialize for signing
        let init_sign_method = env
            .get_method_id(signature_class, "initSign", "(Ljava/security/PrivateKey;)V")
            .map_err(|e| VendorError::SigningError(format!("Failed to find initSign: {}", e)))?;

        if let JValue::Object(key_obj) = key {
            let sig_obj = signature.l().unwrap();
            unsafe {
                env.call_method_unchecked(
                    &sig_obj,
                    init_sign_method,
                    jni::signature::ReturnType::Primitive(jni::signature::Primitive::Void),
                    &[JValue::Object(&key_obj)],
                )
            }
            .map_err(|e| VendorError::SigningError(format!("Failed to init signing: {}", e)))?;

            // Update with data
            let update_method = env
                .get_method_id(signature_class, "update", "([B)V")
                .map_err(|e| VendorError::SigningError(format!("Failed to find update: {}", e)))?;

            let data_array = env.byte_array_from_slice(data).map_err(|e| {
                VendorError::SigningError(format!("Failed to create byte array: {}", e))
            })?;

            unsafe {
                env.call_method_unchecked(
                    &sig_obj,
                    update_method,
                    jni::signature::ReturnType::Primitive(jni::signature::Primitive::Void),
                    &[JValue::Object(&data_array)],
                )
            }
            .map_err(|e| VendorError::SigningError(format!("Failed to update signature: {}", e)))?;

            // Sign
            let sign_method = env.get_method_id(signature_class, "sign", "()[B").map_err(|e| {
                VendorError::SigningError(format!("Failed to find sign method: {}", e))
            })?;

            let signature_result = unsafe {
                env.call_method_unchecked(
                    &sig_obj,
                    sign_method,
                    jni::signature::ReturnType::Array,
                    &[],
                )
            }
            .map_err(|e| VendorError::SigningError(format!("Failed to sign: {}", e)))?;

            // Convert result to Vec<u8>
            if let JValue::Object(sig_array) = signature_result {
                let sig_vec = env.convert_byte_array(sig_array.cast()).map_err(|e| {
                    VendorError::SigningError(format!("Failed to convert signature: {}", e))
                })?;
                Ok(sig_vec)
            } else {
                Err(VendorError::SigningError("Invalid signature result".to_string()))
            }
        } else {
            Err(VendorError::SigningError("Failed to get key object".to_string()))
        }
    }

    /// Get Knox attestation
    pub fn get_attestation(&self, env: &mut JNIEnv, alias: &str) -> VendorResult<Vec<Vec<u8>>> {
        // Load key certificate chain
        let keystore_class = env.find_class("java/security/KeyStore").map_err(|e| {
            VendorError::AttestationFailed(format!("Failed to find KeyStore: {}", e))
        })?;

        let get_instance_method = env
            .get_static_method_id(
                keystore_class,
                "getInstance",
                "(Ljava/lang/String;)Ljava/security/KeyStore;",
            )
            .map_err(|e| {
                VendorError::AttestationFailed(format!("Failed to find getInstance: {}", e))
            })?;

        let provider_jstring = env.new_string("AndroidKeyStore").map_err(|e| {
            VendorError::AttestationFailed(format!("Failed to create provider string: {}", e))
        })?;

        let keystore = unsafe {
            env.call_static_method_unchecked(
                keystore_class,
                get_instance_method,
                jni::signature::ReturnType::Object,
                &[JValue::Object(&provider_jstring)],
            )
        }
        .map_err(|e| {
            VendorError::AttestationFailed(format!("Failed to get KeyStore instance: {}", e))
        })?;

        // Load keystore
        let load_method = env
            .get_method_id(keystore_class, "load", "(Ljava/security/KeyStore$LoadStoreParameter;)V")
            .map_err(|e| {
                VendorError::AttestationFailed(format!("Failed to find load method: {}", e))
            })?;

        let keystore_obj = keystore.l().unwrap();
        unsafe {
            env.call_method_unchecked(
                &keystore_obj,
                load_method,
                jni::signature::ReturnType::Primitive(jni::signature::Primitive::Void),
                &[JValue::Object(JObject::null())],
            )
        }
        .map_err(|e| VendorError::AttestationFailed(format!("Failed to load keystore: {}", e)))?;

        // Get certificate chain
        let get_certificate_chain_method = env
            .get_method_id(
                keystore_class,
                "getCertificateChain",
                "(Ljava/lang/String;)[Ljava/security/cert/Certificate;",
            )
            .map_err(|e| {
                VendorError::AttestationFailed(format!("Failed to find getCertificateChain: {}", e))
            })?;

        let alias_jstring = env.new_string(alias).map_err(|e| {
            VendorError::AttestationFailed(format!("Failed to create alias string: {}", e))
        })?;

        let cert_chain = unsafe {
            env.call_method_unchecked(
                &keystore_obj,
                get_certificate_chain_method,
                jni::signature::ReturnType::Array,
                &[JValue::Object(&alias_jstring)],
            )
        }
        .map_err(|e| {
            VendorError::AttestationFailed(format!("Failed to get certificate chain: {}", e))
        })?;

        // Convert certificate chain to bytes
        let mut cert_bytes = Vec::new();

        if let JValue::Object(chain_obj) = cert_chain {
            let chain_array = chain_obj.cast::<jobject>();
            let chain_len = env.get_array_length(chain_array.into()).map_err(|e| {
                VendorError::AttestationFailed(format!("Failed to get array length: {}", e))
            })?;

            for i in 0..chain_len {
                let cert = env.get_object_array_element(chain_array.into(), i).map_err(|e| {
                    VendorError::AttestationFailed(format!("Failed to get certificate: {}", e))
                })?;

                // Get encoded certificate
                let cert_class = env.find_class("java/security/cert/Certificate").map_err(|e| {
                    VendorError::AttestationFailed(format!(
                        "Failed to find Certificate class: {}",
                        e
                    ))
                })?;

                let get_encoded_method =
                    env.get_method_id(cert_class, "getEncoded", "()[B").map_err(|e| {
                        VendorError::AttestationFailed(format!("Failed to find getEncoded: {}", e))
                    })?;

                let encoded_cert = unsafe {
                    env.call_method_unchecked(
                        &cert,
                        get_encoded_method,
                        jni::signature::ReturnType::Array,
                        &[],
                    )
                }
                .map_err(|e| {
                    VendorError::AttestationFailed(format!(
                        "Failed to get encoded certificate: {}",
                        e
                    ))
                })?;

                if let JValue::Object(cert_bytes_obj) = encoded_cert {
                    let cert_vec = env.convert_byte_array(cert_bytes_obj.cast()).map_err(|e| {
                        VendorError::AttestationFailed(format!(
                            "Failed to convert certificate bytes: {}",
                            e
                        ))
                    })?;
                    cert_bytes.push(cert_vec);
                }
            }
        }

        Ok(cert_bytes)
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
