//! Example Android integration for Samsung Knox TEE
//!
//! This example demonstrates how to integrate the Samsung Knox TEE
//! implementation in an Android application.

#[cfg(target_os = "android")]
use crypto_tee_vendor::{
    samsung::{get_samsung_tee, KnoxParams},
    traits::VendorTEE,
    types::*,
    VendorError, VendorResult,
};

#[cfg(target_os = "android")]
use jni::{
    objects::{JClass, JObject},
    sys::{jint, JNI_VERSION_1_6},
    JNIEnv, JavaVM,
};

/// JNI OnLoad - called when the library is loaded by the JVM
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn JNI_OnLoad(vm: *mut JavaVM, _: *mut std::ffi::c_void) -> jint {
    // Initialize JNI for Knox
    unsafe {
        crypto_tee_vendor::samsung::jni_bridge::init_jni(vm);
    }

    JNI_VERSION_1_6
}

/// Initialize Knox TEE from Android
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_example_cryptotee_KnoxTEE_initialize(
    env: JNIEnv,
    _class: JClass,
    context: JObject,
) -> jint {
    match initialize_knox_internal(&env, context) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[cfg(target_os = "android")]
fn initialize_knox_internal(env: &JNIEnv, context: JObject) -> VendorResult<()> {
    // Get Knox TEE instance
    let knox_tee = get_samsung_tee()?;

    // Initialize JNI context
    let jni_context = crypto_tee_vendor::samsung::jni_bridge::KnoxJniContext::new(
        crypto_tee_vendor::samsung::jni_bridge::get_jni_context()
            .ok_or(VendorError::InitializationError("JNI not initialized".to_string()))?,
    );

    jni_context.initialize(env, context)?;

    Ok(())
}

/// Generate key using Knox
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_example_cryptotee_KnoxTEE_generateKey(
    _env: JNIEnv,
    _class: JClass,
    use_knox_vault: bool,
    require_auth: bool,
) -> jint {
    match generate_key_internal(use_knox_vault, require_auth) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

#[cfg(target_os = "android")]
async fn generate_key_internal(use_knox_vault: bool, require_auth: bool) -> VendorResult<()> {
    // Get Knox TEE instance
    let knox_tee = get_samsung_tee()?;

    // Set up key generation parameters
    let knox_params = KnoxParams {
        use_knox_vault,
        require_user_auth: require_auth,
        auth_validity_seconds: if require_auth { Some(300) } else { None }, // 5 minutes
        use_trustzone: true,
        enable_attestation: true,
        container_id: None,
    };

    let key_params = KeyGenParams {
        algorithm: Algorithm::EcdsaP256,
        hardware_backed: true,
        exportable: false,
        vendor_params: Some(VendorParams::Samsung(knox_params)),
    };

    // Generate key
    let key_handle = knox_tee.generate_key(&key_params).await?;

    println!("Generated key with ID: {}", key_handle.id);

    Ok(())
}

/// Sign data using Knox key
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "C" fn Java_com_example_cryptotee_KnoxTEE_signData(
    env: JNIEnv,
    _class: JClass,
    key_id: JObject, // String
    data: JObject,   // byte[]
) -> JObject {
    match sign_data_internal(&env, key_id, data) {
        Ok(signature) => {
            // Convert signature to Java byte array
            match env.byte_array_from_slice(&signature) {
                Ok(arr) => JObject::from(arr),
                Err(_) => JObject::null(),
            }
        }
        Err(_) => JObject::null(),
    }
}

#[cfg(target_os = "android")]
async fn sign_data_internal(
    env: &JNIEnv,
    key_id_obj: JObject,
    data_obj: JObject,
) -> VendorResult<Vec<u8>> {
    // Get Knox TEE instance
    let knox_tee = get_samsung_tee()?;

    // Convert Java string to Rust string
    let key_id_jstring = env.get_string(key_id_obj.into())?;
    let key_id = key_id_jstring.to_string_lossy().into_owned();

    // Convert Java byte array to Rust Vec<u8>
    let data = env.convert_byte_array(&jni::objects::JByteArray::from_raw(
        data_obj.into_inner() as jni::sys::jbyteArray,
    ))?;

    // Create key handle
    let key_handle = VendorKeyHandle {
        id: key_id,
        algorithm: Algorithm::EcdsaP256,
        vendor: "Samsung Knox".to_string(),
        hardware_backed: true,
        vendor_data: None,
    };

    // Sign data
    let signature = knox_tee.sign(&key_handle, &data).await?;

    Ok(signature.data)
}

/// Example usage in Android Activity
#[cfg(target_os = "android")]
const ANDROID_ACTIVITY_EXAMPLE: &str = r#"
// Example Android Activity code (Java/Kotlin)

class KnoxTEEActivity : AppCompatActivity() {
    companion object {
        init {
            System.loadLibrary("crypto_tee_vendor")
        }
        
        @JvmStatic
        external fun initialize(context: Context): Int
        
        @JvmStatic
        external fun generateKey(useKnoxVault: Boolean, requireAuth: Boolean): Int
        
        @JvmStatic
        external fun signData(keyId: String, data: ByteArray): ByteArray?
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Initialize Knox TEE
        val result = initialize(this)
        if (result == 0) {
            Log.d("KnoxTEE", "Knox TEE initialized successfully")
            
            // Generate a key using Knox Vault
            val keyGenResult = generateKey(
                useKnoxVault = true,
                requireAuth = true
            )
            
            if (keyGenResult == 0) {
                Log.d("KnoxTEE", "Key generated successfully")
                
                // Sign some data
                val dataToSign = "Hello Knox TEE".toByteArray()
                val signature = signData("knox_key_123", dataToSign)
                
                if (signature != null) {
                    Log.d("KnoxTEE", "Data signed successfully")
                }
            }
        }
    }
}
"#;

// For non-Android platforms, provide stub implementations
#[cfg(not(target_os = "android"))]
fn main() {
    println!("This example is only available on Android platforms");
    println!("To use Samsung Knox TEE:");
    println!("1. Build for Android target: cargo build --target aarch64-linux-android");
    println!("2. Include the native library in your Android app");
    println!("3. Load the library using System.loadLibrary()");
    println!("4. Call the JNI functions from your Android code");
}
