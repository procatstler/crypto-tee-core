// Example Android integration for Qualcomm QSEE
//
// This example demonstrates how to integrate the Qualcomm QSEE
// implementation in an Android application.

package com.cryptotee.vendor.qualcomm.example

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.KeyStore
import java.util.concurrent.Executor

// JNI Bridge to Rust library
class QSEEBridge {
    companion object {
        init {
            System.loadLibrary("crypto_tee_vendor")
        }
        
        private const val TAG = "QSEEBridge"
    }
    
    // Native method declarations
    external fun nativeInit()
    external fun nativeGenerateKey(
        alias: String,
        algorithm: String,
        keySize: Int,
        hardwareBacked: Boolean,
        requireAuth: Boolean,
        authValidity: Int
    ): Boolean
    
    external fun nativeSign(
        alias: String,
        data: ByteArray
    ): ByteArray?
    
    external fun nativeVerify(
        alias: String,
        data: ByteArray,
        signature: ByteArray
    ): Boolean
    
    external fun nativeGetAttestation(
        alias: String
    ): ByteArray?
    
    external fun nativeDeleteKey(alias: String): Boolean
    external fun nativeListKeys(): Array<String>
}

// High-level crypto manager using QSEE
class QSEECryptoManager(private val context: Context) {
    private val qseeBridge = QSEEBridge()
    private val keyStore: KeyStore
    
    companion object {
        private const val TAG = "QSEECryptoManager"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
    
    init {
        qseeBridge.nativeInit()
        keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply {
            load(null)
        }
    }
    
    // Check if device supports hardware-backed keys
    fun isHardwareBackedKeysSupported(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            // Check for hardware-backed keystore
            try {
                val testAlias = "test_hw_key_${System.currentTimeMillis()}"
                val keyGenSpec = KeyGenParameterSpec.Builder(
                    testAlias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .setAlgorithmParameterSpec(java.security.spec.ECGenParameterSpec("secp256r1"))
                    .build()
                
                val keyGen = java.security.KeyPairGenerator.getInstance(
                    KeyProperties.KEY_ALGORITHM_EC,
                    ANDROID_KEYSTORE
                )
                keyGen.initialize(keyGenSpec)
                val keyPair = keyGen.generateKeyPair()
                
                // Check if key is hardware-backed
                val factory = java.security.KeyFactory.getInstance(
                    keyPair.private.algorithm,
                    ANDROID_KEYSTORE
                )
                val keyInfo = factory.getKeySpec(
                    keyPair.private,
                    android.security.keystore.KeyInfo::class.java
                )
                
                // Clean up test key
                keyStore.deleteEntry(testAlias)
                
                keyInfo.isInsideSecureHardware
            } catch (e: Exception) {
                Log.e(TAG, "Failed to check hardware backing", e)
                false
            }
        } else {
            false
        }
    }
    
    // Check if device supports StrongBox
    fun isStrongBoxSupported(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            context.packageManager.hasSystemFeature(
                android.content.pm.PackageManager.FEATURE_STRONGBOX_KEYSTORE
            )
        } else {
            false
        }
    }
    
    // Generate a key with optional biometric protection
    fun generateKey(
        alias: String,
        requireBiometric: Boolean = false,
        useStrongBox: Boolean = false
    ): Boolean {
        return try {
            val success = qseeBridge.nativeGenerateKey(
                alias = alias,
                algorithm = "EC",
                keySize = 256,
                hardwareBacked = true,
                requireAuth = requireBiometric,
                authValidity = if (requireBiometric) 300 else 0 // 5 minutes
            )
            
            if (success) {
                Log.i(TAG, "Key generated successfully: $alias")
            } else {
                Log.e(TAG, "Failed to generate key: $alias")
            }
            
            success
        } catch (e: Exception) {
            Log.e(TAG, "Error generating key", e)
            false
        }
    }
    
    // Sign data with biometric authentication
    fun signDataWithBiometric(
        activity: FragmentActivity,
        alias: String,
        data: ByteArray,
        onSuccess: (ByteArray) -> Unit,
        onError: (String) -> Unit
    ) {
        val executor: Executor = ContextCompat.getMainExecutor(context)
        val biometricPrompt = BiometricPrompt(activity, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    onError("Authentication error: $errString")
                }
                
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    
                    // Now sign the data
                    val signature = qseeBridge.nativeSign(alias, data)
                    if (signature != null) {
                        onSuccess(signature)
                    } else {
                        onError("Failed to sign data")
                    }
                }
                
                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    onError("Authentication failed")
                }
            })
        
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("Authenticate to sign")
            .setSubtitle("Use your biometric credential to sign data")
            .setNegativeButtonText("Cancel")
            .build()
        
        biometricPrompt.authenticate(promptInfo)
    }
    
    // Sign data without authentication
    fun signData(alias: String, data: ByteArray): ByteArray? {
        return qseeBridge.nativeSign(alias, data)
    }
    
    // Verify signature
    fun verifySignature(
        alias: String,
        data: ByteArray,
        signature: ByteArray
    ): Boolean {
        return qseeBridge.nativeVerify(alias, data, signature)
    }
    
    // Get key attestation
    fun getKeyAttestation(alias: String): ByteArray? {
        return qseeBridge.nativeGetAttestation(alias)
    }
    
    // Delete key
    fun deleteKey(alias: String): Boolean {
        return qseeBridge.nativeDeleteKey(alias)
    }
    
    // List all keys
    fun listKeys(): List<String> {
        return qseeBridge.nativeListKeys().toList()
    }
}

// Example usage in an Activity
class ExampleActivity : FragmentActivity() {
    private lateinit var cryptoManager: QSEECryptoManager
    
    override fun onCreate(savedInstanceState: android.os.Bundle?) {
        super.onCreate(savedInstanceState)
        
        cryptoManager = QSEECryptoManager(this)
        
        // Check capabilities
        Log.i("Example", "Hardware-backed keys: ${cryptoManager.isHardwareBackedKeysSupported()}")
        Log.i("Example", "StrongBox: ${cryptoManager.isStrongBoxSupported()}")
        
        // Generate a key
        val keyAlias = "my_secure_key"
        if (cryptoManager.generateKey(keyAlias, requireBiometric = true)) {
            // Sign some data
            val dataToSign = "Hello QSEE!".toByteArray()
            
            cryptoManager.signDataWithBiometric(
                activity = this,
                alias = keyAlias,
                data = dataToSign,
                onSuccess = { signature ->
                    val signatureBase64 = Base64.encodeToString(signature, Base64.NO_WRAP)
                    Log.i("Example", "Signature: $signatureBase64")
                    
                    // Verify the signature
                    val isValid = cryptoManager.verifySignature(keyAlias, dataToSign, signature)
                    Log.i("Example", "Signature valid: $isValid")
                },
                onError = { error ->
                    Log.e("Example", "Sign failed: $error")
                }
            )
        }
    }
}

// Data class for key information
data class QSEEKeyInfo(
    val alias: String,
    val algorithm: String,
    val isHardwareBacked: Boolean,
    val requiresAuthentication: Boolean,
    val createdAt: Long
)

// Extended manager with more features
class AdvancedQSEEManager(context: Context) : QSEECryptoManager(context) {
    
    // Generate key with custom parameters
    fun generateAdvancedKey(
        alias: String,
        algorithm: KeyAlgorithm,
        keySize: Int,
        purposes: Set<KeyPurpose>,
        authenticationRequired: Boolean = false,
        authenticationValiditySeconds: Int = 300,
        useStrongBox: Boolean = false
    ): Boolean {
        // Map to native parameters and generate
        return generateKey(alias, authenticationRequired, useStrongBox)
    }
    
    // Batch operations
    fun signMultiple(
        alias: String,
        dataList: List<ByteArray>
    ): List<ByteArray?> {
        return dataList.map { data ->
            signData(alias, data)
        }
    }
    
    // Key rotation
    fun rotateKey(oldAlias: String, newAlias: String): Boolean {
        // Generate new key
        if (!generateKey(newAlias)) {
            return false
        }
        
        // Delete old key after successful generation
        return deleteKey(oldAlias)
    }
    
    // Export public key (for key agreement)
    fun exportPublicKey(alias: String): ByteArray? {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
            val publicKey = keyStore.getCertificate(alias)?.publicKey
            publicKey?.encoded
        } catch (e: Exception) {
            null
        }
    }
}

// Enums for advanced usage
enum class KeyAlgorithm {
    RSA_2048,
    RSA_3072,
    RSA_4096,
    EC_P256,
    EC_P384,
    EC_P521
}

enum class KeyPurpose {
    SIGN,
    VERIFY,
    ENCRYPT,
    DECRYPT
}

// Compose UI Example
@androidx.compose.runtime.Composable
fun CryptoKeyManager() {
    val context = androidx.compose.ui.platform.LocalContext.current
    val cryptoManager = remember { QSEECryptoManager(context) }
    var keys by remember { mutableStateOf(cryptoManager.listKeys()) }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        Text(
            text = "QSEE Key Manager",
            style = MaterialTheme.typography.h4
        )
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Hardware info
        Card(
            modifier = Modifier.fillMaxWidth()
        ) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text("Hardware Support", style = MaterialTheme.typography.h6)
                Text("Hardware-backed: ${cryptoManager.isHardwareBackedKeysSupported()}")
                Text("StrongBox: ${cryptoManager.isStrongBoxSupported()}")
            }
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Generate key button
        Button(
            onClick = {
                val newAlias = "key_${System.currentTimeMillis()}"
                if (cryptoManager.generateKey(newAlias, requireBiometric = true)) {
                    keys = cryptoManager.listKeys()
                }
            },
            modifier = Modifier.fillMaxWidth()
        ) {
            Text("Generate New Key")
        }
        
        Spacer(modifier = Modifier.height(16.dp))
        
        // Key list
        LazyColumn {
            items(keys) { key ->
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(vertical = 4.dp)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(16.dp),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        Text(key)
                        IconButton(
                            onClick = {
                                if (cryptoManager.deleteKey(key)) {
                                    keys = cryptoManager.listKeys()
                                }
                            }
                        ) {
                            Icon(Icons.Default.Delete, contentDescription = "Delete")
                        }
                    }
                }
            }
        }
    }
}