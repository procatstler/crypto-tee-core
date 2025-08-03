// Example iOS integration for Apple Secure Enclave
// 
// This example demonstrates how to integrate the Apple Secure Enclave
// implementation in an iOS application.

import Foundation
import Security
import LocalAuthentication

// Swift wrapper for Rust CryptoTEE Secure Enclave functions
@objc class SecureEnclaveWrapper: NSObject {
    
    // Initialize the Secure Enclave TEE
    @objc static func initialize() -> Bool {
        // In a real implementation, this would call the Rust library
        // through a bridging header or FFI
        return true
    }
    
    // Generate a key in Secure Enclave
    @objc static func generateKey(requireBiometric: Bool, label: String) -> String? {
        // This would call the Rust implementation
        // For demonstration, we show the native iOS approach
        
        let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            requireBiometric ? [.privateKeyUsage, .biometryCurrentSet] : .privateKeyUsage,
            nil
        )!
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrLabel as String: label,
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            print("Error generating key: \(error!.takeRetainedValue())")
            return nil
        }
        
        // Return a key identifier
        return UUID().uuidString
    }
    
    // Sign data with Secure Enclave key
    @objc static func signData(keyId: String, data: Data) -> Data? {
        // This would retrieve the key and sign through Rust
        // For demonstration, we show the concept
        
        let context = LAContext()
        context.localizedReason = "Authenticate to sign data"
        
        // In real implementation, retrieve key by ID and sign
        return nil
    }
}

// Example iOS View Controller using Secure Enclave
class SecureEnclaveViewController: UIViewController {
    
    @IBOutlet weak var statusLabel: UILabel!
    @IBOutlet weak var generateKeyButton: UIButton!
    @IBOutlet weak var signDataButton: UIButton!
    
    private var currentKeyId: String?
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        // Initialize Secure Enclave TEE
        if SecureEnclaveWrapper.initialize() {
            statusLabel.text = "Secure Enclave Ready"
        } else {
            statusLabel.text = "Secure Enclave Not Available"
            generateKeyButton.isEnabled = false
            signDataButton.isEnabled = false
        }
    }
    
    @IBAction func generateKeyTapped(_ sender: Any) {
        // Check biometric availability
        let context = LAContext()
        var error: NSError?
        
        let canUseBiometric = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        if canUseBiometric {
            // Generate key with biometric protection
            if let keyId = SecureEnclaveWrapper.generateKey(requireBiometric: true, label: "CryptoTEE Key") {
                currentKeyId = keyId
                statusLabel.text = "Key Generated: \(keyId)"
                signDataButton.isEnabled = true
            }
        } else {
            // Generate key without biometric
            if let keyId = SecureEnclaveWrapper.generateKey(requireBiometric: false, label: "CryptoTEE Key") {
                currentKeyId = keyId
                statusLabel.text = "Key Generated (No Biometric): \(keyId)"
                signDataButton.isEnabled = true
            }
        }
    }
    
    @IBAction func signDataTapped(_ sender: Any) {
        guard let keyId = currentKeyId else {
            statusLabel.text = "No key available"
            return
        }
        
        let dataToSign = "Hello Secure Enclave".data(using: .utf8)!
        
        // Authenticate and sign
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, 
                              localizedReason: "Authenticate to sign data") { success, error in
            DispatchQueue.main.async {
                if success {
                    if let signature = SecureEnclaveWrapper.signData(keyId: keyId, data: dataToSign) {
                        self.statusLabel.text = "Data signed successfully"
                    } else {
                        self.statusLabel.text = "Signing failed"
                    }
                } else {
                    self.statusLabel.text = "Authentication failed: \(error?.localizedDescription ?? "Unknown")"
                }
            }
        }
    }
}

// SwiftUI Example
import SwiftUI

struct SecureEnclaveView: View {
    @State private var status = "Initializing..."
    @State private var keyId: String?
    @State private var showingBiometricPrompt = false
    
    var body: some View {
        VStack(spacing: 20) {
            Text("Apple Secure Enclave Demo")
                .font(.title)
            
            Text(status)
                .font(.caption)
                .foregroundColor(.gray)
            
            Button("Generate Secure Key") {
                generateKey()
            }
            .buttonStyle(.borderedProminent)
            
            Button("Sign Data") {
                signData()
            }
            .buttonStyle(.bordered)
            .disabled(keyId == nil)
            
            if let keyId = keyId {
                Text("Key ID: \(keyId)")
                    .font(.caption2)
                    .monospaced()
            }
        }
        .padding()
        .onAppear {
            initializeSecureEnclave()
        }
    }
    
    func initializeSecureEnclave() {
        if SecureEnclaveWrapper.initialize() {
            status = "Secure Enclave Ready"
        } else {
            status = "Secure Enclave Not Available"
        }
    }
    
    func generateKey() {
        let context = LAContext()
        var error: NSError?
        
        let biometricAvailable = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        if let newKeyId = SecureEnclaveWrapper.generateKey(
            requireBiometric: biometricAvailable,
            label: "CryptoTEE Demo Key"
        ) {
            keyId = newKeyId
            status = "Key generated successfully"
        } else {
            status = "Key generation failed"
        }
    }
    
    func signData() {
        guard let keyId = keyId else { return }
        
        let context = LAContext()
        context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                              localizedReason: "Authenticate to sign data") { success, error in
            DispatchQueue.main.async {
                if success {
                    let data = "Hello from SwiftUI".data(using: .utf8)!
                    if let signature = SecureEnclaveWrapper.signData(keyId: keyId, data: data) {
                        status = "Signed: \(signature.base64EncodedString().prefix(20))..."
                    } else {
                        status = "Signing failed"
                    }
                } else {
                    status = "Authentication failed"
                }
            }
        }
    }
}

// Bridging Header Example (CryptoTEE-Bridging-Header.h)
/*
#ifndef CryptoTEE_Bridging_Header_h
#define CryptoTEE_Bridging_Header_h

// Import Rust library functions
extern void crypto_tee_initialize(void);
extern const char* crypto_tee_generate_key(bool require_biometric, const char* label);
extern const uint8_t* crypto_tee_sign_data(const char* key_id, const uint8_t* data, size_t data_len, size_t* out_len);
extern void crypto_tee_free_string(char* s);
extern void crypto_tee_free_bytes(uint8_t* bytes);

#endif
*/

// Info.plist additions needed:
/*
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to access your secure keys</string>
*/