# CryptoTEE 프로젝트 아키텍처 설계 문서

## 📌 프로젝트 개요

**CryptoTEE**는 TEE(Trusted Execution Environment) 기반 보안 키 관리와 RFC 9421 메시지 서명을 통합하여 종단 간 메시지 무결성을 보장하는 크로스 플랫폼 보안 프레임워크입니다.

### 🎯 핵심 목표
- **하드웨어 기반 키 보호**: TEE/Secure Enclave를 활용한 안전한 키 생성 및 저장
- **표준 기반 메시지 서명**: RFC 9421 준수로 플랫폼 독립적 메시지 무결성 보장
- **크로스 플랫폼 지원**: Android, iOS, Unix 등 다양한 환경에서 동일한 API 제공
- **제조사 독립성**: 삼성 Knox, Apple Secure Enclave 등 다양한 TEE 구현체 지원

## 🧱 계층형 아키텍처 (Kernel-inspired Design)

```
┌─────────────────────────────────────────────┐
│         L5: Application Layer               │
│    (Web3 Wallet, AI Agent, Secure Apps)    │
└────────────────┬────────────────────────────┘
                 │
┌────────────────┴────────────────────────────┐
│         L4: RFC 9421 Signing Layer          │
│   (Message Canonicalization & Signature)    │
└────────────────┬────────────────────────────┘
                 │
┌────────────────┴────────────────────────────┐
│         L3: CryptoTEE Core Layer            │
│      (Key Management Abstraction API)       │
└────────────────┬────────────────────────────┘
                 │
┌────────────────┴────────────────────────────┐
│         L2: Platform Adapter Layer          │
│    (Android, iOS, Unix OS Abstraction)     │
└────────────────┬────────────────────────────┘
                 │
┌────────────────┴────────────────────────────┐
│         L1: Vendor Adapter Layer            │
│  (Knox, Secure Enclave, OP-TEE, QSEE)     │
└─────────────────────────────────────────────┘
```

## 📋 Layer별 설계 및 Feature 정의

### Layer 1: Vendor Adapter Layer

#### 목적
제조사별 TEE/Secure Element의 특수한 기능과 제약사항을 추상화하여 상위 레이어에 일관된 인터페이스 제공

#### 주요 Features
- **F1.1 Vendor Capability Detection**
  - 디바이스의 TEE 지원 여부 확인
  - 지원 가능한 알고리즘 및 키 크기 조회
  - 보안 수준 확인 (StrongBox, Hardware-backed 등)

- **F1.2 Vendor-specific Key Operations**
  - 제조사별 키 생성 API 래핑
  - 특수 보안 기능 활용 (Knox Vault, Secure Enclave 등)
  - 제조사별 인증/검증 메커니즘 지원

- **F1.3 Secure Communication Channel**
  - TEE와의 안전한 통신 채널 구성
  - 제조사별 프로토콜 처리

#### 설계 원칙 (SOLID)
- **Single Responsibility**: 각 Vendor Adapter는 하나의 제조사 TEE만 담당
- **Open/Closed**: 새로운 제조사 추가 시 기존 코드 수정 없이 확장 가능
- **Interface Segregation**: 제조사별 특수 기능은 별도 인터페이스로 분리

#### 플러그인 아키텍처
```rust
// Vendor Plugin Interface
pub trait VendorTEE: Send + Sync {
    fn probe(&self) -> Result<VendorCapabilities>;
    fn generate_key(&self, params: &KeyGenParams) -> Result<VendorKeyHandle>;
    fn sign(&self, key: &VendorKeyHandle, data: &[u8]) -> Result<Vec<u8>>;
    fn get_attestation(&self) -> Result<Attestation>;
}

// Plugin Registration
pub struct VendorRegistry {
    vendors: HashMap<String, Box<dyn VendorTEE>>,
}

impl VendorRegistry {
    pub fn register(&mut self, name: &str, vendor: Box<dyn VendorTEE>) {
        self.vendors.insert(name.to_string(), vendor);
    }
}
```

#### TDD 접근 방법
1. **Mock Vendor 구현**: 테스트용 가상 TEE 구현체 작성
2. **Capability 테스트**: 각 벤더의 기능 지원 여부 검증
3. **Error Handling 테스트**: TEE 접근 실패 시나리오 검증
4. **Performance 테스트**: 키 생성/서명 성능 측정

### Layer 2: Platform Adapter Layer

#### 목적
운영체제별 보안 API를 통합하여 플랫폼 독립적인 키 관리 인터페이스 제공

#### 주요 Features
- **F2.1 Platform Abstraction**
  - Android Keystore API 래핑
  - iOS Keychain Services 추상화
  - Linux keyring/OP-TEE 클라이언트 통합

- **F2.2 Platform-specific Security Features**
  - 생체인증 연동 (BiometricPrompt, LAContext)
  - 플랫폼별 접근 제어 정책 적용
  - 백업/복구 메커니즘 지원

- **F2.3 FFI Bridge Implementation**
  - Rust ↔ Java/Kotlin (JNI)
  - Rust ↔ Swift/ObjC (C FFI)
  - Rust ↔ C/C++ (Native)

#### 설계 원칙 (SOLID)
- **Dependency Inversion**: 플랫폼 구현체는 추상 인터페이스에 의존
- **Liskov Substitution**: 모든 플랫폼 어댑터는 동일한 계약 준수

#### 플러그인 아키텍처
```rust
// Platform Plugin Interface
pub trait PlatformTEE {
    type VendorImpl: VendorTEE;
    
    fn detect_vendors(&self) -> Vec<Box<dyn VendorTEE>>;
    fn select_best_vendor(&self) -> Result<Self::VendorImpl>;
    fn handle_platform_auth(&self, challenge: &[u8]) -> Result<AuthResult>;
}

// Dynamic Platform Loading
#[cfg(target_os = "android")]
pub fn load_platform() -> Box<dyn PlatformTEE> {
    Box::new(AndroidPlatform::new())
}

#[cfg(target_os = "ios")]
pub fn load_platform() -> Box<dyn PlatformTEE> {
    Box::new(IOSPlatform::new())
}
```

#### TDD 접근 방법
1. **Platform Detection 테스트**: OS 버전 및 기능 감지 검증
2. **FFI Boundary 테스트**: 언어 간 데이터 전달 무결성 확인
3. **Permission 테스트**: 플랫폼별 권한 요청 시나리오
4. **Fallback 테스트**: Vendor TEE 미지원 시 동작 검증

### Layer 3: CryptoTEE Core Layer

#### 목적
하위 레이어의 복잡성을 숨기고 간단하고 일관된 키 관리 API 제공

#### 주요 Features
- **F3.1 Unified Key Management API**
  - `generate_key()`: 안전한 키 생성
  - `import_key()`: 외부 키 가져오기 (지원 시)
  - `delete_key()`: 키 안전한 삭제
  - `list_keys()`: 키 목록 조회

- **F3.2 Cryptographic Operations**
  - `sign()`: 데이터 서명
  - `verify()`: 서명 검증
  - `encrypt()`/`decrypt()`: 암복호화 (선택적)

- **F3.3 Key Lifecycle Management**
  - 키 회전 정책 지원
  - 키 만료 관리
  - 키 사용 감사 로깅

#### 설계 원칙 (SOLID)
- **Single Responsibility**: 키 관리와 암호화 연산만 담당
- **Open/Closed**: 새로운 암호화 알고리즘 추가 시 확장 가능

#### 플러그인 아키텍처
```rust
// Core API
pub struct CryptoTEE {
    platform: Box<dyn PlatformTEE>,
    plugins: PluginManager,
}

// Plugin System
pub trait CryptoPlugin {
    fn name(&self) -> &str;
    fn initialize(&mut self, context: &CryptoContext) -> Result<()>;
    fn extend_operations(&self) -> Vec<Operation>;
}

// Algorithm Plugin Example
pub struct Ed25519Plugin;

impl CryptoPlugin for Ed25519Plugin {
    fn name(&self) -> &str { "ed25519" }
    
    fn extend_operations(&self) -> Vec<Operation> {
        vec![
            Operation::new("ed25519_sign", |params| { /* ... */ }),
            Operation::new("ed25519_verify", |params| { /* ... */ }),
        ]
    }
}
```

#### TDD 접근 방법
1. **API Contract 테스트**: 모든 공개 API의 동작 검증
2. **Algorithm 테스트**: 각 암호화 알고리즘의 정확성 검증
3. **Concurrency 테스트**: 동시 키 접근 시나리오
4. **Error Recovery 테스트**: 장애 상황 복구 검증

### Layer 4: RFC 9421 Signing Layer

#### 목적
HTTP 메시지 서명 표준(RFC 9421)을 구현하여 메시지 무결성 보장

#### 주요 Features
- **F4.1 Message Canonicalization**
  - HTTP 요청/응답 정규화
  - 서명 대상 컴포넌트 추출
  - Signature Base 생성

- **F4.2 Signature Generation**
  - Signature-Input 헤더 생성
  - CryptoTEE를 통한 서명 수행
  - Signature 헤더 구성

- **F4.3 Signature Verification**
  - 서명 헤더 파싱
  - 메시지 재구성 및 검증
  - 서명 유효성 확인

#### 설계 원칙 (SOLID)
- **Interface Segregation**: 서명/검증 인터페이스 분리
- **Dependency Inversion**: CryptoTEE 추상화에만 의존

#### 플러그인 아키텍처
```rust
// RFC 9421 Signer Interface
pub trait MessageSigner {
    fn sign_request(&self, req: &HttpRequest, key_id: &str) -> Result<SignedRequest>;
    fn verify_request(&self, req: &SignedRequest) -> Result<VerificationResult>;
}

// Signature Algorithm Plugin
pub trait SignatureAlgorithm {
    fn identifier(&self) -> &str;
    fn sign(&self, key: &KeyHandle, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, key: &KeyHandle, data: &[u8], sig: &[u8]) -> Result<bool>;
}

// Plugin Registration
impl Rfc9421Signer {
    pub fn register_algorithm(&mut self, alg: Box<dyn SignatureAlgorithm>) {
        self.algorithms.insert(alg.identifier().to_string(), alg);
    }
}
```

#### TDD 접근 방법
1. **Canonicalization 테스트**: 메시지 정규화 정확성 검증
2. **Known Vector 테스트**: RFC 9421 테스트 벡터 검증
3. **Header Injection 테스트**: 악의적 헤더 주입 방어
4. **Compatibility 테스트**: 타 구현체와의 상호운용성

### Layer 5: Application Layer

#### 목적
최종 사용자 애플리케이션에 보안 기능 제공

#### 주요 Features
- **F5.1 High-level SDKs**
  - Android SDK (Kotlin)
  - iOS SDK (Swift)
  - Web SDK (TypeScript/WASM)

- **F5.2 Use-case Specific APIs**
  - Web3 Wallet Integration
  - Secure Messaging
  - Authentication Services

#### 설계 원칙
- 사용자 친화적 API
- 플랫폼 관례 준수
- 강력한 에러 처리

## 🔧 기술 스택

### Core (Rust)
- **선택 이유**: 메모리 안전성, 성능, FFI 지원
- **주요 의존성**:
  - `ring`: 암호화 primitives
  - `tracing`: 구조화된 로깅
  - `thiserror`: 에러 처리
  - `serde`: 직렬화

### Platform Bindings
- **Android**: JNI (`jni-rs`), NDK
- **iOS**: C FFI (`cbindgen`), Swift Package Manager
- **Node.js**: N-API (`napi-rs`)

### Build System
```toml
[features]
default = ["software-fallback"]
vendor-samsung = ["dep:knox-sdk-sys"]
vendor-apple = ["dep:security-framework"]
platform-android = ["dep:jni", "dep:ndk"]
platform-ios = ["dep:core-foundation"]
full = ["vendor-samsung", "vendor-apple", "platform-android", "platform-ios"]
```

## 📁 프로젝트 구조

```
crypto-tee-core/
├── Cargo.toml
├── src/
│   ├── lib.rs                    # Public API
│   ├── core/                     # L3: Core implementation
│   │   ├── mod.rs
│   │   ├── api.rs               # CryptoTEE trait
│   │   ├── types.rs             # Core types
│   │   └── manager.rs           # Key lifecycle
│   ├── platform/                 # L2: Platform adapters
│   │   ├── mod.rs
│   │   ├── android.rs
│   │   ├── ios.rs
│   │   └── linux.rs
│   ├── vendor/                   # L1: Vendor implementations
│   │   ├── mod.rs
│   │   ├── samsung/
│   │   ├── apple/
│   │   └── qualcomm/
│   ├── rfc9421/                  # L4: Message signing
│   │   ├── mod.rs
│   │   ├── canonicalize.rs
│   │   ├── sign.rs
│   │   └── verify.rs
│   ├── plugins/                  # Plugin system
│   │   ├── mod.rs
│   │   └── registry.rs
│   └── ffi/                      # FFI exports
│       ├── mod.rs
│       ├── android.rs
│       └── ios.rs
├── tests/                        # Integration tests
│   ├── common/
│   └── scenarios/
├── benches/                      # Performance benchmarks
└── examples/                     # Usage examples
```

## 🧪 TDD 개발 프로세스

### 1. Test-First Development
```rust
// 1. Write failing test
#[test]
fn test_generate_key_with_secure_enclave() {
    let tee = CryptoTEE::new().unwrap();
    let params = KeyGenParams::new()
        .algorithm(Algorithm::EcdsaP256)
        .use_secure_enclave(true);
    
    let result = tee.generate_key("test_key", params);
    assert!(result.is_ok());
}

// 2. Implement minimum code to pass
// 3. Refactor while keeping tests green
```

### 2. Test Categories
- **Unit Tests**: 각 모듈의 독립적 기능 검증
- **Integration Tests**: 레이어 간 통합 검증
- **Property Tests**: 무작위 입력으로 불변성 검증
- **Benchmark Tests**: 성능 regression 방지

### 3. Mock Infrastructure
```rust
// Mock Vendor for testing
pub struct MockVendor {
    keys: Arc<Mutex<HashMap<String, MockKey>>>,
}

impl VendorTEE for MockVendor {
    fn generate_key(&self, params: &KeyGenParams) -> Result<VendorKeyHandle> {
        // Simulated key generation
    }
}
```

## 🏗️ SOLID 원칙 적용

### Single Responsibility Principle
- 각 레이어는 명확한 단일 책임
- 모듈별 관심사 분리

### Open/Closed Principle
- 플러그인 시스템으로 확장 가능
- Core API는 변경에 닫혀있음

### Liskov Substitution Principle
- 모든 Vendor/Platform 구현체는 교체 가능
- 인터페이스 계약 엄격히 준수

### Interface Segregation Principle
- 작고 집중된 인터페이스
- 선택적 기능은 별도 trait

### Dependency Inversion Principle
- 상위 레이어는 추상화에만 의존
- 구체적 구현은 런타임에 주입

## 🔌 플러그인 시스템

### Plugin Lifecycle
```rust
// Plugin initialization
let mut tee = CryptoTEE::new()?;
tee.register_plugin(Box::new(Ed25519Plugin::new()));
tee.register_plugin(Box::new(Rfc9421Plugin::new()));

// Plugin discovery
let plugins = tee.discover_plugins("./plugins")?;
for plugin in plugins {
    tee.load_plugin(plugin)?;
}
```

### Custom Plugin Example
```rust
pub struct CustomSignaturePlugin;

impl CryptoPlugin for CustomSignaturePlugin {
    fn initialize(&mut self, ctx: &CryptoContext) -> Result<()> {
        // Register custom operations
        ctx.register_operation("custom_sign", custom_sign_handler);
        Ok(())
    }
}
```

## 📈 개발 로드맵

### Phase 1: Foundation (Month 1-2)
- [ ] Core architecture setup
- [ ] Basic vendor/platform abstractions
- [ ] Mock implementations
- [ ] CI/CD pipeline

### Phase 2: Platform Support (Month 3-4)
- [ ] Android Keystore integration
- [ ] iOS Keychain integration
- [ ] Software fallback
- [ ] Basic plugin system

### Phase 3: Advanced Features (Month 5-6)
- [ ] RFC 9421 implementation
- [ ] Samsung Knox support
- [ ] Apple Secure Enclave support
- [ ] Performance optimization

### Phase 4: Production Ready (Month 7-8)
- [ ] Security audit
- [ ] Documentation
- [ ] SDK releases
- [ ] Community building

## 🔐 보안 고려사항

### Threat Model
- **Key Extraction**: TEE로 방어
- **Side-channel Attacks**: 타이밍 공격 방어
- **API Misuse**: 강력한 타입 시스템으로 방지

### Security Best Practices
- 모든 키는 TEE 내부에서만 사용
- 민감한 데이터는 즉시 제로화
- 감사 로그 필수
- 정기적인 보안 업데이트

## 📚 참고 자료

- [RFC 9421: HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html)
- [Android Keystore System](https://developer.android.com/training/articles/keystore)
- [Apple Secure Enclave](https://support.apple.com/guide/security/secure-enclave-sec59b0b31ff/web)
- [GlobalPlatform TEE Specifications](https://globalplatform.org/specs-library/tee-specifications/)

---

*이 문서는 CryptoTEE 프로젝트의 living document로, 개발 진행에 따라 지속적으로 업데이트됩니다.*