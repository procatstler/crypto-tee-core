CryptoTEE 프로젝트 개요 및 설계 문서

📌 프로젝트 개요

CryptoTEE는 Android, iOS, Unix 등 다양한 플랫폼에서 동작하는 TEE(Trusted Execution Environment) 기반 보안 키 관리 및 서명 SDK입니다. 이 프로젝트는 다음과 같은 목표를 갖고 있습니다:

🎯 목적
	•	디바이스 보안 영역(TEE) 을 활용한 키 생성, 저장, 서명 기능 제공
	•	RFC 9421 기반 메시지 서명 으로 종단 간 무결성 보장
	•	제조사 및 플랫폼 독립적 아키텍처 구현을 통한 범용 SDK 개발

⸻

❗ 해결하려는 문제점

문제점	설명
디바이스마다 TEE 구조가 상이함	Secure Enclave(iOS), Knox(Android), OP-TEE 등으로 구조와 접근 방식이 다름
플랫폼 종속적 키 관리 방식	Android/iOS 별 구현이 달라 앱 레벨 추상화가 어려움
종단 간 메시지 무결성 부족	기존 TLS만으로는 메시지 조작 탐지가 어려움 (RFC 9421 요구됨)
경량화 어려움	특정 알고리즘/기능이 모든 앱에 필요하지 않음 → 모듈화 필요


⸻

🧱 아키텍처 개요 (계층적 설계)

L5. Application Layer
    └─ Web3 Wallet, AI Agent, Secure Messenger 등

L4. RFC 9421 Signing Layer
    └─ 메시지 서명 및 헤더 구성 (SAGE 연동)

L3. CryptoTEE Core Layer
    └─ 키 관리 및 서명 API 추상화 계층

L2. PlatformTEE Adapter Layer
    └─ Android, iOS, Unix 등 OS별 처리

L1. VendorTEE Adapter Layer
    └─ 제조사별 보안 영역 (Knox, Enclave, OP-TEE)


⸻

🧩 주요 기능 (Layer 3 중심 인터페이스)

CryptoTEE Trait 예시

trait CryptoTEE {
    fn list_capabilities(&self) -> Result<Vec<Capability>>;
    fn generate_key(&self, alias: &str, options: KeyOptions) -> Result<KeyHandle>;
    fn sign(&self, key: &KeyHandle, data: &[u8], options: Option<SignOptions>) -> Result<Vec<u8>>;
}

KeyOptions 예시

pub struct KeyOptions {
    pub algorithm: KeyAlgorithm, // RSA, ECDSA, ED25519 등
    pub key_size: Option<u16>,   // 2048, 3072, 4096...
    pub is_exportable: bool,
    pub allow_sign: bool,
    pub allow_decrypt: bool,
}


⸻

🧰 모듈 구성 및 빌드 전략

Cargo Features 구조

[features]
default = ["rsa", "sha2"]
rsa = []
ecdsa = []
ed25519 = []
sha2 = []
secure_enclave = []
knox = []
soft-crypto = []

디렉토리 구조

crypto-tee/
├── src/
│   ├── traits/        # CryptoTEE, PlatformTEE, VendorTEE
│   ├── types/         # KeyOptions, SignOptions, KeyHandle
│   ├── platform/      # OS-specific adapter (android.rs, ios.rs)
│   ├── vendor/        # Secure Enclave, Knox, OP-TEE
│   ├── fallback/      # 소프트웨어 백엔드
│   └── ffi/           # FFI 레이어 (extern "C")
├── include/           # iOS C-Bridge 헤더
├── examples/          # 예제 앱
├── Cargo.toml


⸻

🌐 다중 언어 바인딩 (FFI)

언어	바인딩 방식	도구
Kotlin (Android)	JNI → Rust	jni-rs, ndk
Swift (iOS)	C Header → Rust	cbindgen
TypeScript (Node.js)	napi → Rust	napi-rs


⸻

📋 개발 단계별 TODO
	1.	✅ 요구사항 정리 및 문제 정의
	2.	✅ 계층 아키텍처 설계 (L1 ~ L5)
	3.	✅ CryptoTEE 인터페이스 정의
	4.	✅ KeyOptions, SignOptions 등 구조화
	5.	✅ VendorTEE 인터페이스 정의 (Secure Enclave, Knox 등)
	6.	✅ PlatformTEE 인터페이스 정의 (Android, iOS, Unix)
	7.	⏭️ Rust 기반 core-crate (crypto-tee) 구조화
	8.	⏭️ FFI 구조 설계 및 언어별 예제 작성
	9.	⏭️ RFC 9421 Signing Layer 연동 (SAGE)
	10.	⏭️ 종단 메시지 무결성 예제 및 통합 테스트 작성

⸻

🔐 라이선스

MIT OR Apache-2.0 (TBD)

⸻

📎 관련 기술 스택
	•	Rust (core, FFI)
	•	Android NDK, Swift
	•	TEE: Secure Enclave, TrustZone, Knox, OP-TEE
	•	RFC 9421 (Message Signature)
	•	cbindgen, jni-rs, napi-rs

⸻

