# crypto-tee-core

# CryptoTEE

CryptoTEE is a cross-platform SDK for secure key management and message integrity using TEE (Trusted Execution Environment) and RFC 9421. It provides a modular, kernel-inspired architecture for building cryptographic operations across Android, iOS, and Unix-based systems.

## Features

- TEE-based key generation and signing
- RFC 9421 message signing support
- Modular architecture with vendor and platform abstraction
- Rust core with FFI bindings for Kotlin, Swift, Node.js

## Architecture Overview
L5: Application Layer (Web3, AI Agent, Auth Client)
L4: RFC 9421 Message Signing Layer
L3: CryptoTEE API Layer (Key Abstraction Interface)
L2: Platform Adapter Layer (Android, iOS, Unix)
L1: Vendor Adapter Layer (Knox, Secure Enclave, QSEE, OP-TEE)


