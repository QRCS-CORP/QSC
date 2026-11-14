# QSC: Quantum Secure Cryptographic Library    

[![Build](https://img.shields.io/github/actions/workflow/status/QRCS-CORP/QSC/build.yml?branch=master)](https://github.com/QRCS-CORP/QSC/actions/workflows/build.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/QRCS-CORP/QSC/codeql-analysis.yml?label=CodeQL&branch=master)](https://github.com/QRCS-CORP/QSC/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/qsc/badge)](https://www.codefactor.io/repository/github/qrcs-corp/qsc)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](https://github.com/QRCS-CORP/QSC/security/policy)
[![License: QRCS-PREL](https://img.shields.io/badge/License-QRCS--PREL-blue.svg)](https://github.com/QRCS-CORP/QSC/blob/master/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%20%28C11%20build%29&color=blue)](https://github.com/QRCS-CORP/QSC/blob/master/CMakeLists.txt)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/QSC/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/QSC)](https://github.com/QRCS-CORP/QSC/releases/tag/2026-04-30)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/QSC.svg)](https://github.com/QRCS-CORP/QSC/commits/master)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)
[![ACVTS Demo](https://img.shields.io/badge/ACVTS%20Demo-25%2F25%20passed-brightgreen)](docs/pdf/qsc_acvts_qualification_report.pdf)

**A compact, self-contained, and highly optimized post-quantum secure cryptographic library written in portable C, with a C11 CMake build baseline.**

---

## What's New in This Release

Version **1.4.0.0 (November 2026)** adds profile-based optimized CMake compilation and optional hardware-protected key interfaces, alongside recent cryptographic optimization, side-channel hardening, TLS 1.3/X.509 integration, expanded elliptic-curve support, and regression coverage. The new build profiles permit smaller statically linked applications without requiring the full TLS and certificate stack.

### Profile-Based Optimized CMake Builds

The separately developed modular CMake integration under `Source/QSC/` introduces explicit source manifests, profile-specific compilation, generated feature metadata, and an exported `QSC::QSC` target. The first integration provided seven core profiles; subsequent integration work extended the selection to gateway, industrial, robotics, AI-model and vehicle uses. `FULL` retains the comprehensive cryptographic, TLS and X.509 stack, while compact profiles select a smaller dependency set.

- **Core profiles:** `FULL`, `CLASSICAL`, `PQC3`, `PQC5`, `HYBRID`, `DEVICE_IDENTITY`, `BOOT_VERIFY`.
- **Expanded application profiles:** `EDGE_GATEWAY`, `CLOUD_HSM`, `INDUSTRIAL_OT`, `ROBOT_EDGE`, `AI_MODEL_TRUST`, `VEHICLE_ECU` (from the later modular integration package). Consult the particular package's `QSCProfiles.cmake` and `CMakePresets.json` for its authoritative complete profile and preset lists; names may differ between integration revisions.
- **Build forms:** Static libraries are the default; the later integration package adds optional shared-library builds and more selective TLS/X.509 source inclusion.
- **Generated build metadata:** `QSCFeatures.h` and a machine-readable capability manifest describe the configured feature set; consumers receive the required compile definitions through the build interface.
- **Optional hardware integration:** Backend selection is explicit and a software-only build has no mandatory HSM, TPM or vendor SDK dependency.
- **Installation:** Modular builds provide the `QSC::QSC` imported target for `find_package(QSC CONFIG REQUIRED)` consumers.

This is **compile-time source selection**, not runtime CPU dispatch. Supported instruction-set optimizations still depend on compiler flags, target architecture, and platform capability. See [Optimized CMake Builds](#optimized-cmake-builds) for commands and qualification limits.

### Hardware-Protected Key Interfaces

QSC now supplies an **optional, versioned hardware-provider facade** and adapters for protected key operations. The facade accepts backend-reported capability, custody, usage, and export policy; it can open or create protected key references and request signing, public-key retrieval, eligible key agreement, RNG output, or attestation evidence when a backend supports those operations.

Supported adapter interfaces cover standards-based **PKCS#11 HSMs**, the **Windows NCrypt Platform Crypto Provider / TPM**, **Linux TPM 2.0 through TPM2-TSS ESAPI**, **Arm PSA Crypto / Trusted Firmware-M**, **Microchip ATECC608**, **NXP SE050/SE05x**, and **Apple Secure Enclave / Android Keystore** platform bridges. Dedicated PKCS#11 and NCrypt adapters integrate protected ECDSA signing with QSC TLS 1.3 and X.509/PKCS#10 workflows.

Hardware interfaces are disabled unless explicitly selected at compile time. Adapter availability does not establish that a physical device supports every algorithm, that private keys are hardware-resident, or that an implementation is FIPS 140-3 validated. Native device/firmware qualification, key-custody verification, and attestation evidence validation remain deployment-specific requirements. See [Hardware Security and Key Providers](#hardware-security-and-key-providers).

### Cryptographic Core Optimization and Hardening

Recent work has focused on improving performance without changing the public cryptographic APIs or silently changing standardized outputs:

- **AES and authenticated encryption** - Revised AES scalar and hardware-accelerated paths, including CTR big-/little-endian counter rollover and 128-bit wraparound regression coverage. AES-GCM and related authentication paths have received additional performance and correctness review.
- **SHA-2, SHA-3, SHAKE, cSHAKE, and HKDF** - Optimized hashing, XOF, and derivation implementations across portable and supported SIMD builds, including short-message and multi-block workloads. Known-answer consistency remains a qualification requirement for every code path.
- **ChaCha20-Poly1305, CSX, and RCS** - Reviewed and optimized stream-cipher and authenticated-encryption paths. CSX and RCS use their reduced-round default profiles, with extended-round configurations available through `QSC_CSX_EXTENDED_ROUND_COUNTS` and `QSC_RCS_EXTENDED_ROUND_COUNTS`; the selected configuration must match the corresponding test vectors and application protocol.
- **QMAC and related constructions** - Updated test coverage and documentation around nonce uniqueness, authentication semantics, and dependency changes in the SHA-3/Keccak implementation.
- **Elliptic-curve arithmetic** - Refined P-256 ECDSA signing and ECDH using native field arithmetic, multiplication/reduction pipeline improvements, and constant-time-oriented scalar multiplication. P-256 key agreement includes projective/scalar blinding and temporary-data clearing. NIST P-384 and P-521 key-agreement and signing interfaces remain available. Ed25519/Ed448 signatures and X25519/X448 key agreement are included; the SLH-DSA layer provides all six SHAKE-based 128/192/256 fast/small profiles.

Performance work is benchmark-guided and retains portable fallbacks. Constant-time-oriented implementation techniques and test results do not constitute a formal side-channel certification.

### High-Performance Networking and Concurrency

The socket and asynchronous execution infrastructure has been substantially modernized:

- **Persistent worker pools** - Optional reusable worker threads, bounded FIFO work queues, completion waiting, and graceful shutdown. Existing thread-pool APIs remain available.
- **Asynchronous socket servers** - Tracked listener workers, callback execution outside internal locks, improved shutdown, restart, and concurrent connection handling.
- **Scalable socket event handling** - Batched readiness and wakeup interfaces using Linux `epoll`, BSD/macOS `kqueue`, and a portable `poll()` fallback; an additive Windows IOCP interface supports overlapped send/receive completion processing.
- **Network I/O APIs** - Added partial-transfer progress reporting, scatter/gather I/O, and improved timeout, EOF, socket-address, and readiness handling.

These features are additive: applications can retain existing synchronous and legacy asynchronous APIs. Windows IOCP and BSD/macOS `kqueue` implementations still require native-platform qualification before release approval.

### Data Structures, Encoding, and System Utilities

The supporting library received a broad performance and correctness upgrade:

| Area | Recent improvements |
|---|---|
| **Lists and collections** | Geometric-capacity growth, corrected list sorting, bounded serialization, optional collection hash indexing, and allocation-failure handling |
| **Queues and sorting** | Contiguous aligned queue storage, checked/batch queue operations, insertion sort and introsort with heapsort fallback, and counting sort for large 8-bit inputs |
| **Memory and integer utilities** | Improved scalar/SIMD memory operations, corrected comparison paths, alignment-preserving resize API, checked conversions, hexadecimal processing, and 64-bit popcount |
| **Base64, DER, and PEM** | Incremental Base64 encode/decode APIs, faster Base64 decoding, zero-copy DER child traversal, structural/canonical checks, and overflow safeguards |
| **Files and directories** | Bounded streaming file copies, large-file offsets, non-truncating positional writes, faster directory listings, and callback-based enumeration |
| **IP and networking utilities** | Corrected IPv4/IPv6 parsing and formatting, CIDR membership helpers, improved DNS and interface selection |
| **CPU and OS information** | Corrected SIMD/OS-state feature detection, cache topology, reentrant account lookup, and optional cached CPU capability snapshots |
| **Time and system helpers** | Monotonic stopwatch timing, checked date parsing, high-resolution elapsed-time APIs, faster date formatting, and bounded system queries |
| **Events, console, and OIDs** | Corrected listener registration and synchronization, reduced console-output overhead, optimized transpose conversion, and indexed OID lookup |

Existing public APIs and checked public structure layouts have been retained; new functionality is exposed through additional APIs.

### Recent Performance Measurements

Representative **Linux x86-64, optimized GCC** microbenchmarks from the recent qualification work are shown below. These results describe specific input sizes and workloads, not guaranteed whole-application speedups.

| Operation | Observed improvement | Scope |
|---|---:|---|
| Collection append | 1,282× | 4,096 items; eliminates repeated whole-collection copying |
| Collection lookup with optional index | 120× | 4,096-item indexed lookup versus original linear scan |
| Asynchronous listener accept/callback overhead | 220× | 300 loopback connections; not end-to-end application throughput |
| Base64 decoding | 2.50× | Matched single-shot decoding benchmark |
| Directory listing | 2.01× | Matched P2 benchmark workload |
| Date formatting | 19.64× | Matched P2 benchmark workload |
| OID identifier lookup | 6.63× | Fixed registry identifier lookups |

The persistent-worker pool and socket event loop also substantially reduce per-task thread-creation and sparse-readiness polling overhead. Improvements vary by platform, compiler flags, workload, and data size.

### Verification and Release Qualification

The [QSC Technical Qualification Report](docs/pdf/qsc_technical_qualification_report_2026-11-06.pdf) records a source-pinned **15/15 successful native offline cryptographic qualification matrix**: Windows Server 2022 x64, Ubuntu 24.04 x64, Linux ARM64 (GCC and Clang), and macOS ARM64 (Apple Clang), each at QSC security classes 1, 3 and 5. Both consolidated evidence gates passed. The underlying qualification used the November 6 `QSC 2026-11-06-B.zip` source snapshot and the `QSC-ARM-Tests` qualification commit `07f32d8a18a91f7a9035994adcbecd234a09b5ac`; runner status is **PASS_WITH_COVERAGE_GAPS**. These are tests of the stated offline cryptographic harness and configurations, not an exhaustive test of every API or modular build profile.

A separate Linux development preflight compiled **241 QSC and QSCTest C translation units** under GCC and Clang with `-Wall -Wextra -Werror` and no diagnostics in that configuration. Additional regression, sanitizer and cross-module testing, together with independently checked Base64, hexadecimal, PEM and DER reference vectors, support engineering review; QSC and QSCTest do not require an OpenSSL runtime dependency.

The modular CMake system was developed and separately exercised using Linux/GCC full and compact profiles, optional PKCS#11 selection, installed external consumers and smoke/round-trip tests. A later review package added expanded application profiles and shared-library integration. These build-integration results are **distinct** from the 15-configuration native cryptographic qualification matrix. Native MSVC/macOS/ARM build-system qualification, physical HSM/TPM testing and formal certification require their own evidence. The technical report does not assert an official NIST ACVP algorithm validation or FIPS 140-3 module certificate.

### NIST ACVTS Demo Algorithm Qualification

In November 2026, QRCS completed **25 of 25 planned algorithm qualification targets** against the **NIST ACVTS Demo sample server**, covering **86 submitted vector sets**. The preserved qualification results report a successful NIST server verdict for each target. Tested algorithm families include SHA-2, SHA-3, SHAKE, HMAC, AES, PBKDF, ML-KEM, ML-DSA, SLH-DSA, HMAC_DRBG, KDA-HKDF, ECDSA, deterministic ECDSA, EdDSA, XECDH, and KAS-ECC-SSC.

The [QSC ACVTS Qualification Report](docs/pdf/qsc_acvts_qualification_report.pdf) documents the results, tested configurations, NIST session and vector-set identifiers, supporting evidence, and qualification boundaries. The campaign used **two explicitly identified, source-pinned QSC revisions**. A [machine-readable evidence manifest](https://github.com/QRCS-CORP/QSC-ACVP/blob/main/Source/ACVP/docs/evidence/2026-11/evidence-manifest.json) and the [public qualification record](https://github.com/QRCS-CORP/QSC-ACVP/blob/main/Source/ACVP/docs/evidence/2026-11/qualification-report.md) provide traceability to the GitHub Actions runs and preserved result artifacts.

**Qualification scope:** These were NIST ACVTS **Demo sample** tests. Passing results do not constitute NIST CAVP algorithm certification, FIPS 140-3/CMVP module validation, or qualification of every platform, instruction-set path, or subsequent QSC source revision.

### Complete TLS 1.3 Protocol Stack

The TLS 1.3 implementation is now complete. The stack implements the RFC 8446 handshake, record layer, certificate authentication, mutual TLS, session-ticket policy controls, HelloRetryRequest, post-handshake KeyUpdate and NewSessionTicket handling, ALPN negotiation, SNI-based certificate selection, and framed-message socket helpers. The TLS group layer supports classical ECDHE, pure ML-KEM, and the currently implemented IETF-aligned ECDHE+ML-KEM hybrid groups. See the [TLS 1.3 Protocol Stack](#tls-13-protocol-stack) section for the full module map and feature detail.

### TLS/X.509 Interoperability and Regression Coverage

The TLS/X.509 implementation has been expanded with peer-information inspection, structured verification-result reporting, socket option and timeout policy controls, concurrent shutdown cleanup, record fragmentation and coalescing handling, ALPN, SNI and multi-certificate support, mTLS authorization callbacks, framed-message helpers, session-ticket policy controls, and negative X.509 validation tests. The staged QSCTest suite now includes dedicated TLS regression stages for these features.

### Expanded Elliptic Curve Primitive Suite

The EC primitive layer has been substantially extended beyond the existing ECDSA and Ed25519 coverage:

- **ECDH over NIST P-curves** (`ecdh.h`, `ecdhp256.*`, `ecdhp384.*`, `ecdhp521.*`) - Static and ephemeral ECDH key agreement over P-256, P-384, and P-521 per NIST SP 800-56A and FIPS 186-5. Constant-time scalar multiplication; public key validation per SP 800-56A requirements. Reuses field arithmetic from the existing ECDSA implementations to avoid code duplication.

- **EdDH** (`eddh.h`, `eddh25519.*`, `eddh448.*`) - Edwards-curve Diffie-Hellman key exchange. Supports X25519 (Curve25519, parameter set `QSC_EDDH_S1EC25519`) and X448 (Goldilocks, parameter set `QSC_EDDH_S3EC448`). Designed for constant-time execution.

- **EdDSA** (`eddsa.h`, `eddsa25519.*`, `eddsa448.*`) - Unified Edwards-curve digital signature interface. Supports Ed25519 and Ed448 (Goldilocks) via a common API; parameter set selected at compile time (`QSC_EDDSA_S1EC25519` or `QSC_EDDSA_S3EC448`).

- **Ed448 / Goldilocks** (`ed448.h`, `ed448.c`) - Full implementation of the Ed448-Goldilocks Edwards curve, underpinning both EdDH-X448 and EdDSA-448.

---

## Documentation

| Resource | Description |
|---|---|
| [QSC Help Documentation](https://qrcs-corp.github.io/QSC/) | Full API reference and usage guide |
| [QSC Technical Specification](https://qrcs-corp.github.io/QSC/pdf/qsc_specification.pdf) | Detailed algorithmic and design specification |
| [QSC Summary Document](https://qrcs-corp.github.io/QSC/pdf/qsc_summary.pdf) | High-level overview of the library |
| [QSC Technical Qualification Report](docs/pdf/qsc_technical_qualification_report_2026-11-06.pdf) | November 6, 2026 engineering qualification dossier; 15 native configurations, evidence matrices and assessment findings (116 pages) |
| [QSC ACVTS Qualification Report](docs/pdf/qsc_acvts_qualification_report.pdf) | November 2026 NIST ACVTS Demo sample results; 25/25 qualification targets and 86 vector sets, with source-pinned evidence and qualification boundaries |
| [Commercial SDK and Wrapper Specifications](#commercial-sdk-and-language-wrappers) | Public technical specifications for the commercially licensed integration SDK and language bindings |

## Overview

QSC is a production-grade cryptographic library built for environments that demand verifiable correctness, long-term quantum resistance, and high throughput. The library combines NIST-standardized post-quantum algorithms with classical primitives, proprietary high-security constructions, and SIMD-accelerated implementations, within a portable C codebase with a C11 CMake build baseline and optional, separately selected hardware-provider dependencies.

The library includes a complete TLS 1.3 protocol stack (RFC 8446) built entirely on the QSC cryptographic core, with no dependency on OpenSSL or any other external TLS library. The stack implements the full handshake surface - 1-RTT certificate-authenticated, mutual TLS, PSK resumption with ticket-policy controls, HelloRetryRequest, post-handshake KeyUpdate and NewSessionTicket, ALPN, SNI-based certificate selection, peer-information inspection, structured verification results, framed-message socket helpers, and hardened shutdown behaviour. It supports hybrid post-quantum key exchange that combines classical ECDH with ML-KEM encapsulation in a single flight. It integrates directly with the QSC X.509 certificate infrastructure, key schedule, AEAD record layer, and socket I/O adapter.

Additional recent additions include ECDSA implementations for NIST P-256, P-384, and P-521, ECDH key agreement over the same NIST P-curves, X25519/X448 key agreement and Ed25519/Ed448 signatures, Falcon lattice-based signatures, the HQC code-based key encapsulation mechanism, and a comprehensive X.509 certificate infrastructure built on a strict DER/BER-capable ASN.1 engine. The X.509 layer covers the full certificate lifecycle: parsing, validation, generation, revocation, OCSP, PKCS#12 key management, and post-quantum ML-DSA certificate profiles, without any external dependencies.

Key design goals:

- **Long-term security** - supports post-quantum, classical, and hybrid asymmetric algorithms; proprietary constructions target 256-bit or greater security levels.
- **Standards alignment** - follows a MISRA-adjacent secure C coding discipline; standardized post-quantum primitives target FIPS 203, FIPS 204, and FIPS 205, and the TLS stack targets RFC 8446. Formal product validation and certification are separate processes.
- **Public internet compatibility** - NIST P-256, P-384, and P-521 ECDSA and ECDH, Edwards-curve EdDH/EdDSA, hybrid post-quantum groups, and X.509 certificate infrastructure enable deployment in TLS 1.3 stacks and compliance with CA/Browser Forum Baseline Requirements for publicly trusted certificates.
- **Performance** - portable C paths alongside AVX, AVX2, AVX-512, and supported ARM SIMD implementations selected at build time; profile-based CMake source selection reduces linked scope for compact applications. The fastest configuration depends on the CPU and workload.
- **Auditability** - thoroughly commented, well-structured source with a comprehensive test suite covering known-answer tests, NIST CAVP/ACVP vectors, fuzzing, and stress testing across every primitive.
- **Portability** - core software builds target Windows (MSVC), Linux (GCC), and macOS (Clang) without mandatory external cryptographic libraries; optional device backends may require platform SDKs or vendor middleware.

> **Version:** 1.4.0.0  
> **Tested on:** Windows 10 / 11 / Server · Ubuntu Linux · macOS  
> _Standardized ML-KEM, ML-DSA, and SLH-DSA target FIPS 203/204/205; other candidate and experimental algorithms are identified separately. RFC 8446 TLS 1.3 is implemented; standards alignment does not imply a completed NIST FIPS validation._

---

## Projects

The distribution includes two companion projects alongside the QSC library, both available on the QRCS-CORP/QSC project page, QSCTest and QSCCAVP.

### QSCTest

The primary validation suite for the QSC library. QSCTest exercises every cryptographic primitive through a structured battery of tests designed to detect correctness regressions, implementation errors, and performance degradation.

**Test coverage includes:**

- **Known Answer Tests (KATs)** - output from every primitive is verified against pre-computed reference vectors.
- **NIST ACVP Vectors** - asymmetric and symmetric primitives verified against official NIST Automated Cryptographic Validation Program test vectors.
- **Fuzzing** - randomized input testing to detect edge-case failures and undefined behaviour.
- **Stress Testing** - extended load testing to surface resource leaks, state corruption, and threading issues.
- **Function Correctness** - round-trip and cross-function consistency checks (e.g., encrypt→decrypt, sign→verify).

Coverage spans the full library: asymmetric ciphers (ML-KEM, McEliece, HQC, ECDH P-256/P-384/P-521, EdDH X25519/X448), signature schemes (ML-DSA, SLH-DSA, Falcon, ECDSA P-256/P-384/P-521, EdDSA Ed25519/Ed448), symmetric ciphers (AES, RCS, CSX, ChaCha20-Poly1305), hash and XOF functions (SHA2, SHA3, SHAKE, cSHAKE), MAC functions (KMAC, QMAC, HMAC, Poly1305), DRBGs (CSG, HCG), entropy providers (ACP, CSP, RDP, ETR), the X.509 certificate layer, the complete TLS 1.3 protocol stack, and all utility modules.

The TLS regression suite is organized into staged feature tests. Current TLS/X.509 stages include ALPN negotiation, SNI and multi-certificate policy, mTLS authorization callbacks, peer-info and verification-result inspection, session-ticket policy controls, framed-message helper policy, record fragmentation and coalescing, socket option and timeout policy, concurrent shutdown and worker cleanup, and negative X.509 certificate-purpose validation. Additional QSCTest coverage includes embedded OpenSSL-verified Base64, hexadecimal, PEM, and DER reference cases, with no external test-library dependency. Hardware-provider qualification also includes portable contract, policy and negative-path tests that can run without physical hardware; native-device tests are reported separately and require the corresponding provider and device.

---

### QSCCAVP

The CAVP/ACVP-oriented local conformance test suite. It exercises applicable QSC primitives against published or obtained reference vectors and prepares for official algorithm validation workflows. Access to the NIST ACVP service and formal validation remain subject to authorization and completion of the required process.

**Algorithm coverage and target standards:**

| Category | Algorithms | Standard |
|---|---|---|
| Hash & XOF Functions | SHA2-256, SHA2-512, SHA3-256, SHA3-512, SHAKE-128, SHAKE-256, cSHAKE, KMAC | FIPS-180-4, FIPS-202 |
| MAC Functions | HMAC-SHA2-256, HMAC-SHA2-512, GMAC | FIPS-198-1 |
| Symmetric Cipher (AES) | CBC, CTR, ECB, GCM modes | FIPS-197, SP 800-38A/D |
| Key Encapsulation | ML-KEM (Kyber) | FIPS-203 (ACVP vectors) |
| Digital Signatures | ML-DSA (Dilithium), SLH-DSA (SPHINCS+) | FIPS-204, FIPS-205 (ACVP vectors) |

These local tests provide engineering evidence for regulated deployments but are **not** a NIST CAVP algorithm certificate or FIPS 140-3 module validation. Verify official status independently before making compliance claims.

---


## Commercial SDK and Language Wrappers

QSC is supported by a commercial integration SDK and language bindings for customers incorporating QSC into their own applications and products. **The QSC SDK and wrapper implementations are available to commercially licensed customers under the applicable QRCS commercial licensing agreement (QRCS-CASL).** These components, including their source code and binaries, **are not included in the public QSC research and evaluation distribution**.

The corresponding technical specifications are publicly available for architecture review, integration planning, and evaluation of the available interfaces:

| Component | Integration interface | Public specification |
|---|---|---|
| **QSC SDK (C)** | C developer examples, integration utilities, and the SDK qualification workbench. | [Specification (PDF)](docs/pdf/wrappers/qscsdk_specification.pdf) |
| **QSCABI** | Native C application binary interface for language bindings and external integrations. | [Specification (PDF)](docs/pdf/wrappers/qscabi_specification.pdf) |
| **QSCCPP** | C++17 library interface with typed cryptographic APIs and resource ownership. | [Specification (PDF)](docs/pdf/wrappers/qsccpp_specification.pdf) |
| **QSCCS** | C#/.NET wrapper with managed types, native interop, and resource management. | [Specification (PDF)](docs/pdf/wrappers/qsccs_specification.pdf) |
| **QSCRS** | Rust wrapper with a safe API over the native QSCABI boundary. | [Specification (PDF)](docs/pdf/wrappers/qscrs_specification.pdf) |
| **QSCPY** | Python wrapper using the native QSCABI interface. | [Specification (PDF)](docs/pdf/wrappers/qscpy_specification.pdf) |
| **QSCOSSL** | Selected OpenSSL-compatible APIs backed by QSC; not a complete OpenSSL replacement. | [Specification (PDF)](docs/pdf/wrappers/qscossl_specification.pdf) |

The published specifications describe interfaces and implementation requirements; access to these documents does not grant a license to the associated SDK or wrapper implementations. Commercial distributions and supported integration packages are provided under the applicable agreement with QRCS. For commercial licensing or access inquiries, contact **[licensing@qrcscorp.ca](mailto:licensing@qrcscorp.ca)**.

---

## Library Contents

### Asymmetric Cryptography

#### Key Encapsulation Mechanisms (KEM)

| Algorithm | Type | Standard |
|---|---|---|
| **ML-KEM** (Kyber-512/768/1024) | Module-LWE based KEM | NIST FIPS 203; Kyber-1280 is a separate experimental, nonstandard profile |
| **Classic McEliece** | Niederreiter dual-form code-based KEM | NIST PQC Round 3 |
| **HQC** | Quasi-cyclic code-based KEM | NIST PQC Round 4 |
| **ECDH** (P-256 / P-384 / P-521) | NIST prime-curve ECDH key agreement; constant-time scalar multiplication; public-key validation per SP 800-56A | NIST SP 800-56A, FIPS 186-5 |
| **EdDH** (X25519 / X448) | Edwards-curve Diffie-Hellman; Curve25519 (`QSC_EDDH_S1EC25519`) and Goldilocks (`QSC_EDDH_S3EC448`) | RFC 7748 |

#### Digital Signature Schemes

| Algorithm | Type | Standard / Reference |
|---|---|---|
| **ML-DSA** (Dilithium) | Module-lattice based signatures | NIST FIPS-204 |
| **SLH-DSA** (SPHINCS+) | Stateless hash-based signatures; SHAKE-128s/128f, SHAKE-192s/192f, SHAKE-256s/256f | NIST FIPS 205 |
| **Falcon** | NTRU lattice-based compact signatures | NIST PQC Round 3 |
| **ECDSA** (P-256 / P-384 / P-521) | Elliptic curve signatures over NIST P-256, P-384, and P-521; RFC 6979 deterministic nonce; interoperable with TLS 1.3 and public CA certificates | FIPS 186-5, RFC 6979, RFC 8422 |
| **EdDSA** (Ed25519 / Ed448) | Edwards-curve digital signatures; Ed25519 and Ed448-Goldilocks parameter sets selectable at compile time (`QSC_EDDSA_S1EC25519` / `QSC_EDDSA_S3EC448`) | RFC 8032 |

---

### TLS 1.3 Protocol Stack

QSC includes a complete TLS 1.3 implementation conforming to RFC 8446, built entirely on the QSC cryptographic core with no dependency on OpenSSL or any other external TLS library. The stack is designed specifically to support hybrid post-quantum key exchange, combining classical ECDH with ML-KEM encapsulation in a single handshake flight. It integrates directly with the QSC X.509 certificate infrastructure, key schedule, and AEAD record layer, and exposes a clean engine interface that is independent of any particular socket or I/O framework.

#### Protocol Coverage

The complete RFC 8446 protocol surface is implemented:

- **1-RTT handshake** - certificate-authenticated client and server paths; full state machine from ClientHello through application data
- **Mutual TLS (mTLS)** - server-initiated CertificateRequest; client certificate presentation, validation, and authorization callback policy
- **PSK resumption** - NewSessionTicket emission and consumption; binder computation; 1-RTT and 0-RTT policy controls
- **HelloRetryRequest** - server-initiated group renegotiation with transcript message_hash transform per RFC 8446 §4.4.1; enforced one-HRR-per-handshake limit
- **ALPN** - application-layer protocol negotiation with ordered protocol lists, strict vector decoding, selected-protocol inspection, and optional policy enforcement
- **SNI and multi-certificate selection** - server_name extension processing and hostname-driven local certificate selection, including default-certificate fallback policy
- **Post-handshake KeyUpdate** - both `update_not_requested` and `update_requested` flows; reciprocal update is mandatory when requested (RFC 8446 §4.6.3)
- **Post-handshake NewSessionTicket** - server emission and client consumption with per-ticket PSK derivation from `resumption_master_secret`
- **Peer inspection** - negotiated cipher suite, named group, signature scheme, selected ALPN, peer-certificate summary, and structured verification-result reporting
- **Socket policy** - receive, send, connect, handshake, and idle timeout controls; socket buffer policy; no-delay, keep-alive, reuse-address, dual-stack, and blocking-mode controls
- **Framed messages** - length-prefixed message helpers layered over TLS application data with deterministic bounds checking
- **Closure and cleanup** - encrypted `close_notify` alert construction and dispatch, idempotent listener close, concurrent server stop cleanup, and worker state reset
- **Compatibility** - ChangeCipherSpec pass-through for middlebox compatibility

#### Cipher Suites

| Identifier | IANA Value | Record AEAD | Hash |
|---|---|---|---|
| `TLS_AES_128_GCM_SHA256` | 0x1301 | AES-128-GCM | SHA-256 |
| `TLS_AES_256_GCM_SHA384` | 0x1302 | AES-256-GCM | SHA-384 |
| `TLS_CHACHA20_POLY1305_SHA256` | 0x1303 | ChaCha20-Poly1305 | SHA-256 |

#### Named Groups and Hybrid Key Exchange

The group layer abstracts classical, pure-KEM, and hybrid named groups behind a uniform descriptor and key-exchange interface. Hybrid groups use the component key-share and shared-secret ordering required by their corresponding IETF TLS profiles. All key-share buffer sizes are enforced at compile time via static assertions in `tlslimits.h`.

| Group | IANA | Classical | PQC Component | Availability |
|---|---:|---|---|---|
| secp256r1 | 0x0017 | P-256 ECDH | - | `QSC_ECDH_S1P256` |
| secp384r1 | 0x0018 | P-384 ECDH | - | enabled profile |
| x25519 | 0x001D | X25519 | - | enabled profile |
| x448 | 0x001E | X448 | - | enabled profile |
| ML-KEM-512 | 0x0200 | - | ML-KEM-512 | `QSC_KYBER_S1K2P512` |
| ML-KEM-768 | 0x0201 | - | ML-KEM-768 | `QSC_KYBER_S3K3P768` |
| ML-KEM-1024 | 0x0202 | - | ML-KEM-1024 | `QSC_KYBER_S5K4P1024` |
| X25519MLKEM768 | 0x11EC | X25519 | ML-KEM-768 | ML-KEM-768 profile |
| SecP256r1MLKEM768 | 0x11EB | P-256 ECDH | ML-KEM-768 | ML-KEM-768 profile plus P-256 ECDH |
| SecP384r1MLKEM1024 | 0x11ED | P-384 ECDH | ML-KEM-1024 | ML-KEM-1024 profile |

#### Signature Schemes

| Scheme | IANA | Standard |
|---|---|---|
| `ecdsa_secp256r1_sha256` | 0x0403 | FIPS 186-5 |
| `ecdsa_secp384r1_sha384` | 0x0503 | FIPS 186-5 |
| `ed25519` | 0x0807 | RFC 8032 |
| ML-DSA-44 | 0x0904 | NIST FIPS-204 |
| ML-DSA-65 | 0x0905 | NIST FIPS-204 |
| ML-DSA-87 | 0x0906 | NIST FIPS-204 |

#### TLS Module Map

| Module | Header(s) | Description |
|---|---|---|
| **Type Definitions** | `tlstypes.h` | All TLS 1.3 enumerations: cipher suites, named groups, signature schemes, handshake types, alert descriptions, content types, PSK exchange modes |
| **Protocol Constants** | `tlsdefs.h` | Fixed TLS protocol constants and HKDF label strings (version fields, record header sizes, AEAD tag/nonce sizes, HKDF label prefixes) |
| **Protocol Limits** | `tlslimits.h` | Maximum sizes and protocol-enforced field bounds; compile-time static assertions enforce all buffer capacity invariants |
| **Error Codes** | `tlserrors.*` | TLS-layer error enumeration and description helpers |
| **Alert Protocol** | `tlsalert.*` | Alert message encoding, decoding, and encrypted delivery; full RFC 8446 alert description set |
| **Record Layer** | `tlsrecord.*` | TLS record framing; plaintext and AEAD-protected TLSCiphertext encoding; constant-time inner content-type scanning; sequence counter management with pre-encryption overflow enforcement |
| **Codec** | `tlscodec.*` | Bounds-checked read/write helpers (u8, u16, u24, u32, bytes, vector8, vector16); no direct array indexing without prior length validation |
| **I/O Adapter** | `tlsio.*` | Blocking-socket adapter (qsc_tls_io_connection) binding a TLS engine to a QSC socket; handshake drive loop with maximum round-trip limit; send, receive, and shutdown |
| **Named Groups** | `tlsgroups.*` | NamedGroup descriptor table; keypair generation and shared-secret derivation for all classical, pure-KEM, and hybrid groups; compile-time size validation |
| **Signature Algorithms** | `tlssigalgs.*` | SignatureScheme registry; maps TLS algorithm identifiers to QSC ECDSA, Ed25519, and ML-DSA signing backends |
| **Extensions** | `tlsextensions.*` | Encode and decode for TLS 1.3 extensions: supported_versions, key_share (client offer and server response), supported_groups, signature_algorithms, signature_algorithms_cert where enabled, server_name (SNI), application_layer_protocol_negotiation (ALPN), pre_shared_key, psk_key_exchange_modes, early_data, and NewSessionTicket early_data |
| **Key Schedule** | `tlskeyschedule.*` | Complete RFC 8446 §7.1 HKDF key schedule: HKDF-Extract and HKDF-Expand-Label; Derive-Secret for all epochs; traffic key and IV derivation; Finished MAC computation and constant-time verification; binder key derivation and PSK binder computation; KeyUpdate traffic-secret rotation; CertificateVerify input construction; resumption PSK derivation |
| **Transcript Hash** | `tlstranscript.*` | Running SHA-256, SHA-384, or SHA-512 transcript hash; snapshot without disturbing running state; HelloRetryRequest message_hash transform (RFC 8446 §4.4.1); secure erasure of cloned hash state |
| **Handshake Messages** | `tlshandshake.*` | Encode and decode helpers for all RFC 8446 handshake message body types: ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateRequest, CertificateVerify, Finished, KeyUpdate, NewSessionTicket, EndOfEarlyData |
| **Session Resumption** | `tlssession.*` | Session ticket structure (qsc_tls_session_ticket); ticket serialization and deserialization; per-ticket PSK derivation from resumption_master_secret and ticket nonce |
| **Certificate Layer** | `tlscert.*` | TLS certificate chain decoding from Certificate messages; presentation to caller-supplied chain validation callback; leaf certificate tracking for CertificateVerify |
| **Certificate X.509 Bridge** | `tlscertx509.*` | Connects the TLS certificate layer to the QSC X.509 infrastructure for DER parsing, chain verification, hostname matching, and revocation checks |
| **Signature Binding** | `tlssignerdefault.*` | Default signer trampolines connecting qsc_tls_certificate_interface to QSC ECDSA, Ed25519, and ML-DSA signing APIs; verifycertificateverify callback is mandatory |
| **ECDSA DER Helper** | `tlsecdsader.*` | ECDSA signature DER encode/decode helpers used by the TLS signature scheme layer |
| **TLS Engine** | `tlsengine.*` | Unified client/server connection handle (qsc_tls_connection); handshake drive; application data encrypt/decrypt; post-handshake dispatch (KeyUpdate, NewSessionTicket); session ticket emission and consumption; close_notify; full keying-material zeroization on dispose |
| **TLS Client** | `tlsclient.*` | Client handshake state machine: ClientHello emission; ServerHello supported_versions verification; HelloRetryRequest processing; EncryptedExtensions, Certificate, CertificateVerify, and Finished processing; PSK binder computation; early-data key installation; client Finished emission; application-key installation |
| **TLS Server** | `tlsserver.*` | Server handshake state machine: ClientHello parsing with supported_versions validation; ServerHello and full server flight emission; HelloRetryRequest emission; SNI certificate selection; client certificate handling (mTLS); authorization callback processing; PSK lookup callback interface; early-data acceptance; NewSessionTicket emission |
| **TLS Socket API** | `tlssocket.*` | Blocking socket integration, connection/listener wrappers, socket option propagation, timeout policy, selected ALPN accessors, peer-info accessors, framed-message helpers, and concurrent shutdown cleanup |
| **Alert and State Types** | `tlsstate.h` | Internal state structures: qsc_tls_record_state, qsc_tls_transcript_state, qsc_tls_key_schedule_state, qsc_tls_peer_capabilities, qsc_tls_local_certificate_config |

#### Security Properties

- **Hybrid post-quantum forward secrecy** - the DHE input to HKDF-Extract is the concatenation of the ECDH shared secret and the ML-KEM shared secret; an attacker must break both primitives to recover session keys
- **Version downgrade protection** - the client verifies that `supported_versions` is present in ServerHello and that the selected version is exactly TLS 1.3 (0x0304); absence or a mismatched version causes immediate rejection with `missing_extension` or `illegal_parameter`
- **Unknown extension rejection** - any extension present in ServerHello that was not offered in ClientHello is rejected with `unsupported_extension` per RFC 8446 §4.2
- **Constant-time Finished verification** - the Finished MAC is verified using `qsc_intutils_verify`, which XOR-accumulates all bytes without early exit
- **Constant-time content-type scanning** - the inner content-type backward byte scan uses mask-select operations with no data-dependent branches
- **Sequence exhaustion enforcement** - the 64-bit record sequence counter is checked for UINT64_MAX exhaustion before any AEAD operation; no record is ever processed under an exhausted nonce space (RFC 8446 §5.5)
- **Mandatory CertificateVerify callback** - the engine returns `internal_error` if `verifycertificateverify` is not configured; the handshake cannot complete without server authentication
- **Certificate-bound signature selection** - the server selects a TLS signature scheme only when it is build-supported, CertificateVerify-capable, and compatible with the active local certificate identity
- **TLS certificate-purpose enforcement** - TLS server and client leaf certificates are rejected when BasicConstraints, KeyUsage, ExtendedKeyUsage, SAN, hostname, validity, or critical-extension policy does not satisfy the configured purpose
- **Structured verification reporting** - peer certificate, hostname, chain, X.509 wrapper, TLS status, and alert mappings are retained for inspection after success or failure
- **Secure erasure** - all traffic keys, transcript states, shared secrets, and handshake buffers are cleared with `qsc_memutils_secure_erase` at disposal; key material is erased before overwrite on epoch transitions

---

### X.509 Certificate Infrastructure

QSC includes a complete X.509 PKI layer covering the full certificate lifecycle: DER parsing, semantic verification, certificate and CRL generation, PKCS#10 certificate signing requests, OCSP response validation, PKCS#12 bundle handling, and trust store management. The implementation is built on a strict DER/BER decoder and a typed ASN.1 helper layer, and natively supports both classical ECDSA and post-quantum ML-DSA certificate profiles.

#### Correctness and Standards Compliance

The X.509 implementation includes standards-oriented checks derived from RFC 5280, X.690, and RFC 6125. Supported DER universal types receive additional canonical-encoding validation; comprehensive semantic conformance testing remains an ongoing qualification activity:

- **DER canonical checks** - DER decoding rejects indefinite-length encodings; supported universal-type checks include canonical BOOLEAN values and minimally encoded INTEGERs. Further universal-type semantic validation remains under qualification.
- **OID validation** - the first OID arc is validated to the range `{0, 1, 2}` per X.660, preventing crafted OIDs from bypassing algorithm dispatch.
- **Full 64-bit integer support** - ASN.1 INTEGER decoding correctly handles the 9-byte unsigned representation of values ≥ 2⁶³, covering the full range of CRL serial numbers and other large integer fields.
- **RFC 6125-compliant hostname verification** - the Subject CN fallback is suppressed whenever any Subject Alternative Name extension is present, regardless of entry type, as required by RFC 6125 §6.4.4.
- **Unicode name normalisation** - Distinguished Name attribute values are NFC-normalised before comparison, ensuring correct name matching for certificates issued with precomposed or decomposed Unicode characters (RFC 5280 §7.1).
- **pathLen overflow protection** - the BasicConstraints `pathLenConstraint` field is range-checked against `UINT32_MAX` before assignment, rejecting malformed encodings that would silently truncate the constraint value.
- **PQC-sized buffers** - DER and PEM decode buffers are sized to accommodate the largest current post-quantum certificate profile (ML-DSA-87: 2592-byte public key, 4627-byte signature), preventing silent decode failures for valid PQC certificates.

#### X.509 Module Map

| Module | Header | Description |
|---|---|---|
| **BER/DER Engine** | `encoding.h` | Full BER and DER encode/decode engine with correct definite-length constructed element handling; Base64, hex, and PEM encoding primitives |
| **ASN.1 Helper Layer** | `asn1.h` | Typed decoding helpers for sequences, sets, context-specific elements, OID validation (arcs 0–2 enforced), strict DER BOOLEAN, full 64-bit integer support, and bitstring extraction |
| **Object Identifier Registry** | `oid.h` | Stable OID registry with encoded values, dotted-decimal names, and descriptive strings for all algorithm and extension identifiers used by the X.509 layer |
| **Certificate Types** | `x509types.h` | Normalised in-memory structures for all X.509 objects: `qsc_x509_certificate`, `qsc_x509_name`, `qsc_x509_validity`, `qsc_x509_subject_public_key_info`, extension records, and associated enumerations; buffer constants sized for ML-DSA-87 |
| **Certificate Parser** | `x509cert.h` | DER-encoded X.509 certificate decoder; populates `qsc_x509_certificate` and records the raw TBSCertificate span for signature verification without re-serialisation |
| **Certificate Builder** | `x509certwrite.h` | X.509 v3 certificate builder and signing interface; constructs TBSCertificate fields, attaches extensions, signs with a caller-supplied private key, and produces DER or PEM output |
| **Distinguished Name** | `x509name.h` | Issuer/subject Name parsing; decodes relative distinguished name sequences into typed attribute lists; handles multi-valued RDNs; RFC 5280 §7.1 canonical comparison with Unicode NFC normalisation |
| **Validity / Time** | `x509time.h` | Decodes ASN.1 UTCTime and GeneralizedTime into normalised `qsc_x509_time` structures; provides validity interval comparison following RFC 5280 |
| **SubjectPublicKeyInfo** | `x509spki.h` | Decodes SubjectPublicKeyInfo for ECDSA (P-256, P-384, P-521), ML-DSA (44/65/87), and ML-KEM (512/768/1024) key types; validates public key sizes against expected PQC parameter set sizes |
| **Signature Algorithm** | `x509sig.h` | Decodes certificate signature AlgorithmIdentifiers for ECDSA and ML-DSA profiles; unpacks ECDSA DER SEQUENCE(INTEGER, INTEGER) signatures; validates ML-DSA signature length against the active parameter set |
| **Extensions** | `x509ext.h` | Decodes and queries all standard certificate extensions including BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier, SubjectAltName, IssuerAltName, CRLDistributionPoints, AuthorityInfoAccess, SubjectInfoAccess, and CertificatePolicies |
| **Certificate Verification** | `x509verify.h` | Semantic verification layer: algorithm consistency; validity intervals; issuer–subject name linkage; BasicConstraints and KeyUsage for CAs; KEM-key/CA-flag conflict detection; path length enforcement; duplicate extension detection; RFC 6125-compliant hostname and IP matching; critical extension enforcement; revocation integration |
| **QSC Verification Adapter** | `x509sigver.h` | Binds the X.509 verification layer to QSC's ECDSA (P-256/P-384/P-521) and ML-DSA (44/65/87) signature APIs |
| **Hostname / IP Matching** | `x509host.h` | RFC 6125-compliant DNS name matching with wildcard support and IDNA guard; IPv4 and IPv6 address matching against SubjectAltName IP entries; CN fallback suppressed when any SAN extension is present |
| **Certificate Signing Request** | `x509csr.h` | PKCS#10 CSR encoding, decoding, and verification; constructs certification requests from a SubjectPublicKeyInfo and Distinguished Name |
| **Certificate Revocation List** | `x509crl.h` | X.509 CRL parsing, entry lookup, and signature verification; decodes v1 and v2 CRLs including cRLNumber, deltaCRLIndicator, issuingDistributionPoint, and per-entry reasonCode and invalidityDate extensions |
| **CRL Builder** | `x509crlwrite.h` | X.509 CRL builder, signing, and PEM encoding; constructs TBSCertList fields and adds revocation entries with optional reason codes |
| **OCSP** | `x509ocsp.h` | OCSP response parsing and online certificate status validation; decodes BasicOCSPResponse, verifies the responder signature, and maps the result to a `qsc_x509_revocation_status` value |
| **Revocation Policy** | `x509rev.h` | Unified revocation policy interface integrating CRL and OCSP checking; supports `REQUIRE_VALID_CRL`, `BEST_EFFORT`, and `DISABLED` revocation modes |
| **Revocation Extensions** | `x509revext.h` | Extended revocation helpers for delta-CRL application and stapled OCSP verification |
| **Authority Info Access** | `x509aia.h` | Decodes and queries the AuthorityInfoAccess and SubjectInfoAccess extensions; extracts OCSP responder URIs and CA Issuers URIs |
| **Trust Store** | `x509store.h` | Trust-anchor store and certificate chain construction; manages `qsc_x509_trust_anchor` records; provides chain anchoring, self-signed detection, and anchor lookup |
| **Private Key** | `x509key.h` | Private key decoding, size validation, and certificate-key matching for PKCS#8 OneAsymmetricKey and SEC 1 ECPrivateKey structures |
| **Key Serialisation** | `x509keywrite.h` | Private key encoding and PEM conversion; serialises ECDSA and ML-DSA private keys to PKCS#8 DER or SEC 1 DER |
| **PKCS#12** | `x509pkcs12.h` | PKCS#12 bundle parsing and encrypted private-key decryption; decodes PFX structures using AES-256-CBC or 3DES |
| **PEM Codec** | `x509pem.h` | PEM encode/decode for certificates, CRLs, CSRs, PKCS#8 private keys, SEC 1 EC keys, and ML-DSA/ML-KEM key types; supports multi-certificate PEM bundles |
| **DER Write Primitives** | `x509write.h` | Low-level ASN.1 DER writing helpers for primitive values, composite objects, SPKI structures, and standard extension payloads |
| **High-Level Wrapper** | `x509wrap.h` | Convenience wrapper exposing the most common X.509 operations through a simplified API surface |

#### Supported Certificate Signature Profiles

| Profile | Signature OID | Public Key Type | Parameter |
|---|---|---|---|
| `ecdsa-with-SHA256` | `1.2.840.10045.4.3.2` | `id-ecPublicKey` | `prime256v1` (NIST P-256) |
| `ecdsa-with-SHA384` | `1.2.840.10045.4.3.3` | `id-ecPublicKey` | `secp384r1` (NIST P-384) |
| `ecdsa-with-SHA512` | `1.2.840.10045.4.3.4` | `id-ecPublicKey` | `secp521r1` (NIST P-521) |
| `id-ML-DSA-44` | `2.16.840.1.101.3.4.3.17` | `id-ML-DSA-44` | ML-DSA parameter set 44 |
| `id-ML-DSA-65` | `2.16.840.1.101.3.4.3.18` | `id-ML-DSA-65` | ML-DSA parameter set 65 |
| `id-ML-DSA-87` | `2.16.840.1.101.3.4.3.19` | `id-ML-DSA-87` | ML-DSA parameter set 87 |

---

### Hardware Security and Key Providers

The optional hardware integration uses the common `hwprovider.h` / `hwtypes.h` provider contract. It models capability discovery, protected-key lookup/generation, usage policy, custody and export restrictions, transient key-handle lifetime, signing, key agreement where supported, public-key retrieval, provider RNG, and device-specific attestation evidence. The provider ABI is versioned with `QSC_HW_ABI_VERSION` (independent of the QSC release number). Applications must verify backend capabilities and explicitly request non-exportable custody when required.

| Interface | Headers / modules | Scope and prerequisites |
|---|---|---|
| **Provider facade** | `hwprovider.h`, `hwprovider.c`, `hwtypes.h` | Versioned, backend-independent callback interface; no mandatory vendor runtime |
| **PKCS#11 / Cryptoki** | `hwpkcs11.h`, `p11loader.c`, `p11session.c`, `p11keys.c`, `p11sign.c`, `p11agree.c` | Selective HSM/token module loading; external Cryptoki module and compatible development interface required |
| **Windows TPM / NCrypt** | `hwncrypt.h`, `hwncrypt.c` | Microsoft Platform Crypto Provider; protected ECDSA key operations; physical TPM access must be confirmed |
| **Linux TPM 2.0** | `hwtpm.h`, `hwtpm.c`, `hwtpmquote.h` | TPM2-TSS ESAPI/TCTI option, pre-provisioned persistent identities, bounded quote verification; no TPM provisioning by QSC |
| **Arm PSA Crypto / TF-M** | `hwpsa.h`, `hwpsanative.h` | OEM bridge or selected native PSA client; trusted execution and key-custody properties require platform evidence |
| **Microchip ATECC608** | `hwatecc.h` | Device-bound P-256 identity and signing with an OEM-supplied CryptoAuthLib/HAL bridge |
| **NXP SE050/SE05x** | `hwse050.h` | SE05x token policy preflight through an OEM-installed Plug & Trust PKCS#11 module |
| **Apple / Android** | `hwplatform.h` | Apple Secure Enclave and Android Keystore/StrongBox bridges, subject to platform capabilities |
| **TLS 1.3 / X.509 binding** | `hwpkcs11tls.h`, `hwncrypttls.h` | CertificateVerify ECDSA signing and X.509/PKCS#10 signing with protected keys; no private-key export required |

#### Hardware Configuration and Security Boundaries

The public C interfaces are guarded by `QSC_HARDWARE_ENABLED` and the relevant backend feature definitions: `QSC_HARDWARE_PKCS11_ENABLED`, `QSC_HARDWARE_NCRYPT_ENABLED`, `QSC_HARDWARE_TPM_ENABLED`, `QSC_HARDWARE_PSA_ENABLED`, `QSC_HARDWARE_ATECC_ENABLED`, `QSC_HARDWARE_SE050_ENABLED`, and `QSC_HARDWARE_PLATFORM_ENABLED`. Native Linux TPM2-TSS and native PSA implementations have additional opt-in controls (`QSC_TPM2_TSS_ENABLED` and `QSC_HARDWARE_PSA_NATIVE_ENABLED`). These are **C preprocessor feature guards**, not necessarily names of CMake cache options; use the hardware options exposed by the selected CMake integration.

- **Key custody:** A reported hardware capability is not proof of non-exportability or physical hardware provenance. Keys and policies must be checked against the selected device, middleware, firmware, and operating-system configuration.
- **Attestation:** Evidence retrieval and verification are separate operations; a successful API call must not be represented as a trusted-device attestation without independent trust-chain, nonce, and policy checks.
- **Algorithm availability:** Supported operations differ by backend; software ML-DSA/ML-KEM support does not imply those algorithms are natively available in an HSM or TPM.
- **Dependencies and threads:** The software-only core remains independent of vendor SDKs. Selected native backends may require vendor packages, and provider close/release must be synchronized with concurrent operations according to each interface contract.
- **Qualification:** Portable and simulator-backed tests are not substitutes for physical-device qualification. No FIPS 140-3 certification or hardware security rating is claimed by the existence of these adapters.

---

### Symmetric Cryptography

#### Authenticated Encryption (AEAD)

| Algorithm | Description |
|---|---|
| **RCS** | Wide-block Rijndael stream cipher with KMAC authentication; 256 and 512-bit keys |
| **CSX-512** | ChaCha-derived stream cipher with 512-bit keys and KMAC authentication |
| **AES-GCM** | AES in GMAC Authentication mode; combines AES-CTR with GMAC |
| **AES-HBA** | AES in Hash-Based Authentication mode; combines AES-CTR with KMAC |

#### Classical Symmetric Ciphers

| Algorithm | Modes / Notes |
|---|---|
| **AES** | CBC, CTR, ECB, GCM, HBA; hardware-accelerated via AES-NI and SIMD |
| **ChaCha20-Poly1305** | Standard 256-bit ChaCha stream cipher with Poly1305 MAC |

#### Hash Functions

| Algorithm | Variants |
|---|---|
| **SHA3** | SHA3-256, SHA3-512 (FIPS-202) |
| **SHA2** | SHA2-256, SHA2-384, SHA2-512 (FIPS-180-4) |

#### Message Authentication Codes (MAC)

| Algorithm | Description |
|---|---|
| **KMAC** | Keccak-based MAC; FIPS-202 |
| **QMAC** | Proprietary GF(2²⁵⁶) polynomial MAC |
| **HMAC** | SHA2-256 and SHA2-512 variants; FIPS-198-1 |
| **Poly1305** | High-speed Bernstein MAC |
| **GMAC** | Galois/Counter Mode MAC |

#### Deterministic Random Bit Generators (DRBG)

| Identifier | Description |
|---|---|
| **CSG** (`csg.h`) | cSHAKE-based auto-seeding DRBG |
| **HCG** (`hcg.h`) | HMAC-based auto-seeding DRBG |
| **Secrand** (`secrand.h`) | Secure PRNG; produces random integers of every standard integer type |

#### Extensible Output & Key Derivation Functions (XOF / KDF)

| Identifier | Description |
|---|---|
| **SHAKE / cSHAKE** | FIPS-202 XOFs for key derivation and DRBG seeding |
| **SCB** (`scb.h`) | SHAKE Cost-Based KDF; memory-hard derivation with configurable cost |
| **HKDF** | SHA2-256 and SHA2-512 based extract-and-expand KDF |

#### Entropy Providers

| Identifier | Description |
|---|---|
| **ACP** (`acp.h`) | Auto Entropy Collection Provider; aggregates multiple entropy sources |
| **CSP** (`csp.h`) | OS-native cryptographic entropy provider |
| **RDP** (`rdp.h`) | Hardware entropy via RDRAND/RDSEED |
| **ETR** (`etr.h`) | External true-random source callback with SHAKE-512 output conditioning and explicit initialization/failure behavior |

---

### Proprietary Component Specifications

Each proprietary construction in QSC is accompanied by a full technical specification and an independent formal security analysis.

| Component | Description | Specification | Formal Analysis |
|---|---|---|---|
| **CSX** | ChaCha-based authenticated AEAD stream cipher; 512-bit keys, 64-bit integers, KMAC authentication | [Specification](https://qrcs-corp.github.io/QSC/pdf/csx_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/csx_formal.pdf) |
| **QMAC** | Wide-block GF(2²⁵⁶) polynomial MAC function | [Specification](https://qrcs-corp.github.io/QSC/pdf/qmac_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/qmac_formal.pdf) |
| **RCS** | Rijndael-based authenticated AEAD stream cipher with KMAC authentication | [Specification](https://qrcs-corp.github.io/QSC/pdf/rcs_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/rcs_formal.pdf) |
| **SCB** | SHAKE Cost-Based KDF; memory-hard passphrase derivation with configurable CPU and memory cost | [Specification](https://qrcs-corp.github.io/QSC/pdf/scb_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/scb_formal.pdf) |

---

### Utility and System Support

#### Encoding and Data Infrastructure

| Module | Description |
|---|---|
| `encoding.h` | BER/DER encoding and decoding; Base64, hex, and PEM handling; incremental Base64 interfaces, bounded decoding, and structural DER validation |
| `asn1.h` | ASN.1 typed helpers with overflow-checked DER sizing and zero-copy child-region extraction, used by X.509 |
| `oid.h` | OID registry and O(1) indexed identifier lookup for the X.509 and ASN.1 layers |

#### Memory, Data, and File Management

| Module | Description |
|---|---|
| `memutils.h` | Portable/SIMD memory operations: copy, clear, XOR, compare, secure erase, aligned allocation, and alignment-preserving resize |
| `arrayutils.h` | Byte array manipulation, bounded substring search, and checked numeric conversion helpers |
| `stringutils.h` | String handling, case conversion, and optimized byte/hexadecimal conversion |
| `intutils.h` | Endian conversion, bit manipulation, 64-bit popcount, checked hex decoding, and constant-time comparison via `qsc_intutils_verify` |
| `donna128.h` | Portable 128-bit integer arithmetic |
| `fileutils.h` | File I/O, bounded streaming copies, 64-bit offsets, safe positional writes, and path operations |
| `folderutils.h` | Directory creation, efficient listings, callback-driven enumeration, and management |
| `qsort.h` | Signed integer sorting using insertion sort, introsort, heapsort fallback, and 8-bit counting sort; not a constant-time secret-data sort |

#### Networking

| Module | Description |
|---|---|
| `socket.h`, `socketbase.h`, `socketflags.h` | Cross-platform TCP/IP primitives, vectored I/O, progress reporting, scalable readiness loops, and Windows IOCP interfaces |
| `netutils.h` | DNS resolution, bounded endpoint names, and improved network interface discovery |
| `socketclient.h` | Asynchronous TCP socket client |
| `socketserver.h` | Tracked asynchronous listener worker, callback-safe shutdown, and concurrent TCP connection acceptance |
| `ipinfo.h` | IPv4/IPv6 parsing, formatting, CIDR prefix membership, and local/remote IP information |

#### Concurrency and System Utilities

| Module | Description |
|---|---|
| `async.h` | Asynchronous execution, bounded task batching, detached threads, and synchronization helpers |
| `threadpool.h` | Legacy task management plus optional persistent-worker pools with bounded queues and graceful shutdown |
| `cpuidex.h` | CPU and OS-enabled SIMD detection, cache topology, and optional cached feature snapshots |
| `sysutils.h` | Bounded system identity, OS information, filesystem space, memory, and processor statistics |
| `timerex.h` | Monotonic elapsed-time measurement with microsecond/nanosecond interfaces |
| `timestamp.h` | UTC/local timestamps, checked date parsing, and optimized date formatting |
| `event.h` | Named callback registration and event-listener management with corrected synchronization and capacity growth |
| `consoleutils.h` | Bounded console input and buffered output/formatting helpers |
| `winutils.h` | Windows-specific platform utilities |

#### Data Structures

| Module | Description |
|---|---|
| `collection.h` | Generic keyed collection with geometric growth, optional indexed lookup, and bounded serialization |
| `list.h` | Dynamic generic list with geometric capacity, corrected sorting, and bounded serialization |
| `queue.h` | Aligned FIFO queue with checked push/pop and batched operations |

#### Self-Test

| Module | Description |
|---|---|
| `selftest.h` | Built-in integrity and performance verification routines for all cryptographic primitives |

---

## Architecture and Performance

QSC uses a dual implementation strategy for performance-critical algorithms, alongside profile-driven CMake source selection:

- **Reference path** - clean, portable C code with a C11 CMake baseline that provides a readable, auditable reference implementation.
- **SIMD-optimized path** - AVX, AVX2, and AVX-512 intrinsic implementations that activate automatically when the appropriate instruction set is enabled at compile time, providing substantial throughput improvements on modern x86-64 hardware.

The paths share public interfaces and are required to produce equivalent outputs. The selected implementation depends on compile-time feature macros, supported CPU instructions, and OS register-state support. AVX-512 is advantageous for some workloads, but the fastest configuration should be established by benchmarking on the intended hardware.

SIMD acceleration is applied selectively across AES (AES-NI), RCS, CSX, SHA-2, SHA-3/SHAKE/Keccak, ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), and memory utility operations. The modular CMake profiles independently control which families are compiled and linked; they do not imply that an instruction such as VAES or VPCLMULQDQ is present merely because AVX2 and AES-NI are enabled. Available scalar, AVX2, AVX-512, and ARM-specific paths are qualified separately where toolchains and hardware are available.

The NIST P-curve ECDSA and ECDH implementations use dedicated field and point arithmetic. Recent P-256 work includes optimized multiplication/reduction pipelines, signing-specific and key-agreement-specific execution paths, and blinding and secure-clear handling for ECDH. RFC 6979 deterministic nonce generation is used for ECDSA signing. P-384 and P-521 remain supported through their existing dedicated implementations; EdDH and EdDSA use arithmetic over their respective Edwards-curve fields.

The TLS 1.3 engine is designed for minimal allocation: the record layer heap-allocates only the TLSInnerPlaintext scratch buffer (one allocation per encrypt or decrypt call) and all other working state lives in caller-supplied structures. The engine does not retain persistent state between calls beyond what is stored in the `qsc_tls_connection` or its embedded client/server state. Each TLS layer component - key schedule, record layer, transcript hash, group descriptors, certificate binding, and I/O adapter - is independently testable without instantiating a full client/server handshake.

---

## Compilation

### Optimized CMake Builds

QSC has two separate CMake entry points:

- **Repository root (`CMakeLists.txt`):** The currently published, whole-library C11 build. It exposes `BUILD_SHARED_LIBS`, `QSC_ENABLE_TESTS`, `QSC_ENABLE_QSCTEST`, and `QSC_STRICT_WARNINGS`, but **not** `QSC_PROFILE`. Its library target is `qsc` (alias `qsc::qsc`).
- **Modular integration (`Source/QSC/CMakeLists.txt`):** The separately delivered profile-based integration with `Source/QSC/cmake/` source manifests, profile/hardware selection and `Source/QSC/CMakePresets.json`. It supports compact builds, generated capability metadata and the installed `QSC::QSC` target. An extended integration package also supports optional shared builds and selective TLS/X.509 inclusion.

**Repository status:** The modular files are not yet present on the inspected public `master` branch. Install the modular integration files before running the following commands; passing `-DQSC_PROFILE` to the root CMake configuration does not select a compact profile.

**Example: full static-library build** (from the repository root, after the modular CMake integration has been installed):

```sh
cmake -S Source/QSC -B build/qsc-full -DQSC_PROFILE=FULL -DCMAKE_BUILD_TYPE=Release
cmake --build build/qsc-full --config Release
cmake --install build/qsc-full --prefix /path/to/qsc-install
```

**Example: compact PQC level-5 build:**

```sh
cmake -S Source/QSC -B build/qsc-pqc5 -DQSC_PROFILE=PQC5 -DCMAKE_BUILD_TYPE=Release
cmake --build build/qsc-pqc5 --config Release
```

On Visual Studio, supply the desired CMake generator or use the included CMake presets; `--config Release` selects the Release configuration for multi-configuration generators. The `CMAKE_BUILD_TYPE` cache setting applies to single-configuration generators only.

| Profile | Intended use |
|---|---|
| `FULL` | Entire QSC library, including TLS 1.3 and X.509 |
| `CLASSICAL` | Classical cryptographic primitives and required utility modules |
| `PQC3` | Compact post-quantum security-class-3 cryptographic selection |
| `PQC5` | Compact post-quantum security-class-5 cryptographic selection |
| `HYBRID` | Combined classical and post-quantum cryptographic selection |
| `DEVICE_IDENTITY` | Smaller device-identity and protected-key integration use cases |
| `BOOT_VERIFY` | Compact signature-verification and boot-verification use cases |
| `EDGE_GATEWAY` | Field gateway cryptography, networking and selected protocol integration |
| `CLOUD_HSM` | Cloud services and HSM-centric key-custody integration |
| `INDUSTRIAL_OT` | Industrial control, operational technology and long-lifecycle endpoints |
| `ROBOT_EDGE` | Robotics, autonomous machinery and edge-device security |
| `AI_MODEL_TRUST` | AI model artifact signatures and trust/verification workflows |
| `VEHICLE_ECU` | Vehicle embedded-control-unit cryptography and secure updates |

The initial seven profiles and the expanded application profiles belong to different revisions of the modular integration. The **authoritative full list of supported profile identifiers and presets is the exact revision installed** (`cmake/QSCProfiles.cmake` and `CMakePresets.json`); avoid selecting a name not present in that version.

Compact profiles select their intended source sets instead of merely hiding APIs behind preprocessor switches. Profile selection is performed at configuration/build time and should be validated against the application's required symbols and parameter sets. The generated `QSCFeatures.h` and capability manifest describe the selected feature set; consumers use the exported `QSC::QSC` target and should not override generated feature definitions inconsistently.

When installed, downstream CMake consumers can use:

```cmake
find_package(QSC CONFIG REQUIRED)
target_link_libraries(my_application PRIVATE QSC::QSC)
```

#### CMake options and compiler flags

| Option or command | Scope | Meaning |
|---|---|---|
| `-DQSC_PROFILE=<profile>` | Modular integration | Select the named source/feature profile; `FULL` is the baseline example. Not supported by the legacy root build. |
| `-DBUILD_SHARED_LIBS=ON` or `OFF` | Root build; later modular revision | Select shared or static output where implemented. Static is the normal compact-distribution choice. |
| `-DCMAKE_BUILD_TYPE=Release` | Single-configuration generators | Choose optimization configuration for Makefiles/Ninja. |
| `cmake --build <build-dir> --config Release` | Multi-configuration generators | Select the Release configuration in Visual Studio and comparable generators. |
| `-DQSC_STRICT_WARNINGS=ON` or `OFF` | Root build | Enable or disable the root build's strict-warning option. |
| `-DQSC_ENABLE_TESTS=ON` or `OFF` | Root build | Include the optional `tests/` CMake project if it exists. |
| `-DQSC_ENABLE_QSCTEST=ON` or `OFF` | Root build | Build the QSCTest executable when its sources are present. |
| `-DCMAKE_C_FLAGS=...` | Both, when supported | Select target/compiler instruction options for a specific build. Do not enable instructions unsupported by the deployment CPU or OS. |
| `cmake --list-presets` | Modular integration | List the precise presets packaged with the selected revision. Run from `Source/QSC/` or provide `-S` as supported by the installed CMake version. |
| `cmake -LAH -N <build-dir>` | Configured build tree | Inspect the **actual** supported cache entries, including hardware/provider and compiler selections. |

For modular hardware selection, consult `cmake/QSCHardware.cmake`; source-level guards such as `QSC_HARDWARE_PKCS11_ENABLED` are **not** automatically CMake cache-option names. A backend's middleware and headers are required only when that backend is enabled. The portable software-only library has no mandatory vendor SDK dependency.

**Qualification boundary:** The November 6 technical dossier records native cryptographic tests across five platform/compiler groups and three security classes; it does **not** automatically qualify every CMake profile, shared-library packaging variant, optional ISA branch or physical hardware provider. The separate modular integration review ran primarily on Linux. The public root build and the modular build must be qualified and versioned independently.

### Prerequisites

| Tool | Requirement |
|---|---|
| **CMake** | 3.15 or newer |
| **Windows** | Visual Studio 2022 or newer (MSVC v143+) |
| **macOS** | Apple Clang via Xcode 14+, or LLVM/Clang via Homebrew |
| **Linux** | GCC 11+ or Clang 14+ |

---

### Windows (Visual Studio)

1. Extract the repository. The QSC library and QSCTest project should sit in adjacent folders at the same directory level.
2. Open the QSCTest project in Visual Studio.
3. Verify the include path is correct:  
   **Project Properties → C/C++ → General → Additional Include Directories**  
   The default path is `$(SolutionDir)..\QSC\QSC`. Update this if your layout differs.
4. Verify that **QSCTest → References** includes a reference to the QSC library project.
5. Set the SIMD instruction level consistently across **both** the QSC library and the QSCTest project in:  
   **Configuration Properties → C/C++ → All Options → Enable Enhanced Instruction Set**  
   Apply this to both Debug and Release configurations. Mismatched settings between the library and consumer projects will cause ABI alignment errors.
6. Right-click the QSC library project and select **Build**.
7. Right-click QSCTest and select **Set as Startup Project**, then run.

> ⚠️ **Important:** The QSC library and all projects that link against it must be compiled with the **same** SIMD instruction set level. Mixing instruction set settings between compilation units can cause struct alignment mismatches and undefined runtime behaviour.

---

### macOS / Linux (Eclipse)

Eclipse project files for both platforms are included in the distribution under `Eclipse/Ubuntu/` and `Eclipse/MacOS/`.

1. Copy the `.project`, `.cproject`, and `.settings` files from the appropriate platform subfolder into the folder containing the corresponding source files (e.g. `Eclipse/Ubuntu/QSC/` → the QSC source folder).
2. Repeat for the QSCTest project.
3. In Eclipse, create a new **C/C++ → Empty Project** using the exact folder name as the project name (`QSC`). Eclipse will load the settings automatically.
4. Repeat for QSCTest.

The default project configuration uses minimal flags with no enhanced instruction set. Extend with the appropriate flag set for your target hardware:

#### AVX
```
-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2
```

| Flag | Purpose |
|---|---|
| `-msse2` | Baseline SSE2 (required for x86-64) |
| `-mavx` | 256-bit floating-point and SIMD |
| `-maes` | AES-NI hardware acceleration |
| `-mpclmul` | Carry-less multiply (PCLMUL) |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | Bit Manipulation Instructions (PEXT/PDEP) |

#### AVX2
```
-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2
```

| Flag | Purpose |
|---|---|
| `-msse2` | Baseline SSE2 |
| `-mavx` | AVX baseline |
| `-mavx2` | 256-bit integer and FP SIMD |
| `-maes` | AES-NI |
| `-mpclmul` | PCLMUL (required for AES-GCM / GHASH) |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | BMI2 |

#### AVX-512
```
-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mpclmul -mrdrnd -mbmi2 -maes
```

| Flag | Purpose |
|---|---|
| `-msse2` | Baseline SSE2 |
| `-mavx` | AVX baseline |
| `-mavx2` | AVX2 baseline (explicit is safer even when implied) |
| `-mavx512f` | AVX-512 Foundation (512-bit registers) |
| `-mavx512bw` | AVX-512 Byte/Word integer instructions |
| `-mpclmul` | Baseline PCLMULQDQ carry-less multiplication |
| `-mvaes` / `-mvpclmulqdq` | Optional, **independent** VAES and VPCLMULQDQ instruction-set features: add only when supported by both CPU and compiler |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | BMI2 |
| `-maes` | AES-NI (128-bit rounds; complement to VAES) |

**CPU and compiler gating:** AVX2 with AES-NI does **not** imply VAES or VPCLMULQDQ. An optional accelerated build may add `-mvaes -mvpclmulqdq` only on suitable hardware and toolchains; Intel/AMD and MSVC compile-time feature detection differ. Keep portable fallback paths available and validate each deployed instruction set. These are compiler flags, not `QSC_PROFILE` values.

---

## Features at a Glance

| Feature | Details |
|---|---|
| **Post-Quantum Algorithms** | ML-KEM (FIPS 203), ML-DSA (FIPS 204), six SHAKE SLH-DSA profiles (FIPS 205), Falcon (Round 3), Classic McEliece, HQC (Round 4); experimental Kyber-1280 available separately |
| **Classical Algorithms** | AES, SHA-2/3, HMAC, ChaCha20-Poly1305, ECDH (P-256/P-384/P-521, X25519/X448), ECDSA (P-256/P-384/P-521), EdDSA (Ed25519/Ed448) |
| **Proprietary Constructions** | RCS, CSX, QMAC, SCB - each with formal security analysis |
| **X.509 / PKI Infrastructure** | Certificate lifecycle: DER/PEM parsing and generation, chain verification, CRL and OCSP revocation, PKCS#10 CSR, PKCS#12 bundles, trust store management; ECDSA and ML-DSA certificate profiles; RFC 5280, RFC 6125, and X.690-oriented validation |
| **TLS 1.3** | Complete RFC 8446 implementation: 1-RTT, mTLS, PSK resumption, HelloRetryRequest, KeyUpdate, NewSessionTicket, ALPN, SNI/multi-certificate selection, peer-info inspection, verification-result reporting, socket timeout policy, framed-message helpers, and concurrent shutdown cleanup; no external TLS dependencies |
| **Hybrid Post-Quantum Key Exchange** | ECDH + ML-KEM combined in a single TLS handshake flight; implemented IETF-aligned hybrid groups are X25519MLKEM768, SecP256r1MLKEM768, and SecP384r1MLKEM1024 |
| **SIMD Acceleration** | Portable scalar plus supported AVX, AVX2, AVX-512, AES-NI and ARM implementations, selected at build time |
| **Optimized CMake** | Modular profile-based source selection with seven original profiles and expanded edge, cloud-HSM, industrial, robotics, AI-model and vehicle profiles; static output by default, optional shared builds in the later integration package; generated feature metadata and exported `QSC::QSC` target |
| **Hardware-Key Integration** | Optional PKCS#11/HSM, NCrypt/TPM, TPM2-TSS, Arm PSA/TF-M, ATECC608, SE050 and Apple/Android keystore providers; protected signing bridges for TLS/X.509 |
| **External Entropy** | Opt-in ETR true-random callback interface with SHAKE-512 conditioning |
| **Coding Discipline** | MISRA-adjacent QRCS secure C coding standard; formal MISRA compliance not claimed |
| **Testing** | Known-answer and vector tests, randomized/stress and interoperability tests, and source-pinned offline qualification: 15/15 native configurations and two passing consolidated evidence gates, each with documented coverage boundaries; see the technical qualification report |
| **Platforms** | Windows (MSVC), Linux (GCC), macOS (Clang) |
| **Language Interop** | Public native C interface; commercially licensed C SDK, C ABI, C++, C#, Rust, Python, and selected OpenSSL-compatible integration wrappers (see [Commercial SDK and Language Wrappers](#commercial-sdk-and-language-wrappers)) |
| **Self-Contained** | Software cryptographic core requires no external cryptographic runtime; optional selected hardware adapters may need vendor/platform middleware |

---

## Roadmap

- [x] Modular profile-based optimized CMake integration, with expanded application profiles, generated consumer metadata, installation/export and optional shared builds in the later review package
- [ ] Publish the modular CMake integration alongside the root build and qualify its installed profiles/presets on each supported platform
- [x] Optional hardware-provider facade, adapter interfaces and protected-key TLS/X.509 integration points
- [ ] Native physical-HSM/TPM/secure-element and multi-platform qualification of selected backends
- [ ] Windows/macOS/ARM and native MSVC qualification of the new modular CMake integration
- [ ] Continued intrinsics-first SIMD optimization and selective assembly where independently beneficial
- [x] TLS 1.3 *(complete - RFC 8446 compliant; 1-RTT, mTLS, PSK policy, HRR, KeyUpdate, NewSessionTicket, ALPN, SNI, peer-info, framed-message helpers, OpenSSL interoperability, and hybrid post-quantum groups)*
- [x] Expanded microbenchmark coverage for cryptographic primitives and peripheral utilities
- [ ] Publish matched performance results from qualified Windows, Linux, macOS, and ARM64 hardware
- [ ] Integration of emerging post-quantum research and forthcoming NIST standards

---

## License

### Investment Inquiries

QRCS is currently seeking a corporate investor for this technology. Parties interested in licensing or investment should contact us at **contact@qrcscorp.ca** or visit [qrcscorp.ca](https://www.qrcscorp.ca) for a full inventory of our products and services.

---

### Patent Notice

One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.

---

### License and Use Notice (2025–2026)

This repository contains cryptographic reference implementations, test code, and supporting materials published by **Quantum Resistant Cryptographic Solutions Corporation (QRCS)** for the purposes of public review, cryptographic analysis, interoperability testing, and evaluation.

All source code and materials in this repository are provided under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026**, unless explicitly stated otherwise.

This license permits:
- Public access for non-commercial research, evaluation, and testing only.

This license **does not** permit:
- Production deployment or operational use.
- Incorporation into any commercial product or service without a separate written agreement executed with QRCS.

The public availability of this repository is intentional and is provided to support cryptographic transparency, independent security assessment, and compliance with applicable cryptographic publication and export regulations.

Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a separate commercial license and support agreement.

For licensing inquiries, supported implementations, or commercial use:  
📧 **licensing@qrcscorp.ca**

---

*Quantum Resistant Cryptographic Solutions Corporation - All rights reserved, 2026.*
