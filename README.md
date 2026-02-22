# QSC: Quantum Secure Cryptographic Library Version 1.1  

[![Build](https://img.shields.io/github/actions/workflow/status/QRCS-CORP/QSC/build.yml?branch=master)](https://github.com/QRCS-CORP/QSC/actions/workflows/build.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/QRCS-CORP/QSC/codeql-analysis.yml?label=CodeQL&branch=master)](https://github.com/QRCS-CORP/QSC/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/qsc/badge)](https://www.codefactor.io/repository/github/qrcs-corp/qsc)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](https://github.com/QRCS-CORP/QSC/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/HKDS/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/QSC/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/QSC)](https://github.com/QRCS-CORP/QSC/releases/tag/2025-05-25)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/QSC.svg)](https://github.com/QRCS-CORP/QSC/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Communications&color=brightgreen)](#)

**A compact, self-contained, and highly optimized post-quantum secure cryptographic library written in C23.**

---

## Documentation

| Resource | Description |
|---|---|
| [QSC Help Documentation](https://qrcs-corp.github.io/QSC/) | Full API reference and usage guide |
| [QSC Technical Specification](https://qrcs-corp.github.io/QSC/pdf/qsc_specification.pdf) | Detailed algorithmic and design specification |
| [QSC Summary Document](https://qrcs-corp.github.io/QSC/pdf/qsc_summary.pdf) | High-level overview of the library |
| [QSC Integration Guide](https://qrcs-corp.github.io/QSC/pdf/qsc_integration.pdf) | Practical guide for embedding QSC into your project |
| [QSC Target Industries](https://qrcs-corp.github.io/QSC/pdf/qsc_library_for_critical_domains.pdf) | Application domains and deployment context |

### Proprietary Component Specifications

Each proprietary construction in QSC is accompanied by a full technical specification and an independent formal security analysis.

| Component | Description | Specification | Formal Analysis |
|---|---|---|---|
| **CSX** | ChaCha-based authenticated AEAD stream cipher; 512-bit keys, 64-bit integers, KMAC/QMAC authentication | [Specification](https://qrcs-corp.github.io/QSC/pdf/csx_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/csx_formal.pdf) |
| **QMAC** | Wide-block GF(2²⁵⁶) polynomial MAC function | [Specification](https://qrcs-corp.github.io/QSC/pdf/qmac_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/qmac_formal.pdf) |
| **RCS** | Rijndael-based authenticated AEAD stream cipher with KMAC/QMAC authentication | [Specification](https://qrcs-corp.github.io/QSC/pdf/rcs_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/rcs_formal.pdf) |
| **SCB** | SHAKE Cost-Based KDF; memory-hard passphrase derivation with configurable CPU and memory cost | [Specification](https://qrcs-corp.github.io/QSC/pdf/scb_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/scb_formal.pdf) |

---

## Overview

QSC is a production-grade cryptographic library built for environments that demand verifiable correctness, long-term quantum resistance, and high throughput. The library combines NIST-standardized post-quantum algorithms with classical primitives, proprietary high-security constructions, and SIMD-accelerated implementations — all within a single, dependency-free C23 codebase.

Key design goals:

- **Long-term security** — all asymmetric algorithms are post-quantum secure; proprietary constructions target 256-bit or greater security levels.
- **Standards compliance** — written to [MISRA C](https://misra.org.uk/) secure coding guidelines; asymmetric primitives updated to final FIPS-203, FIPS-204, and FIPS-205 standards.
- **Performance** — dual code paths: clean portable C reference implementations alongside AVX, AVX2, and AVX-512 intrinsic-optimized variants. Enable the highest instruction set supported by your target CPU for maximum throughput.
- **Auditability** — thoroughly commented, well-structured source with a comprehensive test suite covering known-answer tests, NIST CAVP/ACVP vectors, fuzzing, and stress testing across every primitive.
- **Portability** — compiles on Windows (MSVC), Linux (GCC), and macOS (Clang) with no external dependencies.

> **Version:** 1.0.0.6c  
> **Tested on:** Windows 10 / 11 / Server · Ubuntu Linux · macOS  
> _All asymmetric ciphers and signature schemes have been updated to the final NIST FIPS standards for standardized algorithms and to NIST PQC Round 3 specifications for remaining candidates._

---

## Projects

The distribution includes three companion projects alongside the QSC library, all available on the [QRCS-CORP/QSC project page](https://github.com/QRCS-CORP/QSC).

### QSCTest

The primary validation suite for the QSC library. QSCTest exercises every cryptographic primitive through a structured battery of tests designed to detect correctness regressions, implementation errors, and performance degradation.

**Test coverage includes:**

- **Known Answer Tests (KATs)** — output from every primitive is verified against pre-computed reference vectors.
- **NIST ACVP Vectors** — asymmetric and symmetric primitives verified against official NIST Automated Cryptographic Validation Program test vectors.
- **Fuzzing** — randomized input testing to detect edge-case failures and undefined behaviour.
- **Stress Testing** — extended load testing to surface resource leaks, state corruption, and threading issues.
- **Function Correctness** — round-trip and cross-function consistency checks (e.g., encrypt→decrypt, sign→verify).

Coverage spans the full library: asymmetric ciphers (ML-KEM, McEliece, ECDH), signature schemes (ML-DSA, SLH-DSA, ECDSA), symmetric ciphers (AES, RCS, CSX, ChaCha20-Poly1305), hash and XOF functions (SHA2, SHA3, SHAKE, cSHAKE), MAC functions (KMAC, QMAC, HMAC, Poly1305), DRBGs (CSG, HCG), entropy providers (ACP, CSP, RDP), and all utility modules.

---

### QSCCAVP

The NIST Cryptographic Algorithm Validation Program (CAVP) compliance suite. QSCCAVP runs the official CAVP and ACVP test vector sets against every applicable QSC component to verify conformance with federal standards.

**Validated components and standards:**

| Category | Algorithms | Standard |
|---|---|---|
| Hash & XOF Functions | SHA2-256, SHA2-512, SHA3-256, SHA3-512, SHAKE-128, SHAKE-256, cSHAKE, KMAC | FIPS-180-4, FIPS-202 |
| MAC Functions | HMAC-SHA2-256, HMAC-SHA2-512, GMAC | FIPS-198-1 |
| Symmetric Cipher (AES) | CBC, CTR, ECB, GCM modes | FIPS-197, SP 800-38A/D |
| Key Encapsulation | ML-KEM (Kyber) | FIPS-203 (ACVP vectors) |
| Digital Signatures | ML-DSA (Dilithium), SLH-DSA (SPHINCS+) | FIPS-204, FIPS-205 (ACVP vectors) |

QSCCAVP is the authoritative conformance reference for deployments in regulated environments such as government, defence, finance, and critical infrastructure.

---

### QSCNETCW

A managed C++ / C# .NET wrapper that exposes the full QSC API to .NET applications. QSCNETCW provides idiomatic .NET access to every core library component, enabling integration into C# services, enterprise applications, and Windows platform software without sacrificing the performance or security properties of the underlying C implementation.

**Wrapper coverage includes:**

- All asymmetric key encapsulation and digital signature primitives.
- All symmetric ciphers, hash functions, and MAC functions.
- DRBGs, entropy providers, and secure memory utilities.
- Full parity with the C API — no functionality is omitted in the wrapper layer.

The wrapper is written in managed C++ and compiled as a mixed-mode assembly, allowing direct P/Invoke-free consumption from any .NET language (C#, VB.NET, F#).

---

## Library Contents

### Asymmetric Cryptography

#### Key Encapsulation Mechanisms (KEM)

| Algorithm | Type | Standard |
|---|---|---|
| **ML-KEM** (Kyber) | Module-LWE based KEM | NIST FIPS-203 |
| **Classic McEliece** | Niederreiter dual-form code-based KEM | NIST PQC Round 3 |
| **ECDH** (X25519) | Elliptic Curve Diffie-Hellman | RFC 7748 |

#### Digital Signature Schemes

| Algorithm | Type | Standard |
|---|---|---|
| **ML-DSA** (Dilithium) | Module-lattice based signatures | NIST FIPS-204 |
| **SLH-DSA** (SPHINCS+) | Stateless hash-based signatures | NIST FIPS-205 |
| **ECDSA** (Ed25519) | Elliptic Curve Digital Signature | RFC 8032 |

---

### Symmetric Cryptography

#### Authenticated Encryption (AEAD)

| Algorithm | Description |
|---|---|
| **RCS** | Wide-block Rijndael stream cipher with KMAC/QMAC authentication; 256 and 512-bit keys |
| **CSX-512** | ChaCha-derived stream cipher with 512-bit keys and KMAC/QMAC authentication |
| **AES-GCM** | AES in GMAC Authentication mode; combines AES-CTR with GMAC |
| **AES-HBA** | AES in Hash-Based Authentication mode; combines AES-CTR with KMAC |

#### Classical Symmetric Ciphers

| Algorithm | Modes / Notes |
|---|---|
| **AES** | CBC, CTR, ECB, GCM, HBA, GCM; hardware-accelerated via AES-NI and SIMD |
| **ChaCha20-Poly1305** | Standard 256-bit ChaCha stream cipher with Poly1305 MAC |

#### Hash Functions

| Algorithm | Variants |
|---|---|
| **SHA3** | SHA3-256, SHA3-512 (FIPS-202) |
| **SHA2** | SHA2-256, SHA2-512 (FIPS-180-4) |

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

---

### Utility and System Support

#### Memory, Data, and File Management

| Module | Description |
|---|---|
| `memutils.h` | SIMD-optimized memory operations: copy, clear, XOR, compare, secure erase |
| `arrayutils.h` | Byte array manipulation and conversion utilities |
| `stringutils.h` | Safe string handling and conversion |
| `intutils.h` | Integer endian conversion, bit manipulation, and arithmetic |
| `donna128.h` | Portable 128-bit integer arithmetic |
| `fileutils.h` | File I/O, size, existence, and path operations |
| `folderutils.h` | Directory creation, enumeration, and management |
| `encoding.h` | Base64, hex, and other encoding schemes |
| `qsort.h` | Constant-time and standard quicksort implementations |

#### Networking

| Module | Description |
|---|---|
| `socket.h`, `socketbase.h`, `socketflags.h` | Cross-platform TCP/IP socket primitives |
| `netutils.h` | Network address resolution and interface utilities |
| `socketclient.h` | Asynchronous TCP socket client |
| `socketserver.h` | High-performance asynchronous TCP socket server |
| `ipinfo.h` | Local and remote IP information queries |

#### Concurrency and System Utilities

| Module | Description |
|---|---|
| `async.h` | Asynchronous task execution |
| `threadpool.h` | Managed thread pool for concurrent workloads |
| `cpuidex.h` | CPU feature detection (SIMD capability, cache topology) |
| `sysutils.h` | OS version, memory, and processor statistics |
| `timerex.h` | High-resolution performance timers |
| `timestamp.h` | UTC and local timestamp generation |
| `event.h` | Synchronisation event primitives |
| `consoleutils.h` | Console input/output and formatting helpers |
| `winutils.h` | Windows-specific platform utilities |

#### Data Structures

| Module | Description |
|---|---|
| `collection.h` | Keyed generic collection (dictionary/map) |
| `list.h` | Dynamic generic list |
| `queue.h` | Generic FIFO queue |

#### Self-Test

| Module | Description |
|---|---|
| `selftest.h` | Built-in integrity and performance verification routines for all cryptographic primitives |

---

## Architecture and Performance

QSC uses a dual implementation strategy for all performance-critical algorithms:

- **Reference path** — clean, portable C23 code that compiles on any conforming compiler and provides a readable, auditable baseline.
- **SIMD-optimized path** — AVX, AVX2, and AVX-512 intrinsic implementations that activate automatically when the appropriate instruction set is enabled at compile time, providing substantial throughput improvements on modern x86-64 hardware.

The two paths share identical interfaces and produce identical output; the compiler selects the appropriate implementation via preprocessor feature detection. For production deployments, enabling AVX-512 (where the target hardware supports it) yields the highest performance across all symmetric primitives, hash functions, and post-quantum algorithms.

SIMD acceleration is applied across: AES (AES-NI), RCS, CSX, SHA3/SHAKE/Keccak, ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), and all memory utility operations.

---

## Compilation

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
-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes
```

| Flag | Purpose |
|---|---|
| `-msse2` | Baseline SSE2 |
| `-mavx` | AVX baseline |
| `-mavx2` | AVX2 baseline (explicit is safer even when implied) |
| `-mavx512f` | AVX-512 Foundation (512-bit registers) |
| `-mavx512bw` | AVX-512 Byte/Word integer instructions |
| `-mvaes` | Vector-AES in 512-bit registers |
| `-mpclmul` | PCLMUL for GF(2ⁿ) operations |
| `-mrdrnd` | RDRAND hardware RNG |
| `-mbmi2` | BMI2 |
| `-maes` | AES-NI (128-bit rounds; complement to VAES) |

---

## Features at a Glance

| Feature | Details |
|---|---|
| **Post-Quantum Algorithms** | ML-KEM (FIPS-203), ML-DSA (FIPS-204), SLH-DSA (FIPS-205), Classic McEliece |
| **Classical Algorithms** | AES, SHA-2/3, HMAC, ChaCha20-Poly1305, ECDH (X25519), ECDSA (Ed25519) |
| **Proprietary Constructions** | RCS, CSX, QMAC, SCB — each with formal security analysis |
| **SIMD Acceleration** | AVX, AVX2, AVX-512, AES-NI, RDRAND across all major primitives |
| **Security Standard** | MISRA C compliant throughout |
| **Testing** | KAT, NIST ACVP/CAVP, fuzzing, and stress tests for every primitive |
| **Platforms** | Windows (MSVC), Linux (GCC), macOS (Clang) |
| **Language Interop** | C++, and .NET (C#/VB.NET/F#) via the QSCNETCW managed wrapper |
| **Self-Contained** | No external runtime dependencies |

---

## Roadmap

- [ ] Continued ASM and SIMD integration and optimization
- [ ] Java wrapper library
- [ ] Expanded benchmarking framework with cross-platform performance reporting
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

*Quantum Resistant Cryptographic Solutions Corporation — All rights reserved, 2026.*