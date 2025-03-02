# QSC: Quantum Secure Cryptographic Solutions Library

**A compact, self-contained, and highly optimized post-quantum secure cryptographic library written in C.**

[View full documentation online](https://qrcs-corp.github.io/QSC/)


## Overview

QSC is designed to provide next-generation, post-quantum secure cryptographic primitives for applications requiring long-term security. Adhering to MISRA secure coding standards, the library is structured for clarity, ease of verification, and seamless integration into secure communications platforms. The code is well structured, thoroughly commented, and comes with an extensive testing platform covering every primitive contained in the library.


## Status

QSC is a compact and self-contained library written in C. It has been developed to meet MISRA secure coding standards and is designed to be easy to read, verify, and implement. The library incorporates next-generation asymmetric and symmetric primitives with a strong emphasis on true long-term security. It forms the basis for future integration efforts as a compact, high-security, post-quantum secure communications platform.

This implementation uses both a base reference code and optimized AVX/AVX2/AVX512 intrinsics for maximum performance. For best results, set your project properties to utilize the highest available SIMD instruction set supported by your CPU—AVX-512 instructions are fully supported and offer the best performance profile.


## Version

**Version:** 1.0.0.5L  
Tested on:  
- **Windows 10** (version 10.0.19042 using Visual Studio 16.10.2)  
- **Ubuntu Linux** (version 20.04 using Eclipse 2021-09 with GCC Ubuntu 9.3.0-17)  
- **macOS Big Sur** (version 11.5.2 using Eclipse 2021-09 with Apple Clang 12.0.5)

_All asymmetric ciphers and signature schemes have been updated to new FIPS standards for the winners, and NIST PQC Round 3 standards for last round contenders._

## Library Contents

### Asymmetric Cryptography

- **Key Encapsulation Mechanisms:**  
  - *McEliece:* Niederreiter dual form of the McEliece public key crypto-system.  
  - *Kyber:* Module-LWE based key encapsulation (updated to NIST FIPS-203 standards).  
  - *NTRU:* Asymmetric cipher implementation.  
  - *ECDH:* Elliptic Curve Diffie-Hellman key exchange.

- **Digital Signature Schemes:**  
  - *Sphincs+:* Post-quantum secure signature scheme (updated to NIST FIPS-205 standards).  
  - *Dilithium:* Lattice-based signature scheme (updated to NIST FIPS-204 standards).  
  - *Falcon:* NTRU-based signature scheme.  
  - *ECDSA (Ed25519):* Elliptic Curve Digital Signature Algorithm.

### Symmetric Cryptography

- **Symmetric Ciphers:**
  - *AES:* Supports modes such as CBC, CTR, HBA, and ECB.  
  - *RCS:* An authenticated AEAD stream cipher based on wide-block Rijndael and KMAC/QMAC. 
  - *CSX:* A ChaCha-based authenticated AEAD stream cipher using 64-bit integers, 512-bit keys, and KMAC/QMAC authentication.
  - *ChaChaPoly20:* ChaCha-based stream cipher. 

- **Hash Functions:**  
  - *SHA3* 256 and 512-bit variants.
  - *SHA2* 256 and 512-bit variants.

- **Message Authentication Codes:**  
  - *QMAC:* GMAC(2^256) variant.  
  - *KMAC:* Keccak-based MAC.  
  - *HMAC:* Based on SHA2.  
  - *Poly1305:* High-speed MAC generator.

- **DRBGs and PRNGs:**
  - **CSG (`csg.h`)**
    cSHAKE wrapped auto-seeding DRBG.
  - **HCG (`hcg.h`)**
    HMAC wrapped auto-seeding DRBG.
  - **SCB (`scb.h`)**
    SHAKE Cost Based KDF (uses memory thrashing and CPU cost mechanisms).
  - **Secrand (`secrand.h`)**
    Secure PRNG producing random integers of every type.
    
- **XOF and KDF Functions:**  
  - *SHAKE* and *cSHAKE* (for key derivation functions and DRBGs).  
  - *SCB (SHAKE Cost Based KDF):* For secure key derivation.
  - *HKDF SHA2-256 AND 512 bit variants

### Randomness and Entropy

- **Entropy Providers & PRNGs:**
  - **ACP (`acp.h`):**  
    Auto Entropy Collection Provider for gathering entropy.
  - **CSP (`csp.h`):**  
    The operating system entropy provider.
  - **RDRAND (`rdp.h`):**  
    Utilizes hardware-based random number generation.


### Utility Functions and System Support

#### Memory, Data, and File Management
- **Array and String Utilities:**  
  `arrayutils.h` and `stringutils.h` for managing character arrays and strings.
- **Memory Functions:**  
  `memutils.h` implements optimized memory operations using SIMD instructions.
- **Integer and Arithmetic:**  
  `intutils.h` and `donna128.h` provide high-precision arithmetic and integer manipulation.
- **File and Folder Utilities:**  
  `fileutils.h` and `folderutils.h` simplify file handling and directory management.

#### Networking
- **TCP/IP and Socket Utilities:**  
  A complete set of network functions provided in `netutils.h`, `socket.h`, `socketclient.h`, `socketserver.h`, `socketbase.h`, and `socketflags.h`.

#### Concurrency and System Utilities
- **Asynchronous Operations:**  
  Managed through `async.h` and `threadpool.h` for multi-threaded processing.
- **System and CPU Information:**  
  `cpuidex.h`, `sysutils.h`, and `ipinfo.h` for system statistics and CPU feature detection.
- **Timing and Events:**  
  `timerex.h`, `timestamp.h`, and `event.h` offer precise timing and event management.
- **Platform-Specific Utilities:**  
  `consoleutils.h` and `winutils.h` provide support for console applications and Windows environments.

#### Additional Utilities
- **Data Structures:**  
  Efficient keyed collections (`collection.h`), list (`list.h`), and queue (`queue.h`) management.
- **Encoding & Sorting:**  
  `encoding.h` for multiple encoding schemes and `qsort.h` for quicksort operations.
- **Self-Test Mechanisms:**  
  `selftest.h` contains routines to verify the integrity and performance of the cryptographic functions.

## Architecture and Performance

- **Reference Implementations:**  
  Clear and maintainable C code ensuring broad platform compatibility.
  
- **SIMD Optimizations:**  
  Critical algorithms use AVX, AVX2, and AVX512 intrinsics to leverage modern CPU capabilities, achieving superior performance.


## Supported Platforms

QSC has been thoroughly tested on:
- **Windows** (Visual Studio)
- **Ubuntu Linux** (GCC)
- **macOS** (Apple Clang)

## Features

- **Comprehensive Cryptography:**  
  Incorporates next-generation asymmetric and symmetric cryptographic primitives.
  
- **High Security:**  
  Emphasizes long-term security with post-quantum algorithms and robust key management.
  
- **Performance Optimized:**  
  Uses advanced SIMD intrinsics (AVX/AVX2/AVX512) for best performance.
  
- **Testing Platform:**  
  Contains extensive test functions for every primitive, ensuring correctness and performance.
  
- **System Utilities:**  
  Provides asynchronous threading, dual-stack networking, CPUID detection, and secure memory management.


## Roadmap

- Continued ASM/SIMD integration and optimization.
- Wrapper libraries for .NET, Java, and Rust.
- Development of a post-quantum TLS 1.3 implementation.
- Expansion of testing and benchmarking frameworks.
- Integration of emerging cryptographic research and standards.

## License

QRCS-PL Private License. See the included license file for details.  
Software is copyrighted, and some mechanisms are patent pending.  
Written by John G. Underhill under the QRCS-PL license. 
Redistribution or commercial use is not permitted without expressed written permission.  
_All rights reserved by QRCS Corp. 2025._

