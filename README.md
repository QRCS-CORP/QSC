# QSC: Quantum Secure Cryptographic Library

[![Build](https://img.shields.io/github/actions/workflow/status/QRCS-CORP/QSC/build.yml?branch=master)](https://github.com/QRCS-CORP/QSC/actions/workflows/build.yml)
[![CodeQL](https://img.shields.io/github/actions/workflow/status/QRCS-CORP/QSC/codeql-analysis.yml?label=CodeQL&branch=master)](https://github.com/QRCS-CORP/QSC/actions/workflows/codeql-analysis.yml)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/QSC/)
[![Security Policy](https://img.shields.io/badge/security-policy-blue.svg)](https://github.com/QRCS-CORP/QSC/security/policy)
![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/QSC)


**A compact, self-contained, and highly optimized post-quantum secure cryptographic library written in C.**

[QSC Help Documentation](https://qrcs-corp.github.io/QSC/)  
[QSC Technical Specification](https://qrcs-corp.github.io/QSC/pdf/QSC_Specification.pdf)  
[QSC Summary Document](https://qrcs-corp.github.io/QSC/pdf/QSC_Summary.pdf)  
[QSC Target Industries](https://qrcs-corp.github.io/QSC/pdf/QSC_High-Security_Cryptographic_Library_for_Critical_Domains.pdf) 

## Overview

QSC is designed to provide next-generation, post-quantum secure cryptographic primitives for applications requiring long-term security. Adhering to MISRA secure coding standards, the library is structured for clarity, ease of verification, and seamless integration into secure communications platforms. The code is well structured, thoroughly commented, and comes with an extensive testing platform covering every primitive contained in the library.


## Status

QSC is a compact and self-contained library written in C. It has been developed to meet MISRA secure coding standards and is designed to be easy to read, verify, and implement. The library incorporates next-generation asymmetric and symmetric primitives with a strong emphasis on true long-term security. It forms the basis for future integration efforts as a compact, high-security, post-quantum secure communications platform.

This implementation uses both a base reference code and optimized AVX/AVX2/AVX512 intrinsics for maximum performance. For best results, set your project properties to utilize the highest available SIMD instruction set supported by your CPU—AVX-512 instructions are fully supported and offer the best performance profile.


## Version

**Version:** 1.0.0.6c 
Tested on:  
- **Windows 10/11/Server**    
- **Ubuntu Linux**  
- **macOS**  

_All asymmetric ciphers and signature schemes have been updated to new FIPS standards for the winners, and NIST PQC Round 3 standards for last round contenders._

## Library Contents

### Asymmetric Cryptography

- **Key Encapsulation Mechanisms:**  
  - **McEliece:** Niederreiter dual form of the McEliece public key crypto-system.  
  - **Kyber:** Module-LWE based key encapsulation (updated to NIST FIPS-203 standards).  
  - **NTRU:** Asymmetric cipher implementation.  
  - **ECDH:** Elliptic Curve Diffie-Hellman key exchange.

- **Digital Signature Schemes:**  
  - **Sphincs+:** Post-quantum secure signature scheme (updated to NIST FIPS-205 standards).  
  - **Dilithium:** Lattice-based signature scheme (updated to NIST FIPS-204 standards).  
  - **Falcon:** NTRU-based signature scheme.  
  - **ECDSA (Ed25519):** Elliptic Curve Digital Signature Algorithm.

### Symmetric Cryptography

- **Symmetric Ciphers:**
  - **AES:** Supports modes such as CBC, CTR, HBA, and ECB.  
  - **RCS:** An authenticated AEAD stream cipher based on wide-block Rijndael and KMAC/QMAC. 
  - **CSX:** A ChaCha-based authenticated AEAD stream cipher using 64-bit integers, 512-bit keys, and KMAC/QMAC authentication.
  - **ChaChaPoly20:** ChaCha-based stream cipher. 

- **Hash Functions:**  
  - **SHA3:** 256 and 512-bit variants.
  - **SHA2:** 256 and 512-bit variants.

- **Message Authentication Codes:**  
  - **QMAC:** GMAC(2^256) variant.  
  - **KMAC:** Keccak FIPS-202 MAC function.  
  - **HMAC:** SHA2-256 and 512-bit MAC functions.  
  - **Poly1305:** High-speed MAC generator.

- **DRBGs and PRNGs:**
  - **CSG (`csg.h`):** cSHAKE wrapped auto-seeding DRBG.
  - **HCG (`hcg.h`):** HMAC wrapped auto-seeding DRBG.
  - **SCB (`scb.h`):** SHAKE Cost Based KDF (uses memory thrashing and CPU cost mechanisms).
  - **Secrand (`secrand.h`):** Secure PRNG producing random integers of every type.
    
- **XOF and KDF Functions:**  
  - **SHAKE** and **cSHAKE:** (for key derivation functions and DRBGs).  
  - **SCB:** SHAKE Cost Based KDF used for secure passphrase-key derivation.
  - **HKDF:** SHA2-256 AND 512 bit variants

- **Entropy Providers & PRNGs:**
  - **ACP (`acp.h`):** Auto Entropy Collection Provider for gathering entropy.
  - **CSP (`csp.h`):** The operating system entropy provider.
  - **RDRAND (`rdp.h`):** Utilizes hardware-based random number generation.


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
  A complete set of network functions provided in `netutils.h`, `socket.h`, `socketbase.h`, and `socketflags.h`.
- **Socket Server and Client:**
  An asynchronous high-performance socket server and client in `socketclient.h` and `socketserver.h`.

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

- **Language Interoperability:**  
  Interoperability with C++, and .NET via the QSCNETCW wrapper library.

## Compilation

QSC is a standalone, portable, and MISRA-aligned cryptographic library written in C. It supports platform-optimized builds across **Windows**, **macOS**, and **Linux** via [CMake](https://cmake.org/), and includes support for modern hardware acceleration such as AVX/AVX2/AVX-512, AES-NI, and RDRAND.

### Prerequisites

- **CMake**: 3.15 or newer
- **Windows**: Visual Studio 2022 or newer
- **macOS**: Clang via Xcode or Homebrew
- **Ubuntu**: GCC or Clang


### Building QSC and QSCTest

#### Windows (MSVC)

Use the Visual Studio solution to create the library and test project QSC Test.
Extract the files, and open the QSCTest project. The QSC library has a default location in a folder parallel to the QSCTest folder.  
The QSCTest additional files folder is set to: **$(SolutionDir)..\QSC\QSC**, if this is not the location of the library files, change it by going to QSCTest project properties **Configuration Properties->C/C++->General->Additional Include Directories** and set the library files location.  
Ensure that the **QSCTest->References** property contains a reference to the QSC library. QSC supports every AVX instruction family (AVX/AVX2/AVX-512).   
Set the QSC library and the QSCTest project to the same AVX family setting in **Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**.  
Set both QSC and QSCTest to the same instruction set in Debug and Release Solution Configurations.  
Compile the QSC library (right-click and choose build), then set the QSCTest project as the startup project (right-click Set as Startup Project), and run the project.

#### MacOS / Ubuntu (Eclipse)

The QSC library and QSCTest project have been tested using the Eclipse IDE on Ubuntu and MacOS.  
In the Eclipse folder there are subfolders for Ubuntu and MacOS that contain the **.project**, **.cproject**, and **.settings** Eclipse files.  Copy those files directly into the folders containing the code files, ex. in the **Eclipse\Ubuntu\QSC** folder, and do the same for the QSCTest project.  
Create a new project for QSC, select C/C++ project, and then **Create an empty project** with the same name as the folder with the files, 'QSC'.  
Eclipse should load the project with all of the settings into the project view window. The same proceedure is true for **MacOS and Ubuntu**, but some settings are different (GCC/Clang), so choose the project files that correspond to the operating system.  
The default projects use minimal flags, but are set to use AVX2, AES-NI, and RDRand by default.

Sample flag sets and their meanings:  
-**AVX Support**: -msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # 256-bit FP/SIMD  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mpclmul**      # PCLMUL (carry-less multiply)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX2 Support**: -msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # 256-bit integer + FP SIMD  
-**mpclmul**      # PCLMUL (carry-less multiply for AES-GCM, GHASH, etc.)  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX-512 Support**: -msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # AVX2 baseline (implied by AVX-512 but explicit is safer)  
-**mavx512f**     # 512-bit Foundation instructions  
-**mavx512bw**    # 512-bit Byte/Word integer instructions  
-**mvaes**        # Vector-AES (VAES) in 512-bit registers  
-**mpclmul**      # PCLMUL (carry-less multiply for GF(2ⁿ))  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  
-**maes**         # AES-NI (128-bit AES rounds; optional if VAES covers your AES use)  


## Roadmap

- Continued ASM/SIMD integration and optimization.
- Wrapper library for Java.
- Expansion of testing and benchmarking frameworks.
- Integration of emerging cryptographic research and standards.

## License

ACQUISITION INQUIRIES:
QRCS is currently seeking a corporate acquirer for this technology.
Parties interested in exclusive licensing or acquisition should contact:
john.underhill@protonmail.com  

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

QRCS-PL private License. See license file for details.  
Software is copyrighted and algorithms are patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
All rights reserved by QRCS Corp. 2025.

