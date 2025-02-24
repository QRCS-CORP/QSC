#ifndef DOXYMAIN_H
#define DOXYMAIN_H

/*! \mainpage QSC: Quantum Secure Cryptographic Solutions Library
 *
 * \brief Main documentation page for the QSC Library.
 *
 * \details
 * QSC (Quantum Secure Cryptographic Solutions) is a compact, self-contained, and highly optimized 
 * cryptographic library written in C. It is designed to provide next-generation, post-quantum secure 
 * cryptographic primitives for applications requiring long-term security. The library adheres to 
 * MISRA secure coding standards and is structured for clarity, ease of verification, and integration 
 * into secure communication platforms.
 *
 * \par Overview
 * The QSC Library includes a comprehensive suite of cryptographic algorithms and utilities, such as:
 * - **Asymmetric Cryptography:**
 *   - *Key Encapsulation Mechanisms:* McEliece (Niederreiter dual form), Kyber, NTRU, and ECDH.
 *   - *Digital Signature Schemes:* Sphincs+, Dilithium, Falcon, and ECDSA (Ed25519).
 * - **Symmetric Cryptography:**
 *   - *Block Ciphers:* AES (with modes such as CBC, CTR, and ECB) and RCS (an authenticated stream cipher 
 *     based on wide-block Rijndael and KMAC).
 *   - *Stream Ciphers:* ChaChaPoly20 and CSX (a ChaCha-based authenticated cipher).
 * - **Hash Functions and MACs:**
 *   - Cryptographic message digests including SHA3 and SHA2.
 *   - Message authentication codes (MAC) via KMAC, HMAC, and Poly1305.
 * - **Pseudo-Random Number Generation and Entropy:**
 *   - XOF functions (SHAKE and cSHAKE) used in DRBGs and key derivation functions (HKDF).
 *   - Secure random number generators (PRNGs) and entropy providers (ACP, CSP, RDP) that integrate hardware 
 *     randomness (e.g., Intel RDRAND) with system entropy.
 * - **System Utilities:**
 *   - Asynchronous threading, mutex-based synchronization, and dual IPv4/IPv6 networking.
 *   - CPU feature detection (CPUID) and secure memory management with SIMD (AVX/AVX2/AVX512) optimizations.
 *
 * \par Architecture and Performance
 * The QSC Library is architected with both portability and performance in mind:
 * - **Reference Implementations:** Clear and maintainable C code ensuring broad platform compatibility.
 * - **SIMD Optimizations:** Critical algorithms are implemented using AVX, AVX2, and AVX512 intrinsics to 
 *   leverage modern CPU capabilities, achieving superior performance.
 *
 * \par Supported Platforms
 * QSC has been thoroughly tested on:
 * - Windows 10 (Visual Studio)
 * - Ubuntu Linux (GCC)
 * - macOS Big Sur (Apple Clang)
 *
 * \par References and Standards
 * - **NIST SHA3 (FIPS 202):** [SHA-3 FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
 * - **AES (FIPS 197):** [AES Specification](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf)
 * - **Microsoft CryptGenRandom Documentation:** [CryptGenRandom](https://docs.microsoft.com/en-us/windows/win32/seccrypto/cryptgenrandom)
 * - **POSIX /dev/urandom:** [Linux /dev/urandom](https://man7.org/linux/man-pages/man4/urandom.4.html)
 * - **Intel CPUID Instruction:** [Intel CPUID](https://software.intel.com/content/www/us/en/develop/articles/intel-64-architecture-cpuid-instruction.html)
 * - **AMD CPUID Documentation:** [AMD CPUID](https://www.amd.com/system/files/TechDocs/25481.pdf)
 * - **ChaCha Stream Cipher Specification:** [ChaCha Specification](https://cr.yp.to/chacha/chacha-20080120.pdf)
 * - **Dilithium (FIPS 204):** [Dilithium FIPS 204](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf)
 * - **Classic McEliece Specification:** [McEliece Specification](https://www.randombit.net/mceliece/mceliece-spec.pdf)
 * - **Kyber Documentation:** See the PQ-Crystals Kyber documentation.
 * - **Galois Field Theory and Carryless Multiplication:** [Intel Intrinsics Reference](https://www.intel.com/content/www/us/en/develop/documentation/64-ia-32-architectures-software-developer-instruction-set-reference-guide-325383.pdf)
 *
 * \par Keywords
 * Cryptography, Post-Quantum, Asymmetric Cryptography, Symmetric Cryptography, Digital Signature, Key Encapsulation, 
 * Key Exchange, Hash Function, MAC, Pseudo-Random Number Generator, DRBG, Entropy, SIMD, AVX, AVX2, AVX512, 
 * Secure Memory, Asynchronous, MISRA, QSC.
 *
 * \par Example
 * Refer to the module-specific headers (e.g., aes.h, sha3.h, kyber.h, ecdh.h, ecdsa.h, etc.) for detailed usage examples.
 *
 * \author John G. Underhill
 * \date 2025-02-15
 *
 * \remarks
 * QSC is designed to serve as the foundational cryptographic solution for secure, post-quantum 
 * communications and is continuously updated to incorporate emerging cryptographic research and 
 * standards.
 * 
 * QRCS-PL private License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 * 
 * \author John G. Underhill
 * \date 2025-02-10
 */

#endif
