# QSC: Quantum Secure Cryptographic library in C

## Status

QSC is a compact and self-contained post-quantum secure cryptographic library witten in C. It has been written to MISRA secure coding standards, and has been designed to be easy to read, verify, and implement. The code is well structured, readable and commented, and thoroughly documented, and this solution contains a testing platform, which provides various test functions for every primitive contained in the library. 
This library incorporates next-generation asymmetric and symmetric primitives, with a strong emphasis on true long-term security. The objective of this library is to provide a basis for future integration efforts, and as the foundation of a compact, high-security, post-quantum-secure communications platform. This version has been tested on Windows 10, Ubuntu Linux, and MAC Big Sur. 
This library has SIMD intrinsice integratewd throughout, using AVX, AVX2, and AVX512 implementations.
This implementation uses a base reference code, or AVX/AVX2/AVX512 implementations of ciphers and cryptographic protocols. For best performance, set the project properties to the highest available SIMD instruction set supported by your CPU. AVX-512 instructions are fully supported in this implementation and offer the best performance profile.

## Version
Version 1.0.0.5L
Tested on Windows 10, version 10.0.19042 using Visual Studio version 16.10.2,
Ubuntu Linux version 20.04 using Eclipse version 2021-09 GCC Ubuntu 9.3.0-17
and Mac Big Sur version 11.5.2 using Eclipse version 2021-09 GCC Apple Clang version 12.0.5.
All asymmetric ciphers and signature schemes updated to NIST PQC Round 3

## Contains
### Asymmetric Ciphers
The Round-3 versions of the NIST PQC asymmetric ciphers and signature schemes.
* McEliece: The Niederreiter dual form of the McEliece public key crypto-system
* Kyber: The Module-LWE Kyber public key crypto-system
* NTRU: The NTRU asymmetric cipher
* ECDH: Elliptic Curve Diffie Hellman

### Asymmetric Signature Schemes
* Sphincs+: The Sphincs Plus asymmetric signature scheme
* Dilithium: the lattice based Dilithium asymmetric signature scheme
* Falcon: The NTRU based  asymmetric signature scheme
* ECDSA: Elliptic Curve Digital Signature Algorithm (ED25519)

### Symmetric ciphers
* AES: The AES symmetric block cipher and modes
* ChaChaPoly20: The ChaCha stream cipher
* RCS: The authenticated stream cipher using wide-block Rijndael and KMAC authentication
* CSX: The authenticated stream cipher based on ChaCha, using 64-bit integers, 512-bit keys, and KMAC authentication

### Hash Functions
* SHA3: The SHA3 cryptographic message digest
* SHA2: The SHA2 256 and 512-bit cryptographic message digests

### MAC Generators
* KMAC: 128, 256, and 512-bit versions of the KMAC message authentication code generators
* HMAC: SHA2 based 256 and 512-bit versions of the HMAC message authentication code generators
* Poly1305: The Poly1305 message authentication code generator

### DRBG, XOF, and PRNGs
* The Keccak based SHAKE and cSHAKE, 128, 256, and 512-bit XOF functions
* The HMAC(SHA2) based 256 and 512-bit HKDF Expand and Extract functions
* The cSHAKE based DRBG CSG, with predictive resistance and forward secrecy capabilities
* The Secure Random class, providing random integer generation for all common integer types

### Entropy Providers
* ACP: The auto-collection provider, uses a mix of system entropy sources; timers, system state, RDRAND, and the system provider to seed cSHAKE-512 (the recommended key provider).
* CSP: The system cryptographic provider
* RDP: The Intel RDRAND provider

### Features
* Asynchronous threading
* Dual IPv4/IPv6 synchronous and asynchronous networking stack
* cpuid: tests available CPU feature sets
* secmem: A secure locked-memory class
* memutils: Intrinsics operations for common memory fuctions
* AVX/AVX2/AVX512 intinsics integrated throughout

### Roadmap
* ASM/SIMD integration and optimization
* A post-quantum TLS 1.3 implementation

## License
This project's code is copyrighted, and the mechanism is patent pending.
This placed here for educational purposes only, and not to be used commercially, or redistributed without the author's expressed written permission.
All rights reserved by Digital Freedom Defense Inc. 2022.

## Disclaimer
This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if the cryptographic algorithms contained in this project are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.
