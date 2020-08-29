# QSC: Quantum Secure Cryptographic library in C

## Status
Version 1.0
QSC is a compact and self-contained post-quantum secure cryptographic library witten in C. It has been written to Misra secure coding standards, and has been designed to be easy to read, verify, and implement. The code is well structured, readable and commented, and thoroughly documented, and this solution contains a testing platform, which provides various test functions for every primitive contained in the library. 
This library incorporates next-generation asymmetric and symmetric primitives, with a strong emphasis on true long-term security. The objective of this library is to provide a basis for future integration efforts, and as the foundation of a compact, high-security, post-quantum secure communications platform. This is currently a Windows/Intel library, however, much of the groundwork has been laid towards interoperability with different operating systems and hardware architectures (looking for volunteers). 

## Contains
### Asymmetric Ciphers
The Round-2 versions of the NIST PQ asymmetric ciphers and signature schemes (will be updated to Round 3 versions in the fall).
* McEliece: The Niederreiter dual form of the McEliece public key crypto-system
* Kyber: The Module-LWE Kyber public key crypto-system

### Asymmetric Signature Schemes
* Sphincs+: The Sphincs Plus asymmetric signature scheme
* Dilithium: the lattice based Dilithium asymmetric signature scheme

### Symmetric ciphers
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
* secmem: A secure locked-memory class
* memutils: Intrinsics operations for common memory fuctions
* AVX/AVX2/AVX512 intinsics integrated throughout

### Roadmap
* A post-quantum TLS 1.3 implementation
* Migrartion of asymmetric primitives to NIST PQ round 3 versions

### License
GPLv3

## Disclaimer
This project contains strong cryptography, before downloading the source files, 
it is your responsibility to check if the cryptographic algorithms contained in this project are legal in your country. 
If you use this code, please do so responsibly and in accordance to law in your region.
