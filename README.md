# QSC: Quantum Secure Cryptographic Library    

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

## Overview

QSC is a production-grade cryptographic library built for environments that demand verifiable correctness, long-term quantum resistance, and high throughput. The library combines NIST-standardized post-quantum algorithms with classical primitives, proprietary high-security constructions, and SIMD-accelerated implementations, all within a single, dependency-free C23 codebase.

Recent additions expand the library's reach into public-internet TLS and certificate infrastructure: full ECDSA implementations for NIST P-256, P-384, and P-521 interoperable with the CA/Browser Forum Baseline Requirements, Falcon lattice-based signatures, the HQC code-based key encapsulation mechanism, and a comprehensive X.509 certificate infrastructure built on a strict DER/BER-capable ASN.1 engine. The X.509 layer now covers the full certificate lifecycle; parsing, validation, generation, revocation, OCSP, PKCS#12 key management, and post-quantum ML-DSA certificate profiles, without any external dependencies.

Key design goals:

- **Long-term security** - all asymmetric algorithms are post-quantum secure; proprietary constructions target 256-bit or greater security levels.
- **Standards compliance** - written to [MISRA C](https://misra.org.uk/) secure coding guidelines; asymmetric primitives updated to final FIPS-203, FIPS-204, and FIPS-205 standards.
- **Public internet compatibility** - NIST P-256, P-384, and P-521 ECDSA and X.509 certificate infrastructure enable deployment in TLS 1.2/1.3 stacks and compliance with CA/Browser Forum Baseline Requirements for publicly trusted certificates.
- **Performance** - dual code paths: clean portable C reference implementations alongside AVX, AVX2, and AVX-512 intrinsic-optimized variants. Enable the highest instruction set supported by your target CPU for maximum throughput.
- **Auditability** - thoroughly commented, well-structured source with a comprehensive test suite covering known-answer tests, NIST CAVP/ACVP vectors, fuzzing, and stress testing across every primitive.
- **Portability** - compiles on Windows (MSVC), Linux (GCC), and macOS (Clang) with no external dependencies.

> **Version:** 1.1.0.1b  
> **Tested on:** Windows 10 / 11 / Server · Ubuntu Linux · macOS  
> _All asymmetric ciphers and signature schemes have been updated to the final NIST FIPS standards for standardized algorithms and to NIST PQC Round 3 specifications for remaining candidates._

---

## Projects

The distribution includes three companion projects alongside the QSC library, all available on the [QRCS-CORP/QSC project page](https://github.com/QRCS-CORP/QSC).

### QSCTest

The primary validation suite for the QSC library. QSCTest exercises every cryptographic primitive through a structured battery of tests designed to detect correctness regressions, implementation errors, and performance degradation.

**Test coverage includes:**

- **Known Answer Tests (KATs)** - output from every primitive is verified against pre-computed reference vectors.
- **NIST ACVP Vectors** - asymmetric and symmetric primitives verified against official NIST Automated Cryptographic Validation Program test vectors.
- **Fuzzing** - randomized input testing to detect edge-case failures and undefined behaviour.
- **Stress Testing** - extended load testing to surface resource leaks, state corruption, and threading issues.
- **Function Correctness** - round-trip and cross-function consistency checks (e.g., encrypt→decrypt, sign→verify).

Coverage spans the full library: asymmetric ciphers (ML-KEM, McEliece, HQC, ECDH), signature schemes (ML-DSA, SLH-DSA, Falcon, ECDSA P-256/P-384/P-521, Ed25519), symmetric ciphers (AES, RCS, CSX, ChaCha20-Poly1305), hash and XOF functions (SHA2, SHA3, SHAKE, cSHAKE), MAC functions (KMAC, QMAC, HMAC, Poly1305), DRBGs (CSG, HCG), entropy providers (ACP, CSP, RDP), the X.509 certificate layer, and all utility modules.

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
- Full parity with the C API, no functionality is omitted in the wrapper layer.

The wrapper is written in managed C++ and compiled as a mixed-mode assembly, allowing direct P/Invoke-free consumption from any .NET language (C#, VB.NET, F#).

---

## Library Contents

### Asymmetric Cryptography

#### Key Encapsulation Mechanisms (KEM)

| Algorithm | Type | Standard |
|---|---|---|
| **ML-KEM** (Kyber) | Module-LWE based KEM | NIST FIPS-203 |
| **Classic McEliece** | Niederreiter dual-form code-based KEM | NIST PQC Round 3 |
| **HQC** | QC-MDPC code-based KEM | NIST PQC Round 4 |
| **ECDH** (X25519) | Elliptic Curve Diffie-Hellman | RFC 7748 |

#### Digital Signature Schemes

| Algorithm | Type | Standard / Reference |
|---|---|---|
| **ML-DSA** (Dilithium) | Module-lattice based signatures | NIST FIPS-204 |
| **SLH-DSA** (SPHINCS+) | Stateless hash-based signatures | NIST FIPS-205 |
| **Falcon** | NTRU lattice-based compact signatures | NIST PQC Round 3 |
| **ECDSA** (P-256 / P-384 / P-521) | Elliptic curve signatures over NIST P-256 (secp256r1), P-384 (secp384r1), and P-521 (secp521r1); RFC 6979 deterministic nonce; interoperable with TLS 1.2/1.3 and public CA certificates | FIPS 186-5, RFC 6979, RFC 8422 |
| **EDDSA** | Edwards-curve digital signatures | RFC 8032 |

---

### X.509 Certificate Infrastructure

QSC includes a complete X.509 PKI layer covering the full certificate lifecycle: DER parsing, semantic verification, certificate and CRL generation, PKCS#10 certificate signing requests, OCSP response validation, PKCS#12 bundle handling, and trust store management. The implementation is built on a strict DER/BER decoder and a typed ASN.1 helper layer, and natively supports both classical ECDSA and post-quantum ML-DSA certificate profiles.

#### Correctness and Standards Compliance

The X.509 implementation strictly enforces the requirements of RFC 5280, X.690, and RFC 6125:

- **Strict DER decoding** - the BER decoder rejects indefinite-length encodings for all DER contexts; BOOLEAN values must be `0x00` (FALSE) or `0xFF` (TRUE) per X.690 §11.1; INTEGER encodings are validated for minimal encoding and correct sign representation.
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
| **Certificate Parser** | `x509cert.h` | DER-encoded X.509 certificate decoder; populates `qsc_x509_certificate` and records the raw TBSCertificate span for signature verification without re-serialisation; decodes BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier, SubjectAltName, IssuerAltName, and unknown extensions |
| **Certificate Builder** | `x509certwrite.h` | X.509 v3 certificate builder and signing interface; constructs TBSCertificate fields, attaches extensions, signs with a caller-supplied private key, and produces DER or PEM output |
| **Distinguished Name** | `x509name.h` | Issuer/subject Name parsing; decodes relative distinguished name sequences into typed attribute lists; handles multi-valued RDNs; RFC 5280 §7.1 canonical comparison with Unicode NFC normalisation |
| **Validity / Time** | `x509time.h` | Decodes ASN.1 UTCTime and GeneralizedTime into normalised `qsc_x509_time` structures; provides validity interval comparison following RFC 5280 |
| **SubjectPublicKeyInfo** | `x509spki.h` | Decodes SubjectPublicKeyInfo and the nested AlgorithmIdentifier for ECDSA (P-256, P-384, P-521), ML-DSA (44/65/87), and ML-KEM (512/768/1024) key types; validates public key sizes against expected PQC parameter set sizes |
| **Signature Algorithm** | `x509sig.h` | Decodes certificate and TBSCertificate signature AlgorithmIdentifiers for ECDSA and ML-DSA profiles; unpacks ECDSA DER SEQUENCE(INTEGER, INTEGER) signatures into fixed-width big-endian buffers; validates ML-DSA signature length against the active parameter set |
| **Extensions** | `x509ext.h` | Decodes and queries all standard certificate extensions including BasicConstraints, KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier, SubjectAltName, IssuerAltName, CRLDistributionPoints, AuthorityInfoAccess, SubjectInfoAccess, and CertificatePolicies |
| **Certificate Verification** | `x509verify.h` | Semantic verification layer: TBSCertificate / outer signature algorithm consistency; validity interval evaluation; issuer–subject name linkage; BasicConstraints and KeyUsage checks for CAs; KEM-key / CA-flag conflict detection; path length constraint enforcement; duplicate extension detection; RFC 6125-compliant hostname and IP address matching; critical extension enforcement; revocation integration |
| **QSC Verification Adapter** | `x509sigver.h` | Binds the X.509 verification layer to QSC's ECDSA (P-256/P-384/P-521) and ML-DSA (44/65/87) signature APIs; implements `qsc_x509_signature_verify_callback` for use with `qsc_x509_certificate_verify` and `qsc_x509_chain_verify` |
| **Hostname / IP Matching** | `x509host.h` | RFC 6125-compliant DNS name matching with wildcard support and IDNA guard; IPv4 and IPv6 address matching against SubjectAltName IP entries; CN fallback suppressed when any SAN extension is present |
| **Certificate Signing Request** | `x509csr.h` | PKCS#10 CSR encoding, decoding, and verification interface; constructs certification requests from a SubjectPublicKeyInfo and Distinguished Name, signs with a caller-supplied key, and decodes incoming DER or PEM requests |
| **Certificate Revocation List** | `x509crl.h` | X.509 CRL parsing, entry lookup, and signature verification; decodes v1 and v2 CRLs including cRLNumber, deltaCRLIndicator, issuingDistributionPoint, and per-entry reasonCode and invalidityDate extensions |
| **CRL Builder** | `x509crlwrite.h` | X.509 CRL builder, signing, and PEM encoding interface; constructs TBSCertList fields, adds revocation entries with optional reason codes, and signs with a caller-supplied issuer key |
| **OCSP** | `x509ocsp.h` | OCSP response parsing and online certificate status validation; decodes BasicOCSPResponse, verifies the responder signature, and maps the response to a `qsc_x509_revocation_status` value |
| **Revocation Policy** | `x509rev.h` | Unified revocation policy interface integrating CRL and OCSP checking; supports `REQUIRE_VALID_CRL`, `BEST_EFFORT`, and `DISABLED` revocation modes; called by `qsc_x509_certificate_verify_ex` when revocation options are provided |
| **Revocation Extensions** | `x509revext.h` | Extended revocation helpers for delta-CRL application and stapled OCSP verification; applies delta CRLs against a base CRL and validates OCSP staple tokens attached to TLS handshakes |
| **Authority Info Access** | `x509aia.h` | Decodes and queries the AuthorityInfoAccess and SubjectInfoAccess extensions; extracts OCSP responder URIs and CA Issuers URIs for online revocation and chain building |
| **Trust Store** | `x509store.h` | Trust-anchor store and certificate chain construction interface; manages a flat array of `qsc_x509_trust_anchor` records; provides chain anchoring, self-signed detection, and anchor lookup used by `qsc_x509_chain_verify` |
| **Private Key** | `x509key.h` | Private key decoding, size validation, and certificate-key matching interface; decodes PKCS#8 OneAsymmetricKey and SEC 1 ECPrivateKey structures for ECDSA and ML-DSA key types |
| **Key Serialisation** | `x509keywrite.h` | Private key encoding and PEM conversion interface; serialises ECDSA and ML-DSA private keys to PKCS#8 DER or SEC 1 DER and wraps the result in PEM armour |
| **PKCS#12** | `x509pkcs12.h` | PKCS#12 bundle parsing and encrypted private-key decryption; decodes PFX structures containing certificate chains and password-protected private keys using AES-256-CBC or 3DES |
| **PEM Codec** | `x509pem.h` | PEM encode/decode for certificates, CRLs, CSRs, PKCS#8 private keys, SEC 1 EC keys, and ML-DSA / ML-KEM key types; validates header/footer label consistency and Base64 padding; supports multi-certificate PEM bundles and trust-store loading |
| **DER Write Primitives** | `x509write.h` | Low-level ASN.1 DER writing helpers for primitive values, composite objects, SPKI structures, and standard extension payloads; used internally by the certificate and CRL builders |

#### Supported Certificate Signature Profiles

| Profile | Signature OID | Public Key Type | Parameter |
|---|---|---|---|
| `ecdsa-with-SHA256` | `1.2.840.10045.4.3.2` | `id-ecPublicKey` | `prime256v1` (NIST P-256) |
| `ecdsa-with-SHA384` | `1.2.840.10045.4.3.3` | `id-ecPublicKey` | `secp384r1` (NIST P-384) |
| `ecdsa-with-SHA512` | `1.2.840.10045.4.3.4` | `id-ecPublicKey` | `secp521r1` (NIST P-521) |
| `id-ML-DSA-44` | `2.16.840.1.101.3.4.3.17` | `id-ML-DSA-44` | ML-DSA parameter set 44 |
| `id-ML-DSA-65` | `2.16.840.1.101.3.4.3.18` | `id-ML-DSA-65` | ML-DSA parameter set 65 |
| `id-ML-DSA-87` | `2.16.840.1.101.3.4.3.19` | `id-ML-DSA-87` | ML-DSA parameter set 87 |

The X.509 layer is intentionally split so that the structural and policy checks (`x509verify.h`) remain independent of the cryptographic backend, making it straightforward to add additional signature algorithm bindings in future releases.

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
| **AES** | CBC, CTR, ECB, GCM, HBA; hardware-accelerated via AES-NI and SIMD |
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

### Proprietary Component Specifications

Each proprietary construction in QSC is accompanied by a full technical specification and an independent formal security analysis.

| Component | Description | Specification | Formal Analysis |
|---|---|---|---|
| **CSX** | ChaCha-based authenticated AEAD stream cipher; 512-bit keys, 64-bit integers, KMAC/QMAC authentication | [Specification](https://qrcs-corp.github.io/QSC/pdf/csx_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/csx_formal.pdf) |
| **QMAC** | Wide-block GF(2²⁵⁶) polynomial MAC function | [Specification](https://qrcs-corp.github.io/QSC/pdf/qmac_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/qmac_formal.pdf) |
| **RCS** | Rijndael-based authenticated AEAD stream cipher with KMAC/QMAC authentication | [Specification](https://qrcs-corp.github.io/QSC/pdf/rcs_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/rcs_formal.pdf) |
| **SCB** | SHAKE Cost-Based KDF; memory-hard passphrase derivation with configurable CPU and memory cost | [Specification](https://qrcs-corp.github.io/QSC/pdf/scb_specification.pdf) | [Formal Analysis](https://qrcs-corp.github.io/QSC/pdf/scb_formal.pdf) |

---

### Utility and System Support

#### Encoding and Data Infrastructure

| Module | Description |
|---|---|
| `encoding.h` | BER/DER encoding and decoding engine; Base64, hex, and binary encoding schemes |
| `asn1.h` | ASN.1 typed helper layer built on `encoding.h`; used by the X.509 certificate layer |
| `oid.h` | OID registry and lookup helpers for the X.509 and ASN.1 layers |

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

- **Reference path** - clean, portable C23 code that compiles on any conforming compiler and provides a readable, auditable baseline.
- **SIMD-optimized path** - AVX, AVX2, and AVX-512 intrinsic implementations that activate automatically when the appropriate instruction set is enabled at compile time, providing substantial throughput improvements on modern x86-64 hardware.

The two paths share identical interfaces and produce identical output; the compiler selects the appropriate implementation via preprocessor feature detection. For production deployments, enabling AVX-512 (where the target hardware supports it) yields the highest performance across all symmetric primitives, hash functions, and post-quantum algorithms.

SIMD acceleration is applied across: AES (AES-NI), RCS, CSX, SHA3/SHAKE/Keccak, ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+), and all memory utility operations.

The ECDSA P-256, P-384, and P-521 implementations use Jacobian projective coordinates with the a=−3 doubling shortcut, Solinas reduction for field arithmetic, and Barrett reduction for scalar arithmetic mod n. RFC 6979 deterministic nonce generation (HMAC-SHA256/384/512 respectively) means no entropy source is required during signing.

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
| **Post-Quantum Algorithms** | ML-KEM (FIPS-203), ML-DSA (FIPS-204), SLH-DSA (FIPS-205), Falcon (Round 3), Classic McEliece, HQC (Round 4) |
| **Classical Algorithms** | AES, SHA-2/3, HMAC, ChaCha20-Poly1305, ECDH (X25519), ECDSA (P-256 / P-384 / P-521), Ed25519 |
| **Proprietary Constructions** | RCS, CSX, QMAC, SCB - each with formal security analysis |
| **X.509 / PKI Infrastructure** | Full certificate lifecycle: DER/PEM parsing and generation, chain verification, CRL and OCSP revocation, PKCS#10 CSR, PKCS#12 key bundles, trust store management; ECDSA P-256/P-384/P-521 and ML-DSA-44/65/87 certificate profiles; RFC 5280, RFC 6125, and X.690 strict DER compliance |
| **SIMD Acceleration** | AVX, AVX2, AVX-512, AES-NI, RDRAND across all major primitives |
| **Security Standard** | MISRA C compliant throughout |
| **Testing** | KAT, NIST ACVP/CAVP, fuzzing, and stress tests for every primitive |
| **Platforms** | Windows (MSVC), Linux (GCC), macOS (Clang) |
| **Language Interop** | C++, and .NET (C#/VB.NET/F#) via the QSCNETCW managed wrapper |
| **Self-Contained** | No external runtime dependencies |

---

## Roadmap

- [ ] Continued ASM and SIMD integration and optimization
- [ ] TLS 1.3
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

*Quantum Resistant Cryptographic Solutions Corporation - All rights reserved, 2026.*
