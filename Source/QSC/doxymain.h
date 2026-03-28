/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef DOXYMAIN_H
#define DOXYMAIN_H

/*! \mainpage QSC: Quantum Secure Cryptographic Solutions Library Version 1.1
 *
 * \brief Main documentation page for the QSC Library.
 *
 * \details
 * QSC (Quantum Secure Cryptographic Solutions) is a compact, self-contained, and highly optimized
 * cryptographic library written in C23. It is designed to provide next-generation, post-quantum
 * secure cryptographic primitives for applications requiring long-term security against both
 * classical and quantum adversaries. The library adheres to MISRA secure coding standards and is
 * structured for clarity, ease of verification, and integration into secure communication platforms,
 * including public-internet TLS stacks and PKI certificate infrastructure.
 *
 * \par Overview
 * The QSC Library provides a comprehensive suite of cryptographic algorithms, a complete X.509
 * certificate infrastructure, and a broad set of system utilities:
 *
 * \par Asymmetric Cryptography
 * \b Key \b Encapsulation \b Mechanisms \b (KEM):
 * - \b ML-KEM (Kyber): Module-LWE based key encapsulation, NIST FIPS-203. Parameter sets
 *   ML-KEM-512, ML-KEM-768, and ML-KEM-1024. AVX2-accelerated implementations available.
 * - \b Classic \b McEliece: Niederreiter dual-form code-based KEM, NIST PQC Round 3.
 * - \b HQC: QC-MDPC code-based KEM, NIST PQC Round 4. AVX2-accelerated implementations available.
 * - \b ECDH \b (X25519): Elliptic Curve Diffie-Hellman key exchange over Curve25519, RFC 7748.
 *
 * \b Digital \b Signature \b Schemes:
 * - \b ML-DSA (Dilithium): Module-lattice based signatures, NIST FIPS-204. Parameter sets
 *   ML-DSA-44, ML-DSA-65, and ML-DSA-87. AVX2-accelerated implementations available.
 * - \b SLH-DSA (SPHINCS+): Stateless hash-based signatures, NIST FIPS-205.
 * - \b Falcon: NTRU lattice-based compact signatures, NIST PQC Round 3.
 *   AVX2-accelerated implementations available.
 * - \b ECDSA \b (P-256 / P-384 / P-521): Elliptic curve signatures over NIST P-256 (secp256r1),
 *   P-384 (secp384r1), and P-521 (secp521r1). RFC 6979 deterministic nonce generation
 *   (HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512 respectively). Jacobian projective coordinates
 *   with Solinas and Barrett reduction. Interoperable with TLS 1.2/1.3 and public CA certificates.
 *   Standards: FIPS 186-5, RFC 6979, RFC 8422.
 * - \b EdDSA \b (Ed25519): Edwards-curve digital signatures, RFC 8032.
 *
 * \par Symmetric Cryptography
 * \b Authenticated \b Encryption \b (AEAD):
 * - \b RCS: Wide-block Rijndael-based authenticated stream cipher with KMAC or QMAC authentication;
 *   256-bit and 512-bit key variants. A proprietary QRCS construction.
 * - \b CSX-512: ChaCha-derived authenticated stream cipher with 512-bit keys and KMAC or QMAC
 *   authentication. A proprietary QRCS construction.
 * - \b AES-GCM: AES in Galois/Counter Mode (GMAC authentication); combines AES-CTR with GMAC.
 * - \b AES-HBA: AES in Hash-Based Authentication mode; combines AES-CTR with KMAC authentication.
 *
 * \b Classical \b Symmetric \b Ciphers:
 * - \b AES: CBC, CTR, ECB, GCM, and HBA modes; hardware-accelerated via AES-NI and SIMD.
 *   FIPS-197, SP 800-38A/D.
 * - \b ChaCha20-Poly1305: Standard 256-bit ChaCha stream cipher with Poly1305 MAC.
 *
 * \par Hash Functions and MACs
 * - \b SHA3: SHA3-256 and SHA3-512 (FIPS-202); SHAKE-128, SHAKE-256, and cSHAKE variants.
 * - \b SHA2: SHA2-256 and SHA2-512 (FIPS-180-4).
 * - \b KMAC: Keccak-based message authentication code (FIPS-202).
 * - \b QMAC: Wide-block GF(2^256) polynomial MAC. A proprietary QRCS construction.
 * - \b HMAC: SHA2-256 and SHA2-512 variants (FIPS-198-1).
 * - \b Poly1305: High-speed Bernstein MAC.
 * - \b GMAC: Galois/Counter Mode MAC.
 *
 * \par Deterministic Random Bit Generators and Entropy
 * - \b CSG: cSHAKE-based auto-seeding DRBG (csg.h).
 * - \b HCG: HMAC-SHA2-based auto-seeding DRBG (hcg.h).
 * - \b SHAKE \b / \b cSHAKE: FIPS-202 extensible output functions for key derivation and DRBG seeding.
 * - \b SCB: SHAKE Cost-Based KDF; memory-hard passphrase derivation with configurable CPU and
 *   memory cost parameters. A proprietary QRCS construction (scb.h).
 * - \b HKDF: Extract-and-expand KDF using HMAC-SHA2-256 and HMAC-SHA2-512.
 * - \b ACP: Auto Entropy Collection Provider; aggregates multiple entropy sources (acp.h).
 * - \b CSP: OS-native cryptographic entropy provider (csp.h).
 * - \b RDP: Hardware entropy via Intel RDRAND and RDSEED (rdp.h).
 *
 * \par X.509 Certificate Infrastructure
 * QSC provides a complete, dependency-free X.509 PKI layer covering the full certificate lifecycle.
 * The implementation is built on a strict DER/BER-capable ASN.1 engine and enforces the requirements
 * of RFC 5280, X.690, and RFC 6125. Both classical ECDSA and post-quantum ML-DSA certificate
 * profiles are supported natively.
 *
 * \b Parsing \b and \b Decoding:
 * - \b x509cert.h: DER-encoded X.509 certificate decoder. Populates a \c qsc_x509_certificate
 *   structure and preserves the raw TBSCertificate span for signature verification without
 *   re-serialisation.
 * - \b x509name.h: Issuer and subject Name parsing; decodes relative distinguished name sequences
 *   into typed attribute lists; supports multi-valued RDNs; RFC 5280 §7.1 canonical comparison
 *   with Unicode NFC normalisation.
 * - \b x509time.h: Decodes ASN.1 UTCTime and GeneralizedTime into normalised \c qsc_x509_time
 *   structures; provides validity interval comparison.
 * - \b x509spki.h: Decodes SubjectPublicKeyInfo for ECDSA (P-256, P-384, P-521), ML-DSA
 *   (44/65/87), and ML-KEM (512/768/1024) key types; validates key sizes against expected
 *   parameter set sizes.
 * - \b x509sig.h: Decodes certificate signature AlgorithmIdentifiers for ECDSA and ML-DSA
 *   profiles; unpacks ECDSA DER SEQUENCE(INTEGER, INTEGER) signatures into fixed-width buffers;
 *   validates ML-DSA signature length against the active parameter set.
 * - \b x509ext.h: Decodes and queries all standard certificate extensions: BasicConstraints,
 *   KeyUsage, ExtendedKeyUsage, SubjectKeyIdentifier, AuthorityKeyIdentifier, SubjectAltName,
 *   IssuerAltName, CRLDistributionPoints, AuthorityInfoAccess, SubjectInfoAccess, and
 *   CertificatePolicies.
 * - \b x509crl.h: X.509 CRL parsing and entry lookup; decodes v1 and v2 CRLs including
 *   cRLNumber, deltaCRLIndicator, issuingDistributionPoint, and per-entry reasonCode and
 *   invalidityDate extensions.
 * - \b x509csr.h: PKCS#10 certificate signing request decoding and verification.
 * - \b x509pem.h: PEM decoding for certificates, CRLs, CSRs, PKCS#8 private keys, SEC 1 EC
 *   keys, and ML-DSA/ML-KEM key types; multi-certificate PEM bundle support.
 *
 * \b Certificate \b and \b CRL \b Generation:
 * - \b x509certwrite.h: X.509 v3 certificate builder and signing interface; constructs
 *   TBSCertificate fields, attaches extensions, signs with a caller-supplied private key, and
 *   produces DER or PEM output.
 * - \b x509crlwrite.h: X.509 CRL builder, signing, and PEM encoding interface; constructs
 *   TBSCertList fields and adds revocation entries with optional reason codes.
 * - \b x509csr.h: PKCS#10 CSR encoding; constructs certification requests from a
 *   SubjectPublicKeyInfo and Distinguished Name and signs with a caller-supplied key.
 * - \b x509write.h: Low-level ASN.1 DER writing helpers for primitive values, composite objects,
 *   SPKI structures, and standard extension payloads; used internally by the certificate and CRL
 *   builders.
 *
 * \b Verification \b and \b Trust:
 * - \b x509verify.h: Semantic certificate verification; TBSCertificate/outer signature algorithm
 *   consistency; validity interval evaluation; issuer-subject name linkage; BasicConstraints and
 *   KeyUsage enforcement for CAs; KEM-key/CA-flag conflict detection; path length constraint
 *   enforcement; duplicate extension detection; RFC 6125-compliant hostname and IP address
 *   matching; critical extension enforcement; revocation integration.
 * - \b x509sigver.h: Binds the verification layer to QSC's ECDSA (P-256/P-384/P-521) and
 *   ML-DSA (44/65/87) signature APIs; implements \c qsc_x509_signature_verify_callback for use
 *   with \c qsc_x509_certificate_verify and \c qsc_x509_chain_verify.
 * - \b x509host.h: RFC 6125-compliant DNS name matching with wildcard support and IDNA guard;
 *   IPv4 and IPv6 address matching against SubjectAltName IP entries; CN fallback suppressed
 *   whenever any SAN extension is present.
 * - \b x509store.h: Trust-anchor store and certificate chain construction; manages
 *   \c qsc_x509_trust_anchor records; provides chain anchoring, self-signed detection, and
 *   anchor lookup used by \c qsc_x509_chain_verify.
 *
 * \b Revocation:
 * - \b x509rev.h: Unified revocation policy interface integrating CRL and OCSP status checking;
 *   supports \c REQUIRE_VALID_CRL, \c BEST_EFFORT, and \c DISABLED revocation modes.
 * - \b x509revext.h: Extended revocation helpers for delta-CRL application and stapled OCSP
 *   verification; applies delta CRLs against a base CRL and validates OCSP staple tokens.
 * - \b x509ocsp.h: OCSP response parsing and online certificate status validation; decodes
 *   BasicOCSPResponse, verifies the responder signature, and maps the result to a
 *   \c qsc_x509_revocation_status value.
 * - \b x509aia.h: Decodes and queries the AuthorityInfoAccess and SubjectInfoAccess extensions;
 *   extracts OCSP responder URIs and CA Issuers URIs for online revocation and chain building.
 *
 * \b Key \b and \b Bundle \b Management:
 * - \b x509key.h: Private key decoding, size validation, and certificate-key matching for PKCS#8
 *   OneAsymmetricKey and SEC 1 ECPrivateKey structures covering ECDSA and ML-DSA key types.
 * - \b x509keywrite.h: Private key encoding and PEM conversion; serialises ECDSA and ML-DSA
 *   private keys to PKCS#8 DER or SEC 1 DER and wraps the result in PEM armour.
 * - \b x509pkcs12.h: PKCS#12 bundle parsing and encrypted private-key decryption; decodes PFX
 *   structures containing certificate chains and password-protected private keys using
 *   AES-256-CBC or 3DES.
 * - \b x509pem.h: PEM encoding for certificates, CRLs, CSRs, PKCS#8 private keys, SEC 1 EC
 *   keys, and ML-DSA/ML-KEM key types.
 *
 * \b Supported \b Certificate \b Signature \b Profiles:
 * | Profile                | Signature OID              | Public Key Type   | Parameter            |
 * |------------------------|----------------------------|-------------------|----------------------|
 * | ecdsa-with-SHA256      | 1.2.840.10045.4.3.2        | id-ecPublicKey    | prime256v1 (P-256)   |
 * | ecdsa-with-SHA384      | 1.2.840.10045.4.3.3        | id-ecPublicKey    | secp384r1  (P-384)   |
 * | ecdsa-with-SHA512      | 1.2.840.10045.4.3.4        | id-ecPublicKey    | secp521r1  (P-521)   |
 * | id-ML-DSA-44           | 2.16.840.1.101.3.4.3.17    | id-ML-DSA-44      | ML-DSA parameter 44  |
 * | id-ML-DSA-65           | 2.16.840.1.101.3.4.3.18    | id-ML-DSA-65      | ML-DSA parameter 65  |
 * | id-ML-DSA-87           | 2.16.840.1.101.3.4.3.19    | id-ML-DSA-87      | ML-DSA parameter 87  |
 *
 * \b ASN.1 \b and \b Encoding \b Infrastructure:
 * - \b encoding.h: Full BER and DER encode/decode engine with correct definite-length constructed
 *   element handling; Base64, hex, and PEM encoding primitives. Strict X.690 compliance:
 *   rejects indefinite-length encodings in DER contexts; enforces minimal INTEGER encoding;
 *   validates unused-bits fields in BIT STRINGs.
 * - \b asn1.h: Typed decoding helpers built on \c encoding.h; strict DER BOOLEAN enforcement
 *   (0x00 / 0xFF only); OID first-arc validation (arcs 0-2 per X.660); full 64-bit unsigned
 *   INTEGER support including 9-byte representations; sequence and set structural validators.
 * - \b oid.h: OID registry with encoded values, dotted-decimal names, and descriptive strings for
 *   all algorithm and extension identifiers used by the X.509 layer.
 * - \b x509types.h: Normalised in-memory structures for all X.509 objects; buffer constants sized
 *   for the largest current PQC profile (ML-DSA-87: 4627-byte signature, 2592-byte public key).
 *
 * \par System Utilities
 * \b Memory, \b Data, \b and \b File \b Management:
 * - \b memutils.h: SIMD-optimised memory operations: copy, clear, XOR, compare, and secure erase.
 * - \b arrayutils.h: Byte array manipulation and conversion utilities.
 * - \b stringutils.h: Safe string handling and conversion functions.
 * - \b intutils.h: Integer endian conversion, bit manipulation, and arithmetic helpers.
 * - \b donna128.h: Portable 128-bit integer arithmetic.
 * - \b fileutils.h: File I/O, size, existence, and path operations.
 * - \b folderutils.h: Directory creation, enumeration, and management.
 * - \b qsort.h: Constant-time and standard quicksort implementations.
 *
 * \b Encoding \b Utilities:
 * - \b encoding.h: BER/DER engine; Base64 encode/decode (RFC 4648); hex encode/decode; PEM
 *   encode/decode with header/footer label validation (RFC 7468).
 *
 * \b Networking:
 * - \b socket.h, socketbase.h, socketflags.h: Cross-platform TCP/IP socket primitives.
 * - \b netutils.h: Network address resolution and interface utilities.
 * - \b socketclient.h: Asynchronous TCP socket client.
 * - \b socketserver.h: High-performance asynchronous multi-threaded TCP socket server.
 * - \b ipinfo.h: Local and remote IP address information queries.
 *
 * \b Concurrency \b and \b System:
 * - \b async.h: Asynchronous task execution.
 * - \b threadpool.h: Managed thread pool for concurrent workloads.
 * - \b cpuidex.h: CPU feature detection (SIMD capability, cache topology, RDRAND availability).
 * - \b sysutils.h: OS version, memory, and processor statistics.
 * - \b timerex.h: High-resolution performance timers.
 * - \b timestamp.h: UTC and local timestamp generation.
 * - \b event.h: Synchronisation event primitives.
 * - \b consoleutils.h: Console input/output and formatting helpers.
 * - \b winutils.h: Windows-specific platform utilities.
 *
 * \b Data \b Structures:
 * - \b collection.h: Keyed generic collection (dictionary/map).
 * - \b list.h: Dynamic generic list.
 * - \b queue.h: Generic FIFO queue.
 *
 * \b Self-Test:
 * - \b selftest.h: Built-in integrity and performance verification routines for all cryptographic
 *   primitives.
 *
 * \par Architecture and Performance
 * QSC uses a dual implementation strategy for all performance-critical algorithms:
 * - \b Reference \b path: Clean, portable C23 code that compiles on any conforming compiler,
 *   providing a readable and auditable baseline.
 * - \b SIMD-optimised \b path: AVX, AVX2, and AVX-512 intrinsic implementations that activate
 *   automatically when the appropriate instruction set is enabled at compile time. Acceleration
 *   is applied across AES (AES-NI), RCS, CSX, SHA3/SHAKE/Keccak, ML-KEM, ML-DSA, Falcon,
 *   SLH-DSA, HQC, and all memory utility operations.
 *
 * The ECDSA P-256, P-384, and P-521 implementations use Jacobian projective coordinates with
 * the a=-3 doubling shortcut, Solinas reduction for field arithmetic, and Barrett reduction for
 * scalar arithmetic mod n. RFC 6979 deterministic nonce generation means no entropy source is
 * required during signing.
 *
 * \par Supported Platforms
 * QSC has been thoroughly tested on:
 * - Windows 10 / 11 / Server (Visual Studio 2022, MSVC v143+)
 * - Ubuntu Linux (GCC 11+)
 * - macOS (Apple Clang via Xcode 14+)
 *
 * \par References and Standards
 * - <b>NIST FIPS-202 (SHA-3/SHAKE):</b> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
 * - <b>NIST FIPS-203 (ML-KEM / Kyber):</b> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
 * - <b>NIST FIPS-204 (ML-DSA / Dilithium):</b> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf
 * - <b>NIST FIPS-205 (SLH-DSA / SPHINCS+):</b> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf
 * - <b>NIST FIPS-197 (AES):</b> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
 * - <b>NIST FIPS-180-4 (SHA-2):</b> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
 * - <b>NIST FIPS-186-5 (ECDSA):</b> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-5.pdf
 * - <b>NIST FIPS-198-1 (HMAC):</b> https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
 * - <b>NIST SP 800-38A/D (AES modes):</b> https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
 * - <b>RFC 5280 (X.509 Certificates):</b> https://www.rfc-editor.org/rfc/rfc5280
 * - <b>RFC 6125 (Hostname Verification):</b> https://www.rfc-editor.org/rfc/rfc6125
 * - <b>RFC 6960 (OCSP):</b> https://www.rfc-editor.org/rfc/rfc6960
 * - <b>RFC 6979 (Deterministic ECDSA):</b> https://www.rfc-editor.org/rfc/rfc6979
 * - <b>RFC 7468 (PEM Formats):</b> https://www.rfc-editor.org/rfc/rfc7468
 * - <b>RFC 7748 (X25519 / ECDH):</b> https://www.rfc-editor.org/rfc/rfc7748
 * - <b>RFC 8032 (EdDSA / Ed25519):</b> https://www.rfc-editor.org/rfc/rfc8032
 * - <b>RFC 8422 (ECDSA in TLS):</b> https://www.rfc-editor.org/rfc/rfc8422
 * - <b>ITU-T X.660 (OID arcs):</b> https://www.itu.int/rec/T-REC-X.660
 * - <b>ITU-T X.690 (DER/BER encoding):</b> https://www.itu.int/rec/T-REC-X.690
 * - <b>PKCS#10 (CSR format):</b> https://www.rfc-editor.org/rfc/rfc2986
 * - <b>PKCS#12 (PFX bundles):</b> https://www.rfc-editor.org/rfc/rfc7292
 * - <b>Classic McEliece Specification:</b> https://www.randombit.net/mceliece/mceliece-spec.pdf
 * - <b>ChaCha Stream Cipher:</b> https://cr.yp.to/chacha/chacha-20080120.pdf
 * - <b>Intel CPUID Reference:</b> https://software.intel.com/content/www/us/en/develop/articles/intel-64-architecture-cpuid-instruction.html
 * - <b>Intel Intrinsics Guide:</b> https://www.intel.com/content/www/us/en/develop/documentation/intrinsics-guide/
 *
 * \par Keywords
 * Cryptography, Post-Quantum, Asymmetric Cryptography, Symmetric Cryptography, Digital Signature,
 * Key Encapsulation, Key Exchange, Hash Function, MAC, DRBG, Entropy, X.509, PKI, TLS, CRL, OCSP,
 * PKCS10, PKCS12, ASN.1, DER, BER, PEM, OID, ML-KEM, ML-DSA, SLH-DSA, Falcon, McEliece, HQC,
 * ECDSA, ECDH, EdDSA, AES, ChaCha20, SIMD, AVX, AVX2, AVX512, Secure Memory, MISRA, QSC.
 *
 * \par Example
 * Refer to the module-specific headers (e.g., aes.h, sha3.h, kyber.h, dilithium.h, falcon.h,
 * ecdsa.h, ecdh.h, x509cert.h, x509verify.h, x509pem.h, etc.) for detailed usage examples
 * and API documentation.
 *
 * \remarks
 * QSC is designed to serve as the foundational cryptographic solution for secure, post-quantum
 * communications and is continuously updated to incorporate emerging cryptographic research and
 * standards. The X.509 layer is intentionally structured so that structural and policy checks
 * remain independent of the cryptographic backend, enabling straightforward extension to new
 * signature algorithm profiles as post-quantum standards evolve.
 *
 * QRCS-PREL License. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 *
 * \author John G. Underhill
 * \date 2026-03-28
 * \version 1.1.0.2b
 */

#endif
