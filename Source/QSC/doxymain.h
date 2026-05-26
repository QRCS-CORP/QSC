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

 /*! \mainpage QSC: Quantum Secure Cryptographic Solutions Library Version 1.2
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
  * The QSC Library provides a comprehensive suite of cryptographic algorithms, a complete
  * RFC 8446 TLS 1.3 protocol stack, a complete X.509 certificate infrastructure, and a broad
  * set of system utilities:
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
  * - \b SHA2: SHA2-256, SHA2-384, and SHA2-512 (FIPS-180-4).
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
  * \par TLS 1.3 Protocol Stack
  * QSC includes a complete, dependency-free TLS 1.3 implementation conforming to RFC 8446.
  * The stack is designed specifically to support hybrid post-quantum key exchange, combining
  * classical ECDH with ML-KEM encapsulation in a single handshake flight. It integrates
  * directly with the QSC X.509 certificate infrastructure, key schedule, and record-layer
  * AEAD primitives, and exposes a clean engine interface that is independent of any
  * particular socket or I/O framework.
  *
  * \b Protocol \b Coverage:
  * The TLS 1.3 stack implements the full RFC 8446 protocol surface:
  * - 1-RTT certificate-authenticated handshake (client and server)
  * - Mutual TLS (mTLS): server-initiated CertificateRequest and client certificate validation
  * - PSK resumption: 1-RTT and 0-RTT (early data) paths with NewSessionTicket emission and
  *   consumption, binder computation, and early-data EndOfEarlyData sequencing
  * - HelloRetryRequest: server-initiated group renegotiation with transcript message_hash
  *   transform per RFC 8446 section 4.4.1
  * - Post-handshake KeyUpdate: both update_not_requested and update_requested flows,
  *   with mandatory reciprocal update enforcement
  * - Post-handshake NewSessionTicket: server emission and client consumption with resumption
  *   PSK derivation from resumption_master_secret
  * - Encrypted close_notify alert construction and dispatch
  * - Compatibility ChangeCipherSpec record pass-through
  *
  * \b Cipher \b Suites:
  * | Identifier                        | IANA Value | Hash   |
  * |-----------------------------------|------------|--------|
  * | TLS_AES_128_GCM_SHA256            | 0x1301     | SHA-256 |
  * | TLS_AES_256_GCM_SHA384            | 0x1302     | SHA-384 |
  * | TLS_CHACHA20_POLY1305_SHA256      | 0x1303     | SHA-256 |
  *
  * \b Named \b Groups \b and \b Hybrid \b Key \b Exchange:
  * The group layer (tlsgroups.h) abstracts classical, pure-KEM, and hybrid named groups
  * behind a uniform descriptor and key-exchange interface. Hybrid groups concatenate the
  * ECDH shared secret with the ML-KEM shared secret in the order defined by
  * draft-ietf-tls-hybrid-design and pass the combined value as the DHE input to
  * HKDF-Extract. All key-share sizes are enforced at compile time via static assertions
  * in tlslimits.h.
  *
  * | Group                    | IANA Value | Classical     | PQC Component  |
  * |--------------------------|------------|---------------|----------------|
  * | secp256r1                | 0x0017     | P-256 ECDH    | -              |
  * | secp384r1                | 0x0018     | P-384 ECDH    | -              |
  * | secp521r1                | 0x0019     | P-521 ECDH    | -              |
  * | x25519                   | 0x001D     | X25519        | -              |
  * | x448                     | 0x001E     | X448          | -              |
  * | ML-KEM-512               | 0x0200     | -             | ML-KEM-512     |
  * | ML-KEM-768               | 0x0201     | -             | ML-KEM-768     |
  * | ML-KEM-1024              | 0x0202     | -             | ML-KEM-1024    |
  * | x25519 + ML-KEM-512      | 0x11EB     | X25519        | ML-KEM-512     |
  * | x25519 + ML-KEM-768      | 0x11EC     | X25519        | ML-KEM-768     |
  * | secp256r1 + ML-KEM-768   | 0x11ED     | P-256 ECDH    | ML-KEM-768     |
  * | secp384r1 + ML-KEM-1024  | 0x11EE     | P-384 ECDH    | ML-KEM-1024    |
  * | x25519 + ML-KEM-1024     | 0x11EF     | X25519        | ML-KEM-1024    |
  * | secp256r1 + ML-KEM-512   | 0x11F0     | P-256 ECDH    | ML-KEM-512     |
  * | secp256r1 + ML-KEM-1024  | 0x11F1     | P-256 ECDH    | ML-KEM-1024    |
  * | secp384r1 + ML-KEM-768   | 0x11F2     | P-384 ECDH    | ML-KEM-768     |
  *
  * \b Signature \b Schemes:
  * | Scheme                     | IANA Value | Standard        |
  * |----------------------------|------------|-----------------|
  * | ecdsa_secp256r1_sha256     | 0x0403     | FIPS 186-5      |
  * | ecdsa_secp384r1_sha384     | 0x0503     | FIPS 186-5      |
  * | ed25519                    | 0x0807     | RFC 8032        |
  * | ML-DSA-44                  | 0x0904     | NIST FIPS-204   |
  * | ML-DSA-65                  | 0x0905     | NIST FIPS-204   |
  * | ML-DSA-87                  | 0x0906     | NIST FIPS-204   |
  *
  * \b Key \b Schedule \b (tlskeyschedule.h):
  * Implements the full RFC 8446 section 7.1 key schedule:
  * - HKDF-Extract and HKDF-Expand-Label with label-length bounds checked at call time
  *   and verified against a 514-byte stack-allocated info buffer
  * - Derive-Secret for early, handshake, application, exporter, and resumption epochs
  * - Early secret extraction from PSK or zero IKM
  * - Handshake secret extraction from DHE shared secret
  * - Master secret derivation from zero IKM
  * - Client and server handshake traffic secret derivation from the CH..SH transcript hash
  * - Client and server application traffic secret derivation from the CH..SF transcript hash
  * - Traffic key and IV derivation via HKDF-Expand-Label("key") and ("iv")
  * - Write-side traffic-secret rotation for KeyUpdate via HKDF-Expand-Label("traffic upd")
  * - Finished MAC computation and constant-time verification using qsc_intutils_verify
  * - Binder key derivation, binder computation, and PSK binder patching for 0-RTT
  * - CertificateVerify input construction (64-byte pad + context string + 0x00 + transcript hash)
  * - Resumption PSK derivation from resumption_master_secret and ticket nonce
  *
  * \b Record \b Layer \b (tlsrecord.h):
  * Implements RFC 8446 section 5 TLSPlaintext and TLSCiphertext record framing:
  * - Plaintext record encode and decode with content-type and length validation
  * - AEAD encryption (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) of TLSInnerPlaintext
  *   structures with per-record nonce construction via XOR of static IV and 64-bit sequence counter
  * - Constant-time inner content-type byte scanning using a mask-select backward scan
  *   that does not branch on payload byte values
  * - Sequence overflow enforcement: the 64-bit counter is checked for UINT64_MAX exhaustion
  *   before encryption or decryption begins, ensuring no record is ever processed under
  *   an exhausted nonce space (RFC 8446 section 5.5)
  * - Atomic key installation with secure erasure of prior key material on epoch transitions
  *   and KeyUpdate rotations
  * - Legacy record version field is accepted as-is on receive per RFC 8446 section 5.1;
  *   the outbound legacy_record_version is set to 0x0303 on all records
  *
  * \b Transcript \b Hash \b (tlstranscript.h):
  * - Running SHA-256, SHA-384, or SHA-512 transcript hash maintained without copies
  * - Snapshot operation clones the internal hash state to produce an intermediate digest
  *   without disturbing the running hash; the clone is erased with secure_erase on return
  * - HelloRetryRequest message_hash transform: snapshots the CH1 transcript, reinitializes
  *   the hash, then injects a synthetic HandshakeType 254 (message_hash) header followed by
  *   the snapshot digest, per RFC 8446 section 4.4.1
  *
  * \b Extensions \b (tlsextensions.h):
  * Encode and decode functions for all TLS 1.3 extensions used in ClientHello,
  * ServerHello, HelloRetryRequest, and EncryptedExtensions messages:
  * - supported_versions (client list and server selected-version forms)
  * - supported_groups and key_share (client offer and server response, including
  *   HelloRetryRequest key_share with a single requested group)
  * - signature_algorithms
  * - server_name (SNI)
  * - pre_shared_key (offer with binder placeholder and server selection index)
  * - psk_key_exchange_modes
  * - early_data (empty EncryptedExtensions confirmation and ClientHello request)
  * - NewSessionTicket early_data max_early_data_size field
  *
  * \b Handshake \b Messages \b (tlshandshake.h):
  * Encode and decode helpers for all RFC 8446 handshake message body types:
  * ClientHello, ServerHello, EncryptedExtensions, Certificate, CertificateRequest,
  * CertificateVerify, Finished, KeyUpdate, NewSessionTicket, and EndOfEarlyData.
  * The 4-byte handshake header (type + 24-bit length) is produced and consumed by
  * uniform read/write header helpers used throughout the client and server state machines.
  *
  * \b Codec \b (tlscodec.h):
  * All record and message serialization is performed through bounds-checked read and
  * write helpers (u8, u16, u24, u32, bytes, vector8, vector16). Every access is
  * guarded by a can_read / can_write check before any array indexing. No direct
  * pointer arithmetic is performed without a prior length validation.
  *
  * \b Alert \b and \b Error \b Handling \b (tlsalert.h, tlserrors.h):
  * The full RFC 8446 alert description enumeration is defined in tlstypes.h.
  * Alert records are encoded and dispatched through the record layer. The client and
  * server state machines record the last observed or generated alert in their state
  * structures and propagate error codes through the engine interface.
  *
  * \b Signature \b Binding \b (tlssigalgs.h, tlssignerdefault.h):
  * The TLS layer uses a caller-supplied certificate interface structure
  * (qsc_tls_certificate_interface) to decouple the handshake from the certificate
  * store and signing back-end. The default signer trampolines in tlssignerdefault.h
  * connect this interface to the QSC ECDSA (P-256, P-384), Ed25519, and ML-DSA
  * (44, 65, 87) signing APIs. The verifycertificateverify callback is mandatory;
  * the engine returns an internal_error alert if it is absent.
  *
  * \b Certificate \b Integration \b (tlscert.h, tlscertx509.h):
  * The TLS certificate layer decodes X.509 certificate chains received in Certificate
  * messages and presents them to the caller-supplied chain validation callback. The
  * layer preserves raw DER spans for signature verification without re-serialisation
  * and is integrated with the full QSC X.509 verification infrastructure.
  *
  * \b Session \b Resumption \b (tlssession.h):
  * Session tickets are represented as qsc_tls_session_ticket structures carrying the
  * ticket opaque bytes, nonce, age-add value, lifetime, associated cipher suite, and
  * the per-ticket resumption PSK. The engine provides serialization and deserialization
  * helpers for persistent storage and transport of ticket material.
  *
  * \b Engine \b Interface \b (tlsengine.h):
  * The engine wraps the client and server state machines behind a unified
  * qsc_tls_connection handle. It provides:
  * - qsc_tls_engine_initialize_client / qsc_tls_engine_initialize_server
  * - qsc_tls_engine_handshake: drives the handshake state machine from any phase
  * - qsc_tls_engine_write_application_data: encrypts and frames application records
  * - qsc_tls_engine_read_application_data: decrypts inbound records
  * - qsc_tls_engine_read_application_data_ex: decrypts and dispatches post-handshake
  *   messages (KeyUpdate, NewSessionTicket)
  * - qsc_tls_engine_request_key_update: initiates a local KeyUpdate
  * - qsc_tls_engine_emit_session_ticket: server-side NewSessionTicket emission
  * - qsc_tls_engine_consume_session_ticket: client-side NewSessionTicket consumption
  * - qsc_tls_engine_close: emits an encrypted close_notify record
  * - qsc_tls_engine_dispose: zeroizes all keying material and transient state
  *
  * \b I/O \b Adapter \b (tlsio.h):
  * A thin blocking-socket adapter (qsc_tls_io_connection) binds a qsc_tls_connection
  * to a qsc_socket and marshals bytes between the engine record interface and the QSC
  * socket API. It provides qsc_tls_io_handshake, qsc_tls_io_send, qsc_tls_io_receive,
  * and qsc_tls_io_shutdown. The adapter imposes a maximum handshake round-trip count
  * to prevent unbounded looping on malicious HelloRetryRequest sequences.
  *
  * \b Compile-time \b Safety \b (tlslimits.h):
  * All buffer capacity relationships (key-share sizes, hybrid key-share sizes, extension
  * maximum sizes, private key sizes, signature sizes, and cipher suite sizes) are
  * enforced by negative-size-array typedef assertions. Any change to an algorithm
  * parameter set that violates a capacity invariant produces a compile-time error
  * before any runtime code is produced.
  *
  * \b Security \b Properties:
  * - Forward secrecy: all session keys are derived from ephemeral key exchange material
  *   that is erased after the handshake epoch
  * - Hybrid post-quantum forward secrecy: the DHE input to HKDF-Extract is the
  *   concatenation of the classical ECDH shared secret and the ML-KEM shared secret;
  *   an attacker must break both to recover session keys
  * - Constant-time MAC verification: the Finished MAC is verified using
  *   qsc_intutils_verify, which XOR-accumulates all bytes without early exit
  * - Constant-time inner content-type scanning: the backward byte scan uses
  *   mask-select operations with no data-dependent branches
  * - Secure erasure: all traffic keys, transcript states, shared secrets, and
  *   handshake buffers are cleared with qsc_memutils_secure_erase at disposal;
  *   key material written during epoch transitions is erased before overwrite
  * - Version downgrade protection: the client verifies that supported_versions is
  *   present in ServerHello and that the selected version is exactly TLS 1.3 (0x0304);
  *   absence or a non-TLS-1.3 selection causes immediate rejection with the
  *   appropriate alert (missing_extension or illegal_parameter)
  * - Unknown extension rejection: any extension present in ServerHello that was not
  *   offered in ClientHello is rejected with unsupported_extension per RFC 8446 section 4.2
  * - Sequence exhaustion: the 64-bit record sequence counter is checked for UINT64_MAX
  *   before any AEAD operation, terminating the connection before nonce reuse can occur
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
  *   into typed attribute lists; supports multi-valued RDNs; RFC 5280 7.1 canonical comparison
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
  * - \b intutils.h: Integer endian conversion, bit manipulation, arithmetic helpers, and
  *   constant-time comparison via qsc_intutils_verify.
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
  * The TLS 1.3 engine is designed for minimal allocation: the record layer heap-allocates only
  * the TLSInnerPlaintext scratch buffer (one allocation per encrypt or decrypt call) and all
  * other working state lives in caller-supplied stack or heap structures. The engine does not
  * retain any persistent state between calls beyond what is stored in the qsc_tls_connection
  * or its embedded client/server state.
  *
  * \par Supported Platforms
  * QSC has been thoroughly tested on:
  * - Windows 10 / 11 / Server (Visual Studio 2022, MSVC v143+)
  * - Ubuntu Linux (GCC 11+)
  * - macOS (Apple Clang via Xcode 14+)
  *
  * \par References and Standards
  * - <b>RFC 8446 (TLS 1.3):</b> https://www.rfc-editor.org/rfc/rfc8446
  * - <b>draft-ietf-tls-hybrid-design (Hybrid Key Exchange):</b> https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/
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
  * - <b>RFC 5869 (HKDF):</b> https://www.rfc-editor.org/rfc/rfc5869
  * - <b>RFC 6125 (Hostname Verification):</b> https://www.rfc-editor.org/rfc/rfc6125
  * - <b>RFC 6960 (OCSP):</b> https://www.rfc-editor.org/rfc/rfc6960
  * - <b>RFC 6979 (Deterministic ECDSA):</b> https://www.rfc-editor.org/rfc/rfc6979
  * - <b>RFC 7468 (PEM Formats):</b> https://www.rfc-editor.org/rfc/rfc7468
  * - <b>RFC 7748 (X25519 / ECDH):</b> https://www.rfc-editor.org/rfc/rfc7748
  * - <b>RFC 8032 (EdDSA / Ed25519):</b> https://www.rfc-editor.org/rfc/rfc8032
  * - <b>RFC 8422 (ECDSA in TLS):</b> https://www.rfc-editor.org/rfc/rfc8422
  * - <b>ITU-T X.660 (OID arcs):</b> https://www.itu.int32_t/rec/T-REC-X.660
  * - <b>ITU-T X.690 (DER/BER encoding):</b> https://www.itu.int32_t/rec/T-REC-X.690
  * - <b>PKCS#10 (CSR format):</b> https://www.rfc-editor.org/rfc/rfc2986
  * - <b>PKCS#12 (PFX bundles):</b> https://www.rfc-editor.org/rfc/rfc7292
  * - <b>Classic McEliece Specification:</b> https://www.randombit.net/mceliece/mceliece-spec.pdf
  * - <b>ChaCha Stream Cipher:</b> https://cr.yp.to/chacha/chacha-20080120.pdf
  * - <b>Intel CPUID Reference:</b> https://software.intel.com/content/www/us/en/develop/articles/intel-64-architecture-cpuid-instruction.html
  * - <b>Intel Intrinsics Guide:</b> https://www.intel.com/content/www/us/en/develop/documentation/intrinsics-guide/
  *
  * \par Keywords
  * Cryptography, Post-Quantum, Asymmetric Cryptography, Symmetric Cryptography, Digital Signature,
  * Key Encapsulation, Key Exchange, Hash Function, MAC, DRBG, Entropy, X.509, PKI,
  * TLS, TLS 1.3, RFC 8446, Hybrid Key Exchange, Post-Quantum TLS, Key Schedule, HKDF,
  * Record Layer, AEAD, KeyUpdate, NewSessionTicket, PSK, 0-RTT, HelloRetryRequest,
  * CRL, OCSP, PKCS10, PKCS12, ASN.1, DER, BER, PEM, OID,
  * ML-KEM, ML-DSA, SLH-DSA, Falcon, McEliece, HQC,
  * ECDSA, ECDH, EdDSA, AES, ChaCha20, SIMD, AVX, AVX2, AVX512,
  * Secure Memory, Constant-Time, Forward Secrecy, MISRA, QSC.
  *
  * \par Example
  * Refer to the module-specific headers for detailed usage examples and API documentation.
  * For the TLS 1.3 stack, start with tlsengine.h for the connection lifecycle,
  * tlsclient.h and tlsserver.h for the handshake state machines, tlsio.h for the
  * socket adapter, and tlsgroups.h for the supported named-group and hybrid-group
  * descriptors. For the cryptographic layer, see aes.h, sha3.h, kyber.h, dilithium.h,
  * falcon.h, ecdsa.h, ecdh.h, and the X.509 headers x509cert.h, x509verify.h, x509pem.h.
  *
  * \remarks
  * QSC is designed to serve as the foundational cryptographic solution for secure, post-quantum
  * communications and is continuously updated to incorporate emerging cryptographic research and
  * standards. The TLS 1.3 stack is structured so that the key schedule, record layer, transcript
  * hash, group descriptors, certificate binding, and I/O adapter are independently testable
  * components; each layer can be driven directly from unit tests without instantiating a full
  * client/server handshake. The X.509 layer is intentionally structured so that structural and
  * policy checks remain independent of the cryptographic backend, enabling straightforward
  * extension to new signature algorithm profiles as post-quantum standards evolve.
  *
  * QRCS-PREL License. See license file for details.
  * All rights reserved by QRCS Corporation, copyrighted and patents pending.
  *
  * \author John G. Underhill
  * \date 2026-05-01
  * \version 1.3.0.0
  */

#endif
