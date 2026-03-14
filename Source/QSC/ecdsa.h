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

#ifndef QSC_ECDSA_H
#define QSC_ECDSA_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file ecnistp256.h
 * \brief Contains the primary public API for the ECDSA asymmetric signature scheme
 *        implementation over the NIST P-256 (secp256r1) elliptic curve.
 *
 * \details
 * This header defines the API for ECDSA operating over the NIST P-256 elliptic curve
 * (also known as secp256r1 or prime256v1).  It provides functions for generating key
 * pairs (either randomly or via a seeded generator), signing messages, and verifying
 * signatures.  The implementation is interoperable with TLS 1.2/1.3, X.509 certificates
 * issued by public CAs, and the CA/Browser Forum Baseline Requirements.
 *
 * \par Key and signature encoding:
 * All external byte arrays use big-endian encoding compatible with X9.62 / SEC 1:
 * - Public key:  64 bytes  – uncompressed point coordinates (Qx[32] || Qy[32]),
 *                            no 0x04 prefix.
 * - Private key: 96 bytes  – seed[32] || Qx[32] || Qy[32].
 * - Signature:   64 bytes  – (r[32] || s[32]), prepended to the message in
 *                            the signedmsg buffer.
 *
 * Signing uses a deterministic nonce generated per RFC 6979 (HMAC-SHA256), so no
 * entropy source is required during the signing operation.
 *
 * \par Example:
 * \code
 * // Key-pair creation, signing, and verification using ECDSA over P-256
 * #define MSGLEN 32
 * uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_ECDSA_PRIVATEKEY_SIZE];
 * uint8_t msg[MSGLEN];
 * uint8_t smsg[QSC_ECDSA_SIGNATURE_SIZE + MSGLEN];
 * uint8_t rmsg[MSGLEN];
 * size_t  smsglen = 0;
 * size_t  rmsglen = 0;
 *
 * // Generate key pair from a random seed
 * qsc_ecdsa_generate_keypair(pk, sk, my_rng_function);
 *
 * // Sign: signature is prepended to the message
 * qsc_ecdsa_sign(smsg, &smsglen, msg, MSGLEN, sk);
 *
 * // Verify: recovers the message on success
 * if (qsc_ecdsa_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
 * {
 *     // Authentication failed
 * }
 * \endcode
 *
 * \remarks
 * P-256 is defined by NIST in FIPS 186-4 (Digital Signature Standard) and is the
 * curve required by the CA/Browser Forum Baseline Requirements for publicly trusted
 * TLS certificates.  The field prime is p = 2^256 - 2^224 + 2^192 + 2^96 - 1 and
 * the group order is n = 2^256 - 2^128 - 2^96 + 2^32 * … (see FIPS 186-4 D.1.2.3).
 *
 * \section ecnistp256_links Reference Links
 *  - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf">FIPS 186-4 Digital Signature Standard</a>
 *  - <a href="https://www.secg.org/sec1-v2.pdf">SEC 1: Elliptic Curve Cryptography (Certicom)</a>
 *  - <a href="https://www.rfc-editor.org/rfc/rfc6979">RFC 6979: Deterministic Usage of DSA/ECDSA</a>
 *  - <a href="https://www.rfc-editor.org/rfc/rfc8422">RFC 8422: ECC Cipher Suites for TLS</a>
 */

#define QSC_ECDSA_S1EC256

#if defined(QSC_ECDSA_S1EC256)

/*!
 * \def QSC_ECDSA_SIGNATURE_SIZE
 * \brief The byte size of the signature array (r[32] || s[32]).
 */
#	define QSC_ECDSA_SIGNATURE_SIZE 64U

/*!
 * \def QSC_ECDSA_PRIVATEKEY_SIZE
 * \brief The byte size of the private key array (seed[32] || Qx[32] || Qy[32]).
 */
#	define QSC_ECDSA_PRIVATEKEY_SIZE 96U

/*!
 * \def QSC_ECDSA_PUBLICKEY_SIZE
 * \brief The byte size of the public key array (Qx[32] || Qy[32], big-endian).
 */
#	define QSC_ECDSA_PUBLICKEY_SIZE 64U

#else
#	error "The ECNISTP256 parameter set is invalid!  Define QSC_ECDSA_S1EC256."
#endif

/*!
 * \def QSC_ECDSA_SEED_SIZE
 * \brief The byte size of the random seed / private scalar input array.
 */
#define QSC_ECDSA_SEED_SIZE 32ULL

/*!
 * \def QSC_ECDSA_ALGNAME
 * \brief The formal algorithm name.
 */
#define QSC_ECDSA_ALGNAME "ECDSAP256"
/*!
 * \brief SEC 1 uncompressed EC point byte length for P-256.
 */
#define QSC_ECDSA_SEC1_PUBLICKEY_SIZE 65U

/*!
 * \brief SubjectPublicKeyInfo DER byte length for id-ecPublicKey + secp256r1.
 */
#define QSC_ECDSA_SPKI_DER_SIZE 91U

/*!
 * \brief Maximum DER-encoded ECDSA signature size for P-256.
 */
#define QSC_ECDSA_SIGNATURE_DER_MAX_SIZE 72U

/**
 * \brief Convert a raw public key (Qx || Qy) to SEC 1 uncompressed point form.
 *
 * \param secpub:		[uint8_t*] Output buffer of 65 bytes.
 * \param publickey:	[const uint8_t*] Input raw public key of 64 bytes.
 */
QSC_EXPORT_API void qsc_ecdsa_publickey_to_sec1(uint8_t* secpub, const uint8_t* publickey);

/**
 * \brief Derive a P-256 public key from a raw private scalar.
 *
 * \details
 * This function derives the affine public point Q = dG from a 32-byte
 * big-endian private scalar and serializes the result as the raw public-key
 * form Qx || Qy.
 *
 * The private scalar must be in the range [1, n - 1], where n is the order
 * of the P-256 base point.
 *
 * \param publickey:	[uint8_t*] Output buffer receiving the 64-byte public key.
 * \param privatekey:	[const uint8_t*] Input 32-byte private scalar.
 *
 * \return				[int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsa_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Convert a SEC 1 uncompressed point to the library raw public-key form.
 *
 * \param publickey:	[uint8_t*] Output raw public key of 64 bytes.
 * \param secpub:		[const uint8_t*] Input SEC 1 public key of 65 bytes.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_publickey_from_sec1(uint8_t* publickey, const uint8_t* secpub);

/**
 * \brief Decode an X.509 SubjectPublicKeyInfo DER value for secp256r1.
 *
 * \param publickey:	[uint8_t*] Output raw public key of 64 bytes.
 * \param spkider:		[const uint8_t*] Input DER buffer.
 * \param spkilen:		[size_t] Input DER length in bytes.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_publickey_from_spki(uint8_t* publickey, const uint8_t* spkider, size_t spkilen);

/**
 * \brief Encode a raw public key (Qx || Qy) as X.509 SubjectPublicKeyInfo DER.
 *
 * \param spkider:		[uint8_t*] Output buffer of 91 bytes.
 * \param publickey:	[const uint8_t*] Input raw public key of 64 bytes.
 */
QSC_EXPORT_API void qsc_ecdsa_publickey_to_spki(uint8_t* spkider, const uint8_t* publickey);

/**
 * \brief Encode a raw ECDSA signature (r || s) as ASN.1 DER.
 *
 * \param dersig:		[uint8_t*] Output DER buffer of at least 72 bytes.
 * \param derlen:		[size_t*] Output DER length.
 * \param signature:	[const uint8_t*] Input raw signature of 64 bytes.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_signature_to_der(uint8_t* dersig, size_t* derlen, const uint8_t* signature);

/**
 * \brief Decode an ASN.1 DER ECDSA signature into raw form (r || s).
 *
 * \param signature:	[uint8_t*] Output raw signature of 64 bytes.
 * \param dersig:		[const uint8_t*] Input DER signature buffer.
 * \param derlen:		[size_t] Input DER length.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_signature_from_der(uint8_t* signature, const uint8_t* dersig, size_t derlen);

/**
 * \brief Generate a P-256 public/private key pair from a 32-byte seed.
 *
 * \details
 * Derives the private scalar d = SHA-256(seed) mod n, computes the public key
 * Q = d*G, and stores both.  This function is deterministic: the same seed
 * always produces the same key pair.
 *
 * \warning Arrays must be sized to QSC_ECDSA_PUBLICKEY_SIZE and
 *          QSC_ECDSA_PRIVATEKEY_SIZE respectively.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public verification-key array.
 * \param privatekey:	[uint8_t*] Pointer to the output private signature-key array.
 * \param seed:			[const uint8_t*] Pointer to the random 32-byte seed array.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Generate a P-256 public/private key pair using a caller-supplied RNG.
 *
 * \details
 * Fills a 32-byte seed from rng_generate, then calls
 * qsc_ecdsa_generate_seeded_keypair.  The seed is erased from stack
 * memory before returning.
 *
 * \warning Arrays must be sized to QSC_ECDSA_PUBLICKEY_SIZE and
 *          QSC_ECDSA_PRIVATEKEY_SIZE respectively.
 *
 * \param publickey:	[uint8_t*] Pointer to the public verification-key array.
 * \param privatekey:	[uint8_t*] Pointer to the private signature-key array.
 * \param rng_generate: [bool(*)(uint8_t*, size_t)] Pointer to the random generator function.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Sign a message with a P-256 private key.
 *
 * \details
 * Computes a deterministic ECDSA signature (RFC 6979, HMAC-SHA256) over the
 * SHA-256 digest of the message, then writes the 64-byte signature followed by
 * the message into signedmsg. On success *smsglen = msglen + 64.
 *
 * \warning signedmsg must be at least msglen + QSC_ECDSA_SIGNATURE_SIZE bytes.
 *
 * \param signedmsg:	[uint8_t*] Pointer to the signed-message output array.
 * \param smsglen:		[size_t*] Pointer to the signed-message length output.
 * \param message:		[const uint8_t*] Pointer to the message to sign.
 * \param msglen:		[size_t] Message length in bytes.
 * \param privatekey:	[const uint8_t*] Pointer to the 96-byte private key array.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Sign a message with a P-256 private key, used primarily for RFC KAT testing).
 *
 * \details
 * Computes a deterministic ECDSA signature using the private key scalar d, 
 * (RFC KATs) then writes the 64-byte signature followed by
 * the message into signedmsg. On success *smsglen = msglen + 64.
 *
 * \warning signedmsg must be at least msglen + QSC_ECDSA_SIGNATURE_SIZE bytes.
 *
 * \param signedmsg:	[uint8_t*] Pointer to the signed-message output array.
 * \param smsglen:		[size_t*] Pointer to the signed-message length output.
 * \param message:		[const uint8_t*] Pointer to the message to sign.
 * \param msglen:		[size_t] Message length in bytes.
 * \param privatekey:	[const uint8_t*] Pointer to the 96-byte private key array.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdsa_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verify a P-256 ECDSA signature and recover the message.
 *
 * \details
 * Parses the 64-byte signature prepended to signedmsg, validates r and s are
 * in [1, n-1], verifies that the public key lies on the curve, and checks the
 * ECDSA equation.  On success the message bytes are copied into message and
 * *msglen is set.  On failure message is zeroed and *msglen is set to 0.
 *
 * \param message:		[uint8_t*] Pointer to the recovered message output array.
 * \param msglen:		[size_t*] Pointer to the recovered message length.
 * \param signedmsg:	[const uint8_t*] Pointer to the signed-message input array.
 * \param smsglen:		[size_t] Total signed-message length (signature + message).
 * \param publickey:	[const uint8_t*] Pointer to the 64-byte public verification-key array.
 * \return				[bool] Returns true if the signature is valid, false otherwise.
 */
QSC_EXPORT_API bool qsc_ecdsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
