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

 /* Implementation acknowledgements:
 *
 * This QRCS implementation was developed with reference to the
 * Botan cryptographic library, established cryptographic research,
 * applicable NIST and IETF standards, and published algorithms.
 *
 * The implementation has been adapted and optimized for the QSC
 * architecture, including its arithmetic engines, memory management,
 * platform-specific acceleration, and security requirements.
 *
 * Reference: Botan Cryptographic Library
 * https://botan.randombit.net/
 *
 * Copyright and licensing of third-party derived material remain
 * subject to the applicable original license terms.
 */

#ifndef QSC_ECDSAP384_H
#define QSC_ECDSAP384_H

#include "qsccommon.h"

/* \cond DOXYGEN_NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/*! \def QSC_ECDSAP384_DISABLE_ASM
 * \brief Define to select intrinsic or portable arithmetic instead of inline assembly.
 * \details The former QSC_P384V2_DISABLE_ASM spelling remains accepted.
 */
#if defined(QSC_P384V2_DISABLE_ASM) && !defined(QSC_ECDSAP384_DISABLE_ASM)
#	define QSC_ECDSAP384_DISABLE_ASM
#endif

/*!
 * \file ecdsap384.h
 * \brief Public API for NIST P-384 (secp384r1) ECDSA operations.
 *
 * \details
 * This header defines the public functions for NIST P-384 (secp384r1) ECDSA operations,
 * including key pair generation from a seed, deterministic message signing using RFC 6979,
 * and signature verification. The implementation uses Jacobian projective coordinates for
 * elliptic curve point arithmetic, Solinas prime-field reduction, and Montgomery group-order
 * arithmetic. Native wide multiplication is used when available; fixed-width partial
 * products provide a portable fallback.
 *
 * Key and signature encoding is big-endian and compatible with X9.62/SEC 1 conventions:
 * - Public key: 96 bytes (48-byte X || 48-byte Y, uncompressed, no 0x04 prefix)
 * - Private key: 48-byte seed || 96-byte public key = 144 bytes
 * - Signature: 48-byte r || 48-byte s
 */

/*! 
* \def EC_NISTP384_SEED_SIZE
* \brief Seed and derived scalar byte length 
*/
#define EC_NISTP384_SEED_SIZE 48U

/*!
* \def EC_NISTP384_PUBLICKEY_SIZE
* \brief Public key byte length (X || Y, each 48 bytes big-endian) 
*/
#define EC_NISTP384_PUBLICKEY_SIZE 96U

/*! 
* \def EC_NISTP384_PRIVATEKEY_SIZE
* \brief Private key byte length (seed[48] || pubkey[96]) 
*/
#define EC_NISTP384_PRIVATEKEY_SIZE 144U

/*!
* \def EC_NISTP384_SIGNATURE_SIZE
* \brief Signature byte length (r[48] || s[48], big-endian) 
*/
#define EC_NISTP384_SIGNATURE_SIZE 96U

/*! \def QSC_ECDSAP384_SEED_SIZE
 * \brief ECDSA P-384 seed size in bytes.
 */
#define QSC_ECDSAP384_SEED_SIZE EC_NISTP384_SEED_SIZE

/*! \def QSC_ECDSAP384_PUBLICKEY_SIZE
 * \brief ECDSA P-384 publickey size in bytes.
 */
#define QSC_ECDSAP384_PUBLICKEY_SIZE EC_NISTP384_PUBLICKEY_SIZE

/*! \def QSC_ECDSAP384_PRIVATEKEY_SIZE
 * \brief ECDSA P-384 privatekey size in bytes.
 */
#define QSC_ECDSAP384_PRIVATEKEY_SIZE EC_NISTP384_PRIVATEKEY_SIZE

/*! \def QSC_ECDSAP384_SIGNATURE_SIZE
 * \brief ECDSA P-384 signature size in bytes.
 */
#define QSC_ECDSAP384_SIGNATURE_SIZE EC_NISTP384_SIGNATURE_SIZE

/*!
 * \brief Reusable P-384 verification table for one validated public key.
 * \details Caller-owned public data only; no allocation or retained secrets.
 * Initialize with qsc_ecdsap384_verify_context_initialize before use, or zero-initialize
 * to obtain an invalid context. Fields are internal: do not modify, deserialize,
 * or populate them directly. The context is not a portable serialization format.
 * Concurrent read-only verification is supported with independent output buffers.
 * Never initialize or clear a context concurrently with readers.
 */
typedef struct
{
	/*! \brief Q, 3Q, ..., 15Q; each affine X/Y is six canonical little-endian limbs. */
	uint64_t odd_multiples[8U][2U][6U];
	/*! \brief True only after successful public-key validation and table creation. */
	bool initialized;
} qsc_ecdsap384_verify_context;

/*!
 * \brief Derive a P-384 public key from a raw private scalar.
 *
 * \details
 * This function derives the affine public point Q = dG from a 48-byte
 * big-endian private scalar and serializes the result as the raw public-key
 * form Qx || Qy.
 *
 * The private scalar must be in the range [1, n - 1], where n is the order
 * of the P-384 base point.
 *
 * \param publickey: [uint8_t*] Output buffer receiving the 96-byte public key.
 * \param privatekey: [const uint8_t*] Input 48-byte private scalar.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsap384_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/*!
 * \brief Generate a P-384 public/private key pair from a 48-byte seed.
 *
 * \details
 * Derives a private scalar from the seed via SHA-384, reduces it into [1, n-1], computes
 * Q = d*G using the P-384 base point, and stores both keys. The private key layout is
 * seed[48] || Qx[48] || Qy[48].
 *
 * \param publickey: [uint8_t*] Output public key (96 bytes: Qx || Qy, big-endian).
 * \param privatekey: [uint8_t*] Output private key (144 bytes: seed || Qx || Qy).
 * \param seed: [const uint8_t*] 48-byte random seed.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsap384_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/*!
 * \brief Sign a message using a P-384 private key.
 *
 * \details
 * Produces a 96-byte signature (r || s) prepended to the message in the signedmsg buffer.
 * The nonce k is derived deterministically from the private key and message hash per RFC 6979
 * using HMAC-SHA384. Signing still requires CSP entropy for scalar, projective, and
 * inversion blinding and fails if entropy generation fails. Blinding does not change
 * the deterministic signature bytes.
 *
 * \param signedmsg: [uint8_t*] Output signed-message buffer (msglen + 96 bytes).
 * \param smsglen: [size_t*]  Set to msglen + EC_NISTP384_SIGNATURE_SIZE on success, 0 on failure.
 * \param message: [const uint8_t*] Message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 144-byte private key (seed || pubkey).
 * 
 * \return [int32_t] 0 on success, -1 on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsap384_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/*!
 * \brief Sign a message using a P-384 private key scalar.
 *
 * \details
 * Produces a 96-byte signature (r || s) prepended to the message in the signedmsg buffer.
 * The nonce k is derived deterministically from the private key scalar and message hash per
 * RFC 6979 using HMAC-SHA384. CSP entropy is required for blinding; entropy failure
 * causes signing to fail without changing the deterministic nonce construction.
 *
 * \param signedmsg: [uint8_t*] Output signed-message buffer (msglen + 96 bytes).
 * \param smsglen: [size_t*]  Set to msglen + EC_NISTP384_SIGNATURE_SIZE on success, 0 on failure.
 * \param message: [const uint8_t*] Message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 48-byte private scalar.
 * 
 * \return [int32_t] 0 on success, -1 on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsap384_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/*!
 * \brief Verify a P-384 signed message and recover the message bytes.
 *
 * \details
 * Verifies the 96-byte (r || s) signature prepended to signedmsg against the 96-byte
 * public key. On success the message bytes are copied into message and msglen is set.
 * On failure message is zeroed and msglen is set to 0.
 *
 * \param message: [uint8_t*]  Output message buffer (at least smsglen - 96 bytes).
 * \param msglen: [size_t*]  Set to the recovered message length on success.
 * \param signedmsg: [const uint8_t*] Signed-message buffer (signature || message).
 * \param smsglen: [size_t] Total signed-message length.
 * \param publickey: [const uint8_t*] 96-byte public key (Qx || Qy, big-endian).
 * 
 * \return [bool] Returns true on success, false on failure.
 */
QSC_EXPORT_API bool qsc_ecdsap384_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/*!
 * \brief Verify a signature against a separately computed SHA-256, SHA-384 or SHA-512 digest.
 * \param message Receives the recovered message on success (smsglen minus signature bytes capacity).
 * \param msglen Receives recovered message length; zero on verification failure.
 * \param signedmsg Signature-prefixed message input.
 * \param smsglen Input length in bytes.
 * \param publickey Raw P-384 public key.
 * \param digest SHA-2 digest computed over the original message by the caller.
 * \param digestlen Exactly 32, 48 or 64 bytes; hash truncation or left-zero-extension follows FIPS 186-5.
 * \return True if the signature is mathematically valid for the supplied digest.
 * \details This API does not hash the recovered message. The caller must ensure the
 * digest belongs to that message; otherwise signature-to-message binding is not established.
 * All buffers remain caller-owned, must not overlap, and do not transfer ownership.
 * This operation does not modify shared state and is thread-safe for independent buffers.
 */
QSC_EXPORT_API bool qsc_ecdsap384_verify_prehashed(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen);

/*!
 * \brief Validate a P-384 public key and build its reusable verification table.
 * \param context Writable caller-owned context, cleared on failure; NULL fails.
 * \param publickey Read-only 96-byte big-endian X||Y, disjoint from context.
 * \return True on success; false for NULL arguments or an invalid public key.
 * \details Rejects noncanonical coordinates and off-curve points. No heap or RNG.
 * Reinitialization replaces the previous key. Requires exclusive context access.
 */
QSC_EXPORT_API bool qsc_ecdsap384_verify_context_initialize(qsc_ecdsap384_verify_context* context, const uint8_t* publickey);

/*!
 * \brief Clear a verification context, making subsequent verification fail.
 * \param context Caller-owned context to clear; NULL is permitted.
 * \details Does not release storage. Requires exclusive context access.
 */
QSC_EXPORT_API void qsc_ecdsap384_verify_context_clear(qsc_ecdsap384_verify_context* context);

/*!
 * \brief Verify and recover a SHA-384 signed message using a reusable table.
 * \param message Caller-owned output of at least smsglen minus 96 bytes when
 * smsglen is at least 96; NULL permitted only for an empty recovered message.
 * \param msglen Required output length pointer; set to zero on failure.
 * \param signedmsg Read-only 96-byte r||s signature followed by message bytes.
 * \param smsglen Total signed-message size in bytes, at least 96.
 * \param context Read-only context initialized for the verifying public key.
 * \return True on a valid signature; false for invalid arguments, context or signature.
 * \details The context and buffers must not overlap. With valid pointer and length
 * arguments, an invalid signature or cleared context clears the output. No heap or RNG. Variable-time
 * public-input arithmetic; concurrent use requires independent output buffers.
 */
QSC_EXPORT_API bool qsc_ecdsap384_verify_with_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap384_verify_context* context);

/*!
 * \brief Verify a supplied SHA-2 digest using a reusable public-key table.
 * \param message Caller-owned output of at least smsglen minus 96 bytes when
 * smsglen is at least 96; NULL permitted only for an empty recovered message.
 * \param msglen Required output length pointer; set to zero on failure.
 * \param signedmsg Read-only 96-byte r||s signature followed by message bytes.
 * \param smsglen Total signed-message size in bytes, at least 96.
 * \param context Read-only context initialized for the verifying public key.
 * \param digest Read-only digest of the original message, computed by the caller.
 * \param digestlen Exactly 32, 48 or 64 bytes for SHA-256, SHA-384 or SHA-512.
 * \return True when the signature is valid for the supplied digest; false otherwise.
 * \details Does not hash or bind the recovered message: the caller must ensure
 * digest belongs to that message. All storage remains caller-owned and must not
 * overlap. With valid pointer and length arguments, an invalid signature or
 * cleared context clears the output.
 * Public-input variable-time operation, no heap or RNG. An immutable context may
 * be shared concurrently when each call uses independent output buffers.
 */
QSC_EXPORT_API bool qsc_ecdsap384_verify_prehashed_with_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap384_verify_context* context, const uint8_t* digest, size_t digestlen);

/*! \brief Caller-owned reusable six-column P-384 public-key comb table.
 * \details Initialize before use; zero-initialization creates an inactive context.
 * Entry m-1 stores (sum of bit j of m times 2^(64*j))*Q, for 1 <= m <= 63.
 * Internal coordinates must not be modified, serialized or supplied by a peer.
 * An initialized context may be shared by concurrent readers. Initialization,
 * clearing and replacement require exclusive access. Contains no private data.
 * Existing verification contexts and entry points remain ABI-compatible.
 */
typedef struct
{
	/*! \brief Affine comb points; internal field representation, least-significant word first.
	 */
	uint64_t comb[63U][2U][6U];
	/*! \brief Validated raw big-endian public key, owned by this context.
	 */
	uint8_t publickey[EC_NISTP384_PUBLICKEY_SIZE];
	/*! \brief True only after successful initialization.
	 */
	bool initialized;
} qsc_ecdsap384_comb_verify_context;

/*! \brief Validate a P-384 public key and construct its reusable comb table.
 * \param context Caller-owned destination; exclusive access required.
 * \param publickey Exactly EC_NISTP384_PUBLICKEY_SIZE readable bytes, disjoint from context.
 * \return True on success; false for NULL or noncanonical/off-curve/identity keys.
 * \details Clears context on failure when non-NULL. No retained pointers or heap
 * allocation; thread-safe with distinct contexts. Initialization uses public data.
 */
QSC_EXPORT_API bool qsc_ecdsap384_comb_verify_context_initialize(qsc_ecdsap384_comb_verify_context* context, const uint8_t* publickey);

/*! \brief Clear and invalidate a reusable comb context.
 * \param context Caller-owned context; NULL is allowed. Exclusive access required.
 */
QSC_EXPORT_API void qsc_ecdsap384_comb_verify_context_clear(qsc_ecdsap384_comb_verify_context* context);

/*! \brief Verify and recover a signed message using a reusable public-key comb.
 * \param message Caller-owned output, capacity smsglen minus the signature size; non-NULL.
 * \param msglen Caller-owned length output; zero on failure when non-NULL.
 * \param signedmsg Read-only raw r||s followed by the message.
 * \param smsglen Total signed-message size, at least EC_NISTP384_SIGNATURE_SIZE.
 * \param context Initialized, immutable context from the matching initializer.
 * \return True only for a valid signature; false on invalid arguments or signature.
 * \details Uses the curve's standard SHA-2 digest. All buffers must be disjoint.
 * Output contents are unspecified on failure. Public-input verification only;
 * never supply secret scalars. Thread-safe with independent output buffers.
 */
QSC_EXPORT_API bool qsc_ecdsap384_verify_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap384_comb_verify_context* context);

/*! \brief Verify with a reusable comb and an independently supplied SHA-2 digest.
 * \param message Caller-owned output, capacity smsglen minus the signature size; non-NULL.
 * \param msglen Caller-owned length output; zero on failure when non-NULL.
 * \param signedmsg Read-only raw r||s followed by the associated message.
 * \param smsglen Total signed-message size, at least EC_NISTP384_SIGNATURE_SIZE.
 * \param context Initialized, immutable context from the matching initializer.
 * \param digest Caller-owned SHA-256, SHA-384 or SHA-512 digest.
 * \param digestlen Exactly 32, 48 or 64 bytes; normalized as in the prehashed API.
 * \return True only if the signature matches the supplied digest.
 * \details Does not hash or bind the appended message to the digest; the caller
 * must establish that relationship. Buffers must be disjoint; output contents
 * are unspecified on failure. Public-input verification only. Concurrent readers
 * may share context with independent writable buffers. No input is retained.
 */
QSC_EXPORT_API bool qsc_ecdsap384_verify_prehashed_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap384_comb_verify_context* context, const uint8_t* digest, size_t digestlen);

/*! \brief Compatibility declarations for the previous curve API names. */
/*! \brief Compatibility name for qsc_ecdsap384_comb_verify_context; identical storage and ownership. */
typedef qsc_ecdsap384_comb_verify_context qsc_p384_comb_verify_context;

/*! \brief Compatibility name for qsc_ecdsap384_verify_context; identical storage and ownership. */
typedef qsc_ecdsap384_verify_context qsc_p384_verify_context;

/*! \brief Compatibility entry point for qsc_ecdsap384_publickey_from_privatekey.
 * \copydetails qsc_ecdsap384_publickey_from_privatekey
 */
QSC_EXPORT_API int32_t qsc_p384_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/*! \brief Compatibility entry point for qsc_ecdsap384_keypair.
 * \copydetails qsc_ecdsap384_keypair
 */
QSC_EXPORT_API int32_t qsc_p384_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/*! \brief Compatibility entry point for qsc_ecdsap384_sign.
 * \copydetails qsc_ecdsap384_sign
 */
QSC_EXPORT_API int32_t qsc_p384_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/*! \brief Compatibility entry point for qsc_ecdsap384_sign_scalar.
 * \copydetails qsc_ecdsap384_sign_scalar
 */
QSC_EXPORT_API int32_t qsc_p384_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/*! \brief Compatibility entry point for qsc_ecdsap384_verify.
 * \copydetails qsc_ecdsap384_verify
 */
QSC_EXPORT_API bool qsc_p384_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/*! \brief Compatibility entry point for qsc_ecdsap384_verify_prehashed.
 * \copydetails qsc_ecdsap384_verify_prehashed
 */
QSC_EXPORT_API bool qsc_p384_verify_prehashed(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen);

/*! \brief Compatibility entry point for qsc_ecdsap384_verify_context_initialize.
 * \copydetails qsc_ecdsap384_verify_context_initialize
 */
QSC_EXPORT_API bool qsc_p384_verify_context_initialize(qsc_p384_verify_context* context, const uint8_t* publickey);

/*! \brief Compatibility entry point for qsc_ecdsap384_verify_context_clear.
 * \copydetails qsc_ecdsap384_verify_context_clear
 */
QSC_EXPORT_API void qsc_p384_verify_context_clear(qsc_p384_verify_context* context);

/*! \brief Compatibility entry point for qsc_ecdsap384_verify_with_context.
 * \copydetails qsc_ecdsap384_verify_with_context
 */
QSC_EXPORT_API bool qsc_p384_verify_with_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p384_verify_context* context);

/*! \brief Compatibility entry point for qsc_ecdsap384_verify_prehashed_with_context.
 * \copydetails qsc_ecdsap384_verify_prehashed_with_context
 */
QSC_EXPORT_API bool qsc_p384_verify_prehashed_with_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p384_verify_context* context, const uint8_t* digest, size_t digestlen);

/*! \brief Compatibility entry point for qsc_ecdsap384_comb_verify_context_initialize.
 * \copydetails qsc_ecdsap384_comb_verify_context_initialize
 */
QSC_EXPORT_API bool qsc_p384_comb_verify_context_initialize(qsc_p384_comb_verify_context* context, const uint8_t* publickey);

/*! \brief Compatibility entry point for qsc_ecdsap384_comb_verify_context_clear.
 * \copydetails qsc_ecdsap384_comb_verify_context_clear
 */
QSC_EXPORT_API void qsc_p384_comb_verify_context_clear(qsc_p384_comb_verify_context* context);

/*! \brief Compatibility entry point for qsc_ecdsap384_verify_with_comb_context.
 * \copydetails qsc_ecdsap384_verify_with_comb_context
 */
QSC_EXPORT_API bool qsc_p384_verify_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p384_comb_verify_context* context);

/*! \brief Compatibility entry point for qsc_ecdsap384_verify_prehashed_with_comb_context.
 * \copydetails qsc_ecdsap384_verify_prehashed_with_comb_context
 */
QSC_EXPORT_API bool qsc_p384_verify_prehashed_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p384_comb_verify_context* context, const uint8_t* digest, size_t digestlen);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond DOXYGEN_NO_DOCUMENT */

#endif
