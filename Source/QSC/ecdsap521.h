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

#ifndef QSC_ECDSAP521_H
#define QSC_ECDSAP521_H

#include "qsccommon.h"

/* \cond DOXYGEN_NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file ecdsap521.h
 * \brief Public API for NIST P-521 (secp521r1) ECDSA operations.
 *
 * \details
 * This header defines the public functions for NIST P-521 ECDSA operations,
 * including public-key derivation from a raw private scalar, seed-based key-pair
 * generation, deterministic signing using RFC 6979, and signature verification.
 *
 * Key and signature encoding is big-endian and compatible with X9.62 / SEC 1:
 * - Public key: 132 bytes (Qx[66] || Qy[66], uncompressed, no 0x04 prefix)
 * - Private key: 198 bytes (seed[66] || publickey[132])
 * - Signature: 132 bytes (r[66] || s[66])
 */

/*!
* \def EC_NISTP521_SEED_SIZE
* \brief Seed and scalar byte length for P-521 
*/
#define EC_NISTP521_SEED_SIZE 66U

/*!
* \def EC_NISTP521_PUBLICKEY_SIZE
* \brief Public key byte length (Qx || Qy) 
*/
#define EC_NISTP521_PUBLICKEY_SIZE 132U

/*!
* \def EC_NISTP521_PRIVATEKEY_SIZE
* \brief Private key byte length (seed[66] || pubkey[132]) 
*/
#define EC_NISTP521_PRIVATEKEY_SIZE 198U

/*!
* \def EC_NISTP521_SIGNATURE_SIZE
* \brief Signature byte length (r[66] || s[66]) 
*/
#define EC_NISTP521_SIGNATURE_SIZE 132U

/*!
 * \brief Parameter-specific public sizes for ECDSA P-521.
 *
 * These constants are available independently of the default ECDSA facade selection.
 */
/*! \def QSC_ECDSAP521_SEED_SIZE
 * \brief ECDSA P-521 seed size in bytes.
 */
#define QSC_ECDSAP521_SEED_SIZE EC_NISTP521_SEED_SIZE

/*! \def QSC_ECDSAP521_PUBLICKEY_SIZE
 * \brief ECDSA P-521 publickey size in bytes.
 */
#define QSC_ECDSAP521_PUBLICKEY_SIZE EC_NISTP521_PUBLICKEY_SIZE

/*! \def QSC_ECDSAP521_PRIVATEKEY_SIZE
 * \brief ECDSA P-521 privatekey size in bytes.
 */
#define QSC_ECDSAP521_PRIVATEKEY_SIZE EC_NISTP521_PRIVATEKEY_SIZE

/*! \def QSC_ECDSAP521_SIGNATURE_SIZE
 * \brief ECDSA P-521 signature size in bytes.
 */
#define QSC_ECDSAP521_SIGNATURE_SIZE EC_NISTP521_SIGNATURE_SIZE

/*!
 * \brief Derive a P-521 public key from a raw private scalar.
 *
 * \details
 * This function derives the affine public point Q = dG from a 66-byte
 * big-endian private scalar and serializes the result as Qx || Qy.
 *
 * \param publickey: [uint8_t*] Output buffer receiving the 132-byte public key.
 * \param privatekey: [const uint8_t*] Input 66-byte private scalar.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsap521_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/*!
 * \brief Generate a P-521 public/private key pair from a 66-byte seed.
 *
 * \details
 * The seed is hashed with SHA-512 and reduced modulo the P-521 subgroup order to
 * derive the signing scalar. The public key is then computed as Q = dG. The output
 * private key layout is seed[66] || Qx[66] || Qy[66].
 *
 * \param publickey: [uint8_t*] Output public key (132 bytes).
 * \param privatekey: [uint8_t*] Output private key (198 bytes).
 * \param seed: [const uint8_t*] Input 66-byte seed.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsap521_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/*!
 * \brief Sign a message using a P-521 private key.
 *
 * \details
 * The message is hashed with SHA-512. The deterministic nonce is generated using
 * RFC 6979 with HMAC-SHA512. The output signed-message buffer contains the
 * 132-byte signature prepended to the message.
 *
 * \param signedmsg: [uint8_t*] Output signed-message buffer.
 * \param smsglen: [size_t*] Set to msglen + EC_NISTP521_SIGNATURE_SIZE on success.
 * \param message: [const uint8_t*] Message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 198-byte private key (seed || pubkey).
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsap521_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/*!
 * \brief Sign a message using a raw P-521 private scalar.
 *
 * \details
 * The input private key is the 66-byte big-endian signing scalar d. This function
 * exists so the implementation can be tested directly against RFC 6979 known-answer
 * vectors, which specify the scalar explicitly.
 *
 * \param signedmsg: [uint8_t*] Output signed-message buffer.
 * \param smsglen: [size_t*] Set to msglen + EC_NISTP521_SIGNATURE_SIZE on success.
 * \param message: [const uint8_t*] Message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 66-byte private scalar.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_ecdsap521_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/*!
 * \brief Verify a P-521 signed message and recover the message bytes.
 *
 * \param message: [uint8_t*] Output message buffer.
 * \param msglen: [size_t*] Set to the recovered message length on success.
 * \param signedmsg: [const uint8_t*] Signed-message buffer (signature || message).
 * \param smsglen: [size_t] Total signed-message length.
 * \param publickey: [const uint8_t*] 132-byte raw public key (Qx || Qy).
 *
 * \return [bool] Returns true on success, false on failure.
 */
QSC_EXPORT_API bool qsc_ecdsap521_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/*!
 * \brief Verify a signature against a separately computed SHA-256, SHA-384 or SHA-512 digest.
 * \param message Receives the recovered message on success (smsglen minus signature bytes capacity).
 * \param msglen Receives recovered message length; zero on verification failure.
 * \param signedmsg Signature-prefixed message input.
 * \param smsglen Input length in bytes.
 * \param publickey Raw P-521 public key.
 * \param digest SHA-2 digest computed over the original message by the caller.
 * \param digestlen Exactly 32, 48 or 64 bytes; hash truncation or left-zero-extension follows FIPS 186-5.
 * \return True if the signature is mathematically valid for the supplied digest.
 * \details This API does not hash the recovered message. The caller must ensure the
 * digest belongs to that message; otherwise signature-to-message binding is not established.
 * All buffers remain caller-owned, must not overlap, and do not transfer ownership.
 * This operation does not modify shared state and is thread-safe for independent buffers.
 */
QSC_EXPORT_API bool qsc_ecdsap521_verify_prehashed(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen);

/*! \brief Caller-owned reusable six-column P-521 public-key comb table.
 * \details Initialize before use; zero-initialization creates an inactive context.
 * Entry m-1 stores (sum of bit j of m times 2^(87*j))*Q, for 1 <= m <= 63.
 * Internal coordinates must not be modified, serialized or supplied by a peer.
 * An initialized context may be shared by concurrent readers. Initialization,
 * clearing and replacement require exclusive access. Contains no private data.
 * Existing verification contexts and entry points remain ABI-compatible.
 */
typedef struct
{
	/*! \brief Affine comb points; internal field representation, least-significant word first. */
	uint64_t comb[63U][2U][9U];
	/*! \brief Validated raw big-endian public key, owned by this context. */
	uint8_t publickey[EC_NISTP521_PUBLICKEY_SIZE];
	/*! \brief True only after successful initialization. */
	bool initialized;
} qsc_ecdsap521_comb_verify_context;

/*! \brief Validate a P-521 public key and construct its reusable comb table.
 * \param context Caller-owned destination; exclusive access required.
 * \param publickey Exactly EC_NISTP521_PUBLICKEY_SIZE readable bytes, disjoint from context.
 * \return True on success; false for NULL or noncanonical/off-curve/identity keys.
 * \details Clears context on failure when non-NULL. No retained pointers or heap
 * allocation; thread-safe with distinct contexts. Initialization uses public data.
 */
QSC_EXPORT_API bool qsc_ecdsap521_comb_verify_context_initialize(qsc_ecdsap521_comb_verify_context* context, const uint8_t* publickey);

/*! \brief Clear and invalidate a reusable comb context.
 * \param context Caller-owned context; NULL is allowed. Exclusive access required.
 */
QSC_EXPORT_API void qsc_ecdsap521_comb_verify_context_clear(qsc_ecdsap521_comb_verify_context* context);

/*! \brief Verify and recover a signed message using a reusable public-key comb.
 * \param message Caller-owned output, capacity smsglen minus the signature size; non-NULL.
 * \param msglen Caller-owned length output; zero on failure when non-NULL.
 * \param signedmsg Read-only raw r||s followed by the message.
 * \param smsglen Total signed-message size, at least EC_NISTP521_SIGNATURE_SIZE.
 * \param context Initialized, immutable context from the matching initializer.
 * \return True only for a valid signature; false on invalid arguments or signature.
 * \details Uses the curve's standard SHA-2 digest. All buffers must be disjoint.
 * Output contents are unspecified on failure. Public-input verification only;
 * never supply secret scalars. Thread-safe with independent output buffers.
 */
QSC_EXPORT_API bool qsc_ecdsap521_verify_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap521_comb_verify_context* context);

/*! \brief Verify with a reusable comb and an independently supplied SHA-2 digest.
 * \param message Caller-owned output, capacity smsglen minus the signature size; non-NULL.
 * \param msglen Caller-owned length output; zero on failure when non-NULL.
 * \param signedmsg Read-only raw r||s followed by the associated message.
 * \param smsglen Total signed-message size, at least EC_NISTP521_SIGNATURE_SIZE.
 * \param context Initialized, immutable context from the matching initializer.
 * \param digest Caller-owned SHA-256, SHA-384 or SHA-512 digest.
 * \param digestlen Exactly 32, 48 or 64 bytes; normalized as in the prehashed API.
 * \return True only if the signature matches the supplied digest.
 * \details Does not hash or bind the appended message to the digest; the caller
 * must establish that relationship. Buffers must be disjoint; output contents
 * are unspecified on failure. Public-input verification only. Concurrent readers
 * may share context with independent writable buffers. No input is retained.
 */
QSC_EXPORT_API bool qsc_ecdsap521_verify_prehashed_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_ecdsap521_comb_verify_context* context, const uint8_t* digest, size_t digestlen);

/*! \brief Compatibility declarations for the previous curve API names. */
/*! \brief Compatibility name for qsc_ecdsap521_comb_verify_context; identical storage and ownership. */
typedef qsc_ecdsap521_comb_verify_context qsc_p521_comb_verify_context;

/*! \brief Compatibility entry point for qsc_ecdsap521_publickey_from_privatekey.
 * \copydetails qsc_ecdsap521_publickey_from_privatekey
 */
QSC_EXPORT_API int32_t qsc_p521_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/*! \brief Compatibility entry point for qsc_ecdsap521_keypair.
 * \copydetails qsc_ecdsap521_keypair
 */
QSC_EXPORT_API int32_t qsc_p521_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/*! \brief Compatibility entry point for qsc_ecdsap521_sign.
 * \copydetails qsc_ecdsap521_sign
 */
QSC_EXPORT_API int32_t qsc_p521_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/*! \brief Compatibility entry point for qsc_ecdsap521_sign_scalar.
 * \copydetails qsc_ecdsap521_sign_scalar
 */
QSC_EXPORT_API int32_t qsc_p521_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/*! \brief Compatibility entry point for qsc_ecdsap521_verify.
 * \copydetails qsc_ecdsap521_verify
 */
QSC_EXPORT_API bool qsc_p521_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/*! \brief Compatibility entry point for qsc_ecdsap521_verify_prehashed.
 * \copydetails qsc_ecdsap521_verify_prehashed
 */
QSC_EXPORT_API bool qsc_p521_verify_prehashed(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen);

/*! \brief Compatibility entry point for qsc_ecdsap521_comb_verify_context_initialize.
 * \copydetails qsc_ecdsap521_comb_verify_context_initialize
 */
QSC_EXPORT_API bool qsc_p521_comb_verify_context_initialize(qsc_p521_comb_verify_context* context, const uint8_t* publickey);

/*! \brief Compatibility entry point for qsc_ecdsap521_comb_verify_context_clear.
 * \copydetails qsc_ecdsap521_comb_verify_context_clear
 */
QSC_EXPORT_API void qsc_p521_comb_verify_context_clear(qsc_p521_comb_verify_context* context);

/*! \brief Compatibility entry point for qsc_ecdsap521_verify_with_comb_context.
 * \copydetails qsc_ecdsap521_verify_with_comb_context
 */
QSC_EXPORT_API bool qsc_p521_verify_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p521_comb_verify_context* context);

/*! \brief Compatibility entry point for qsc_ecdsap521_verify_prehashed_with_comb_context.
 * \copydetails qsc_ecdsap521_verify_prehashed_with_comb_context
 */
QSC_EXPORT_API bool qsc_p521_verify_prehashed_with_comb_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p521_comb_verify_context* context, const uint8_t* digest, size_t digestlen);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond DOXYGEN_NO_DOCUMENT */

#endif
