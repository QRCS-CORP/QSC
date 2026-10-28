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

#ifndef QSC_ECDSAP256_H
#define QSC_ECDSAP256_H

#include "qsccommon.h"
/** cond */
QSC_CPLUSPLUS_ENABLED_START

/**
 * \details All API operations are synchronous and use caller-owned buffers.
 * Key material is not retained between calls. Callers must provide valid,
 * non-overlapping buffers sized according to this header, synchronize access
 * to buffers shared with other threads, and securely erase sensitive inputs.
 * Verification reports false on invalid signatures; other operations report
 * 0 on success and negative error codes on failure.
 */

/*!
 * \file ecdsap256.h
 * \brief Public API for NIST P-256 (secp256r1) ECDSA signature operations.
 *
 * \details
 * This header defines the public functions for NIST P-256 (secp256r1) ECDSA operations,
 * including key pair generation from a seed, deterministic message signing using RFC 6979,
 * and signature verification. The implementation uses Jacobian projective coordinates for
 * elliptic curve point arithmetic, Solinas reduction for the field prime p, and Barrett
 * reduction for the group order n.
 *
 * Key and signature encoding is big-endian and compatible with X9.62/SEC 1 conventions:
 * - Public key: 64 bytes (32-byte X || 32-byte Y, uncompressed, no 0x04 prefix)
 * - Private key: 32-byte seed || 64-byte public key = 96 bytes
 * - Signature: 32-byte r || 32-byte s
 */

/*! 
* \def EC_NISTP256_SEED_SIZE
* \brief Seed and derived scalar byte length 
*/
#define EC_NISTP256_SEED_SIZE 32U

/*!
* \def EC_NISTP256_PUBLICKEY_SIZE
* \brief Public key byte length (X || Y, each 32 bytes big-endian) 
*/
#define EC_NISTP256_PUBLICKEY_SIZE  64U

/*!
* \def EC_NISTP256_PRIVATEKEY_SIZE
* \brief Private key byte length (seed[32] || pubkey[64]) 
*/
#define EC_NISTP256_PRIVATEKEY_SIZE 96U

/*! 
* \def EC_NISTP256_SIGNATURE_SIZE
* \brief Signature byte length (r[32] || s[32], big-endian) 
*/
#define EC_NISTP256_SIGNATURE_SIZE  64U

/*! 
* \def EC_NISTP256_SHAREDSECRET_SIZE
* \brief Shared secret byte length derived from the affine X coordinate. 
*/
#define EC_NISTP256_SHAREDSECRET_SIZE 32U

/** \def QSC_ECDSAP256_SEED_SIZE
 * \brief ECDSA P-256 seed size in bytes.
 */
#define QSC_ECDSAP256_SEED_SIZE EC_NISTP256_SEED_SIZE

/** \def QSC_ECDSAP256_PUBLICKEY_SIZE
 * \brief ECDSA P-256 publickey size in bytes.
 */
#define QSC_ECDSAP256_PUBLICKEY_SIZE EC_NISTP256_PUBLICKEY_SIZE

/** \def QSC_ECDSAP256_PRIVATEKEY_SIZE
 * \brief ECDSA P-256 privatekey size in bytes.
 */
#define QSC_ECDSAP256_PRIVATEKEY_SIZE EC_NISTP256_PRIVATEKEY_SIZE

/** \def QSC_ECDSAP256_SIGNATURE_SIZE
 * \brief ECDSA P-256 signature size in bytes.
 */
#define QSC_ECDSAP256_SIGNATURE_SIZE EC_NISTP256_SIGNATURE_SIZE

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
 * \param publickey: [uint8_t*] Output buffer receiving the 64-byte public key.
 * \param privatekey: [const uint8_t*] Input 32-byte private scalar.
 *
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_p256_publickey_from_privatekey(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Generate a P-256 public/private key pair from a 32-byte seed.
 *
 * \details
 * Derives a private scalar from the seed via SHA-256, clamps it into [1, n-1], computes
 * Q = d*G using the P-256 base point, and stores both keys. The private key layout is seed[32] || Qx[32] || Qy[32].
 *
 * \param publickey: [uint8_t*] Output public key (64 bytes: Qx || Qy, big-endian).
 * \param privatekey: [uint8_t*] Output private key (96 bytes: seed || Qx || Qy).
 * \param seed: [const uint8_t*] 32-byte random seed.
 * 
 * \return [int32_t] Returns 0 on success, or a negative error code on failure.
 */
QSC_EXPORT_API int32_t qsc_p256_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Sign a message using a P-256 private key.
 *
 * \details
 * Produces a 64-byte signature (r || s) prepended to the message in the signedmsg buffer.
 * The nonce k is derived deterministically from the private key and message hash per RFC 6979
 * using HMAC-SHA256, eliminating the need for a random number generator at signing time.
 *
 * \param signedmsg: [uint8_t*] Output signed-message buffer (msglen + 64 bytes).
 * \param smsglen: [size_t*]  Set to msglen + EC_NISTP256_SIGNATURE_SIZE on success, 0 on failure.
 * \param message: [const uint8_t*] Message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 96-byte private key (seed || pubkey).
 * 
 * \return [int32_t] 0 on success, -1 on failure.
 */
QSC_EXPORT_API int32_t qsc_p256_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Sign a message using a P-256 private key (RFC 6979 deterministic k using scalar d).
 *
 * \details
 * Produces a 64-byte signature (r || s) prepended to the message in the signedmsg buffer.
 * The nonce k is derived deterministically from the private key and message hash per RFC 6979
 * using HMAC-SHA256, eliminating the need for a random number generator at signing time.
 *
 * \param signedmsg: [uint8_t*] Output signed-message buffer (msglen + 64 bytes).
 * \param smsglen: [size_t*]  Set to msglen + EC_NISTP256_SIGNATURE_SIZE on success, 0 on failure.
 * \param message: [const uint8_t*] Message to sign.
 * \param msglen: [size_t] Message length in bytes.
 * \param privatekey: [const uint8_t*] 96-byte private key (seed || pubkey).
 * 
 * \return [int32_t] 0 on success, -1 on failure.
 */
QSC_EXPORT_API int32_t qsc_p256_sign_scalar(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
 * \brief Verify a P-256 signed message and recover the message bytes.
 *
 * \details
 * Verifies the 64-byte (r || s) signature prepended to signedmsg against the 64-byte
 * public key. On success the message bytes are copied into message and msglen is set.
 * On failure message is zeroed and msglen is set to 0.
 *
 * \param message: [uint8_t*] Output message buffer (at least smsglen - 64 bytes).
 * \param msglen: [size_t*] Set to the recovered message length on success.
 * \param signedmsg: [const uint8_t*] Signed-message buffer (signature || message).
 * \param smsglen: [size_t] Total signed-message length.
 * \param publickey: [const uint8_t*] 64-byte public key (Qx || Qy, big-endian).
 * \return [int32_t] 0 on success, -1 on failure.
 */
QSC_EXPORT_API bool qsc_p256_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/**
 * \brief Verify a signature against a separately computed SHA-256, SHA-384 or SHA-512 digest.
 * \param message Receives the recovered message on success (smsglen minus signature bytes capacity).
 * \param msglen Receives recovered message length; zero on verification failure.
 * \param signedmsg Signature-prefixed message input.
 * \param smsglen Input length in bytes.
 * \param publickey Raw P-256 public key.
 * \param digest SHA-2 digest computed over the original message by the caller.
 * \param digestlen Exactly 32, 48 or 64 bytes; hash truncation or left-zero-extension follows FIPS 186-5.
 * \return True if the signature is mathematically valid for the supplied digest.
 * \details This API does not hash the recovered message. The caller must ensure the
 * digest belongs to that message; otherwise signature-to-message binding is not established.
 * All buffers remain caller-owned, must not overlap, and do not transfer ownership.
 * This operation does not modify shared state and is thread-safe for independent buffers.
 */
QSC_EXPORT_API bool qsc_p256_verify_prehashed(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey, const uint8_t* digest, size_t digestlen);

/**
 * \brief Optional immutable P-256 verification precomputation for one public key.
 * \details Owned by the caller; populate only with qsc_p256_verify_context_initialize.
 * Stores public odd multiples in Montgomery representation; no private key data.
 * Valid for concurrent read-only use after initialization. Modifying fields or
 * sharing with an initializer/clear operation concurrently is unsupported.
 */
typedef struct
{
    /*! \brief Eight affine public-key odd multiples; each X/Y has eight little-endian words. */
    uint32_t odd_montgomery[8U][2U][8U];
    /*! \brief Validated raw 64-byte P-256 public key. */
    uint8_t publickey[EC_NISTP256_PUBLICKEY_SIZE];
    /*! \brief True when initialized with a validated public key. */
    bool initialized;
} qsc_p256_verify_context;

/**
 * \brief Optional four-bit joint-window P-256 verification context.
 * \details Keeps the original verifier context binary layout unchanged. A
 * separately initialized context stores up to 256 affine public combinations
 * iG+jQ, with 0 <= i,j <= 15, using four native 64-bit Montgomery limbs.
 * The table is public and may be read concurrently after initialization.
 * Initialization is relatively expensive and should be amortized over several
 * signature verifications of the same validated public key.
 * \note The optimized joint table is used on supported native 128-bit integer
 * compilers. Other platforms use the preserved portable verification backend.
 * Never initialize or erase a context while another thread is using it.
 */
typedef struct
{
    /*! \brief Original validated-key context, retained for portable fallback. */
    qsc_p256_verify_context base;
    /*! \brief Precomputed affine coordinates indexed as (i << 4) | j. */
    uint64_t joint_montgomery[256U][2U][4U];
    /*! \brief Nonzero when the corresponding joint point is infinity. */
    uint8_t joint_infinity[256U];
    /*! \brief True after successful initialization. */
    bool initialized;
} qsc_p256_joint_verify_context;

/**
 * \brief Validate a public key and initialize its four-bit joint precomputation.
 * \param context Caller-owned, writable context, cleared on failure.
 * \param publickey Public P-256 X||Y, 64 bytes, big-endian.
 * \return True on successful validation and initialization, otherwise false.
 * \note No heap, no global state; context initialization is not concurrent-safe.
 */
QSC_EXPORT_API bool qsc_p256_joint_verify_context_initialize(qsc_p256_joint_verify_context* context, const uint8_t* publickey);

/**
 * \brief Erase a caller-owned four-bit joint verification context.
 * \param context Context to clear, or NULL.
 * \note Do not erase while another thread is verifying with this context.
 */
QSC_EXPORT_API void qsc_p256_joint_verify_context_clear(qsc_p256_joint_verify_context* context);

/**
 * \brief Verify and recover a message using a precomputed joint-window key.
 * \param message Recovered-message output, capacity at least signedlen-64.
 * \param msglen Result length output, set to zero on failure.
 * \param signedmsg Input 64-byte r||s followed by message.
 * \param smsglen Total input length in bytes.
 * \param context Previously initialized, immutable joint verification context.
 * \return True only for a valid signature under the cached public key.
 * \note Public-input-only algorithm; the signing routines do not use this
 * API or any joint-context arithmetic. Thread safe with immutable context and
 * independent input/output buffers.
 */
QSC_EXPORT_API bool qsc_p256_verify_with_joint_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p256_joint_verify_context* context);


/**
 * \brief Validate a public key and prepare a reusable verifier context.
 * \param context Writable caller-owned context, erased on failure.
 * \param publickey Raw 64-byte P-256 public key, big-endian X || Y.
 * \return True for a valid public key; false otherwise.
 * \note No heap or shared mutable data. Call once before concurrent verifications.
 */
QSC_EXPORT_API bool qsc_p256_verify_context_initialize(qsc_p256_verify_context* context, const uint8_t* publickey);

/**
 * \brief Clear all public-key precomputation from the context.
 * \param context Context to clear, NULL is permitted.
 * \note Do not race with other threads reading the context.
 */
QSC_EXPORT_API void qsc_p256_verify_context_clear(qsc_p256_verify_context* context);

/**
 * \brief Verify a signature with one immutable precomputed public-key context.
 * \param message Recovered-message destination of at least smsglen minus 64 bytes.
 * \param msglen Recovered length output, zero on failure.
 * \param signedmsg Input r||s signature plus message bytes.
 * \param smsglen Length of signedmsg in bytes.
 * \param context Initialized, immutable context for the verifying public key.
 * \return True on a valid signature, false on error or invalid signature.
 * \note Thread safe for concurrent calls with independent output buffers and
 * an immutable context. On compilers without 128-bit words the portable
 * verifier remains functional but does not accelerate with precomputation.
 */
QSC_EXPORT_API bool qsc_p256_verify_with_context(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const qsc_p256_verify_context* context);

QSC_CPLUSPLUS_ENABLED_END

#endif
