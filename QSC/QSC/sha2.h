/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John Underhill
 * Contact: john.underhill@protonmail.com
 */


#ifndef QSC_SHA2_H
#define QSC_SHA2_H

#include "common.h"

/**
 * \file sha2.h
 * \brief The SHA2 family of hash functions.
 *
 * \details
 * This header contains the public API and documentation for the SHA2 digest functions,
 * HMAC, and HKDF implementations. It supports SHA2-256, SHA2-384, and SHA2-512 variants.
 * The API includes both short-form functions (processing the complete message in one call)
 * and long-form functions (initialize, update, finalize) for incremental processing.
 *
 * Example for SHA2-512 using the long-form API:
 * \code
 * #define MSGLEN 200
 * uint8_t msg[MSGLEN] = { ... };
 * uint8_t otp[QSC_SHA2_512_HASH_SIZE] = { 0 };
 * qsc_sha512_state ctx;
 *
 * qsc_sha512_initialize(&ctx);
 * qsc_sha512_update(&ctx, msg, MSGLEN);
 * qsc_sha512_finalize(&ctx, otp);
 * \endcode
 *
 * \section sha2_links Reference Links:
 * - <a href="http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">NIST: The SHA-2 Standard</a>
 * - <a href="https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf">Analysis of SIMD Applicability to SHA Algorithms</a>
 */

#if !defined(QSC_SHA2_SHANI_ENABLED)
//#define QSC_SHA2_SHANI_ENABLED
#endif

/*!
 * \def QSC_HKDF_256_KEY_SIZE
 * \brief The HKDF-256 key size in bytes.
 */
#define QSC_HKDF_256_KEY_SIZE 32ULL

/*!
 * \def QSC_HKDF_512_KEY_SIZE
 * \brief The HKDF-512 key size in bytes.
 */
#define QSC_HKDF_512_KEY_SIZE 64ULL

/*!
 * \def QSC_HMAC_256_KEY_SIZE
 * \brief The recommended HMAC(SHA2-256) key size, minimum is 32 bytes.
 */
#define QSC_HMAC_256_KEY_SIZE 32ULL

/*!
 * \def QSC_HMAC_512_KEY_SIZE
 * \brief The recommended HMAC(SHA2-512) key size, minimum is 64 bytes.
 */
#define QSC_HMAC_512_KEY_SIZE 64ULL

/*!
 * \def QSC_HMAC_256_MAC_SIZE
 * \brief The HMAC-256 mac-code size in bytes.
 */
#define QSC_HMAC_256_MAC_SIZE 32ULL

/*!
 * \def QSC_HMAC_512_MAC_SIZE
 * \brief The HMAC-512 mac-code size in bytes.
 */
#define QSC_HMAC_512_MAC_SIZE 64ULL

/*!
 * \def QSC_HMAC_256_RATE
 * \brief The HMAC-256 input rate size in bytes.
 */
#define QSC_HMAC_256_RATE 64ULL

/*!
 * \def QSC_HMAC_512_RATE
 * \brief The HMAC-512 input rate size in bytes.
 */
#define QSC_HMAC_512_RATE 128ULL

/*!
 * \def QSC_SHA2_256_HASH_SIZE
 * \brief The SHA2-256 hash size in bytes.
 */
#define QSC_SHA2_256_HASH_SIZE 32ULL

/*!
 * \def QSC_SHA2_384_HASH_SIZE
 * \brief The SHA2-384 hash size in bytes.
 */
#define QSC_SHA2_384_HASH_SIZE 48ULL

/*!
 * \def QSC_SHA2_512_HASH_SIZE
 * \brief The SHA2-512 hash size in bytes.
 */
#define QSC_SHA2_512_HASH_SIZE 64ULL

/*!
 * \def QSC_SHA2_256_RATE
 * \brief The SHA2-256 absorption rate in bytes.
 */
#define QSC_SHA2_256_RATE 64ULL

/*!
 * \def QSC_SHA2_384_RATE
 * \brief The SHA2-384 absorption rate in bytes.
 */
#define QSC_SHA2_384_RATE 128ULL

/*!
 * \def QSC_SHA2_512_RATE
 * \brief The SHA2-512 absorption rate in bytes.
 */
#define QSC_SHA2_512_RATE 128ULL

/*!
 * \def QSC_SHA2_STATE_SIZE
 * \brief The SHA2 state array size.
 */
#define QSC_SHA2_STATE_SIZE 8ULL

/* SHA2-256 */

/*!
 * \struct qsc_sha256_state
 * \brief The SHA2-256 digest state array.
 */
QSC_EXPORT_API typedef struct
{
    uint32_t state[QSC_SHA2_STATE_SIZE];    /*!< The SHA2-256 state. */
    uint8_t  buffer[QSC_SHA2_256_RATE];     /*!< The message buffer. */
    uint64_t t;                             /*!< The message length. */
    size_t   position;                      /*!< The cache position. */
} qsc_sha256_state;

/*!
 * \brief Process a message with SHA2-256 and return the hash code in the output byte array.
 *
 * \param output:   [uint8_t*] The output byte array; receives the hash code.
 * \param message:  [const uint8_t*] The message input byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_sha256_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/*!
 * \brief Dispose of the SHA2-256 state.
 *
 * \param ctx:      [qsc_sha256_state*] Pointer to the cipher state structure.
 */
QSC_EXPORT_API void qsc_sha256_dispose(qsc_sha256_state* ctx);

/*!
 * \brief Finalize the message state and return the hash value in the output array.
 *
 * \warning The output array must be sized correctly. Finalizes the message state; cannot be used in consecutive calls.
 *          The state must be initialized by the caller.
 *
 * \param ctx:      [qsc_sha256_state*]  Pointer to the function state; must be initialized.
 * \param output:   [uint8_t*] The output byte array; receives the hash code.
 */
QSC_EXPORT_API void qsc_sha256_finalize(qsc_sha256_state* ctx, uint8_t* output);

/*!
 * \brief Initialize a SHA2-256 state structure.
 *
 * \param ctx:      [qsc_sha256_state*] Pointer to the function state.
 */
QSC_EXPORT_API void qsc_sha256_initialize(qsc_sha256_state* ctx);

/*!
 * \brief The SHA2-256 permutation function.
 *
 * Internal function: Called by protocol hash and generation functions, or in the construction of other external protocols.
 * Absorbs a message and permutes the state array.
 *
 * \param output:   [uint32_t*] The function output; must be initialized.
 * \param input:    [const uint8_t*] The input message byte array.
 */
QSC_EXPORT_API void qsc_sha256_permute(uint32_t* output, const uint8_t* input);

/*!
 * \brief Update SHA2-256 with message input.
 *
 * \warning State must be initialized by the caller.
 *
 * \param ctx:      [qsc_sha256_state*] Pointer to the function state.
 * \param message:  [const uint8_t*] The input message byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_sha256_update(qsc_sha256_state* ctx, const uint8_t* message, size_t msglen);

/* SHA2-384 */

/*!
 * \struct qsc_sha384_state
 * \brief The SHA2-384 digest state array.
 */
QSC_EXPORT_API typedef struct
{
    uint64_t state[QSC_SHA2_STATE_SIZE];    /*!< The SHA2-384 state. */
    uint64_t t[2];                          /*!< The message size. */
    uint8_t  buffer[QSC_SHA2_384_RATE];     /*!< The message buffer. */
    size_t   position;                      /*!< The message position. */
} qsc_sha384_state;

/*!
 * \brief Process a message with SHA2-384 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 48 bytes in length.
 *
 * \param output:   [uint8_t*] The output byte array; receives the hash code.
 * \param message:  [const uint8_t*] The message input byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_sha384_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/*!
 * \brief Dispose of the SHA2-384 state.
 *
 * \param ctx:      [qsc_sha384_state*] Pointer to the cipher state structure.
 */
QSC_EXPORT_API void qsc_sha384_dispose(qsc_sha384_state* ctx);

/*!
 * \brief Finalize the SHA2-384 state and return the hash value in the output array.
 *
 * \warning The output array must be sized correctly. Finalizes the message state; cannot be used in consecutive calls.
 *          The state must be initialized by the caller.
 *
 * \param ctx:      [qsc_sha384_state*] Pointer to the function state; must be initialized.
 * \param output:   [uint8_t*] The output byte array; receives the hash code.
 */
QSC_EXPORT_API void qsc_sha384_finalize(qsc_sha384_state* ctx, uint8_t* output);

/*!
 * \brief Initialize a SHA2-384 state structure.
 *
 * \param ctx:      [qsc_sha384_state*] Pointer to the function state.
 */
QSC_EXPORT_API void qsc_sha384_initialize(qsc_sha384_state* ctx);

/*!
 * \brief Update SHA2-384 with message input.
 *
 * \warning State must be initialized by the caller.
 *
 * \param ctx:      [qsc_sha384_state*] Pointer to the function state.
 * \param message:  [const uint8_t*] The input message byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_sha384_update(qsc_sha384_state* ctx, const uint8_t* message, size_t msglen);

/* SHA2-512 */

/*!
 * \struct qsc_sha512_state
 * \brief The SHA2-512 digest state array.
 */
QSC_EXPORT_API typedef struct
{
    uint64_t state[QSC_SHA2_STATE_SIZE];    /*!< The SHA2-512 state. */
    uint64_t t[2];                          /*!< The message length. */
    uint8_t  buffer[QSC_SHA2_512_RATE];     /*!< The message buffer. */
    size_t   position;                      /*!< The cache position. */
} qsc_sha512_state;

/*!
 * \brief Process a message with SHA2-512 and return the hash code in the output byte array.
 *
 * \warning The output array must be at least 64 bytes in length.
 *
 * \param output:   [uint8_t*] The output byte array; receives the hash code.
 * \param message:  [const uint8_t*] The message input byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_sha512_compute(uint8_t* output, const uint8_t* message, size_t msglen);

/*!
 * \brief Dispose of the SHA2-512 state.
 *
 * \param ctx:      [qsc_sha512_state*] Pointer to the cipher state structure.
 */
QSC_EXPORT_API void qsc_sha512_dispose(qsc_sha512_state* ctx);

/*!
 * \brief Finalize the SHA2-512 state and return the hash value in the output array.
 *
 * \warning The output array must be sized correctly. Finalizes the message state; cannot be used in consecutive calls.
 *          The state must be initialized by the caller.
 *
 * \param ctx:      [qsc_sha512_state*] Pointer to the function state; must be initialized.
 * \param output:   [uint8_t*] The output byte array; receives the hash code.
 */
QSC_EXPORT_API void qsc_sha512_finalize(qsc_sha512_state* ctx, uint8_t* output);

/*!
 * \brief Initialize a SHA2-512 state structure.
 *
 * \param ctx:      [qsc_sha512_state*] Pointer to the function state.
 */
QSC_EXPORT_API void qsc_sha512_initialize(qsc_sha512_state* ctx);

/*!
 * \brief The SHA2-512 permutation function.
 *
 * Internal function: Called by protocol hash and generation functions, or in the construction of other external protocols.
 * Absorbs a message and permutes the state array.
 *
 * \param output:   [uint64_t*] The function output; must be initialized.
 * \param input:    [const uint8_t*] The input message byte array.
 */
QSC_EXPORT_API void qsc_sha512_permute(uint64_t* output, const uint8_t* input);

/*!
 * \brief Update SHA2-512 with message input.
 *
 * \warning State must be initialized by the caller.
 *
 * \param ctx:      [qsc_sha512_state*] Pointer to the function state.
 * \param message:  [const uint8_t*] The input message byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_sha512_update(qsc_sha512_state* ctx, const uint8_t* message, size_t msglen);

/* HMAC-256 */

/*!
 * \struct qsc_hmac256_state
 * \brief The HMAC(SHA2-256) state array.
 */
QSC_EXPORT_API typedef struct
{
    qsc_sha256_state pstate;            /*!< The SHA2-256 state. */
    uint8_t ipad[QSC_SHA2_256_RATE];    /*!< The input pad array. */
    uint8_t opad[QSC_SHA2_256_RATE];    /*!< The output pad array. */
} qsc_hmac256_state;

/*!
 * \brief Process a message with HMAC(SHA2-256) and return the MAC code in the output byte array.
 *
 * \warning The output array must be at least 32 bytes in length.
 *
 * \param output:   [uint8_t*] The output byte array; receives the MAC code.
 * \param message:  [const uint8_t*] The message input byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 * \param key:      [const uint8_t*] The secret key array.
 * \param keylen:   [size_t] The key array length.
 */
QSC_EXPORT_API void qsc_hmac256_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/*!
 * \brief Dispose of the HMAC-256 state.
 *
 * \param ctx:      [qsc_hmac256_state*] Pointer to the MAC state structure.
 */
QSC_EXPORT_API void qsc_hmac256_dispose(qsc_hmac256_state* ctx);

/*!
 * \brief Finalize the HMAC-256 state and return the MAC code in the output byte array.
 *
 * \warning The output array must be sized correctly. Finalizes the message state; cannot be used in consecutive calls.
 *          The state must be initialized by the caller.
 *
 * \param ctx:      [qsc_hmac256_state*] Pointer to the MAC state structure; must be initialized.
 * \param output:   [uint8_t*] The output byte array; receives the MAC code.
 */
QSC_EXPORT_API void qsc_hmac256_finalize(qsc_hmac256_state* ctx, uint8_t* output);

/*!
 * \brief Initialize an HMAC-256 state structure with a key.
 *
 * \param ctx:      [qsc_hmac256_state*] Pointer to the MAC state structure.
 * \param key:      [const uint8_t*] Pointer to the secret key array.
 * \param keylen:   [size_t] The key array length.
 */
QSC_EXPORT_API void qsc_hmac256_initialize(qsc_hmac256_state* ctx, const uint8_t* key, size_t keylen);

/*!
 * \brief Update HMAC-256 with message input.
 *
 * \warning State must be initialized by the caller.
 *
 * \param ctx:      [qsc_hmac256_state*] Pointer to the MAC state structure.
 * \param message:  [const uint8_t*] The input message byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_hmac256_update(qsc_hmac256_state* ctx, const uint8_t* message, size_t msglen);

/* HMAC-512 */

/*!
 * \struct qsc_hmac512_state
 * \brief The HMAC(SHA2-512) state array.
 */
QSC_EXPORT_API typedef struct
{
    qsc_sha512_state pstate;            /*!< The SHA2-512 state. */
    uint8_t ipad[QSC_SHA2_512_RATE];    /*!< The input pad array. */
    uint8_t opad[QSC_SHA2_512_RATE];    /*!< The output pad array. */
} qsc_hmac512_state;

/*!
 * \brief Process a message with HMAC(SHA2-512) and return the MAC code in the output byte array.
 *
 * \warning The output array must be at least 64 bytes in length.
 *
 * \param output:   [uint8_t*] The output byte array; receives the MAC code.
 * \param message:  [const uint8_t*] The message input byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 * \param key:      [const uint8_t*] The secret key array.
 * \param keylen:   [size_t] The key array length.
 */
QSC_EXPORT_API void qsc_hmac512_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key, size_t keylen);

/*!
 * \brief Dispose of the HMAC-512 state.
 *
 * \param ctx:      [qsc_hmac512_state*] Pointer to the MAC state structure.
 */
QSC_EXPORT_API void qsc_hmac512_dispose(qsc_hmac512_state* ctx);

/*!
 * \brief Finalize the HMAC-512 state and return the MAC code in the output byte array.
 *
 * \warning The output array must be sized correctly. Finalizes the message state; cannot be used in consecutive calls.
 *          The state must be initialized by the caller.
 *
 * \param ctx:      [qsc_hmac512_state*] Pointer to the MAC state structure; must be initialized.
 * \param output:   [uint8_t*] The output byte array; receives the MAC code.
 */
QSC_EXPORT_API void qsc_hmac512_finalize(qsc_hmac512_state* ctx, uint8_t* output);

/*!
 * \brief Initialize an HMAC-512 state structure with a key.
 *
 * \param ctx:      [qsc_hmac512_state*] Pointer to the MAC state structure.
 * \param key:      [const uint8_t*] Pointer to the secret key array.
 * \param keylen:   [size_t] The key array length.
 */
QSC_EXPORT_API void qsc_hmac512_initialize(qsc_hmac512_state* ctx, const uint8_t* key, size_t keylen);

/*!
 * \brief Update HMAC-512 with message input.
 *
 * \warning State must be initialized by the caller.
 *
 * \param ctx:      [qsc_hmac512_state*] Pointer to the MAC state structure.
 * \param message:  [const uint8_t*] The input message byte array.
 * \param msglen:   [size_t] The number of message bytes to process.
 */
QSC_EXPORT_API void qsc_hmac512_update(qsc_hmac512_state* ctx, const uint8_t* message, size_t msglen);

/* HKDF */

/*!
 * \brief Initialize an instance of HKDF(HMAC(SHA2-256)) and generate pseudo-random output.
 *
 * \param output:   [uint8_t*] The output pseudo-random byte array.
 * \param otplen:   [size_t] The output array length.
 * \param key:      [const uint8_t*] The HKDF key array.
 * \param keylen:   [size_t] The key array length.
 * \param info:     [const uint8_t*] The info array.
 * \param infolen:  [size_t] The info array length.
 */
QSC_EXPORT_API void qsc_hkdf256_expand(uint8_t* output, size_t otplen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/*!
 * \brief Extract a key from a combined key and salt input using HMAC(SHA2-256).
 *
 * \param output:   [uint8_t*] The output pseudo-random byte array.
 * \param otplen:   [size_t] The output array length.
 * \param key:      [const uint8_t*] The HKDF key array.
 * \param keylen:   [size_t] The key array length.
 * \param salt:     [const uint8_t*] The salt array.
 * \param saltlen:  [size_t] The salt array length.
 */
QSC_EXPORT_API void qsc_hkdf256_extract(uint8_t* output, size_t otplen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

/*!
 * \brief Initialize an instance of HKDF(HMAC(SHA2-512)) and generate pseudo-random output.
 *
 * \param output:   [uint8_t*] The output pseudo-random byte array.
 * \param otplen:   [size_t] The output array length.
 * \param key:      [const uint8_t*] The HKDF key array.
 * \param keylen:   [size_t] The key array length.
 * \param info:     [const uint8_t*] The info array.
 * \param infolen:  [size_t] The info array length.
 */
QSC_EXPORT_API void qsc_hkdf512_expand(uint8_t* output, size_t otplen, const uint8_t* key, size_t keylen, const uint8_t* info, size_t infolen);

/*!
 * \brief Extract a key from a combined key and salt input using HMAC(SHA2-512).
 *
 * \param output:   [uint8_t*] The output pseudo-random byte array.
 * \param otplen:   [size_t] The output array length.
 * \param key:      [const uint8_t*] The HKDF key array.
 * \param keylen:   [size_t] The key array length.
 * \param salt:     [const uint8_t*] The salt array.
 * \param saltlen:  [size_t] The salt array length.
 */
QSC_EXPORT_API void qsc_hkdf512_extract(uint8_t* output, size_t otplen, const uint8_t* key, size_t keylen, const uint8_t* salt, size_t saltlen);

#endif
