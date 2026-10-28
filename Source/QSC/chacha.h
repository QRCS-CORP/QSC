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

#ifndef QSC_CHACHA20_H
#define QSC_CHACHA20_H

#include "qsccommon.h"
#include "poly1305.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file chacha.h
 * \brief Contains the public API and documentation for the ChaCha20 implementation.
 *
 * \details
 * This header defines the API for the ChaCha20 stream cipher implementation used by TLS and specified in RFC 8439. 
 * The cipher supports a standard 256-bit key and a legacy 128-bit key; the IETF profile uses a 12-byte nonce.
 * The implementation includes support for AVX, AVX2, and AVX512 intrinsics where available, ensuring high-performance
 * encryption on modern processors. ChaCha20 is widely recognized for its security and efficiency in both software
 * and hardware implementations.
 *
 * \par Example Usage:
 * \code
 * #include "chacha.h"
 *
 * size_t const MSG_LEN = 1024;
 * uint8_t key[32] = { 0U };                      // 256-bit key
 * uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0U }; // 12-byte nonce
 * uint8_t msg[MSG_LEN] = { 0U };
 * uint8_t out[MSG_LEN] = { 0U };
 *
 * qsc_chacha_state ctx;
 * qsc_chacha_keyparams kp = { key, 32, nonce };
 *
 * qsc_chacha_initialize(&ctx, &kp);
 * qsc_chacha_transform(&ctx, out, msg, MSG_LEN);
 * \endcode
 *
 * \section chacha_links Reference Links:
 * - <a href="https://cr.yp.to/chacha/chacha-20080120.pdf">ChaCha20 Stream Cipher Specification</a>
 */

/*!
 * \def QSC_CHACHA_BLOCK_SIZE
 * \brief The internal block size used by the ChaCha20 cipher (in bytes).
 */
#define QSC_CHACHA_BLOCK_SIZE 64U

/*!
 * \def QSC_CHACHA_KEY128_SIZE
 * \brief The size of the 128-bit secret key (in bytes).
 */
#define QSC_CHACHA_KEY128_SIZE 16U

/*!
 * \def QSC_CHACHA_KEY256_SIZE
 * \brief The size of the 256-bit secret key (in bytes).
 */
#define QSC_CHACHA_KEY256_SIZE 32U

/*!
 * \def QSC_CHACHA_NONCE_SIZE
 * \brief The size of the nonce in bytes.
 */
#define QSC_CHACHA_NONCE_SIZE 12U

/*!
 * \def QSC_CHACHA_ROUND_COUNT
 * \brief The number of mixing rounds used by ChaCha20.
 */
#define QSC_CHACHA_ROUND_COUNT 20U

/*!
 * \struct qsc_chacha_state
 * \brief Internal state structure for the ChaCha20 cipher.
 *
 * This structure holds the 16-word internal state used during encryption/decryption.
 */
QSC_EXPORT_API typedef struct
{
    uint32_t state[16U];    /*!< [uint32_t] ChaCha words: counter is word 12, nonce is words 13-15. */
    uint8_t stream[QSC_CHACHA_BLOCK_SIZE]; /*!< [uint8_t] Unconsumed partial-block keystream. */
    size_t available;       /*!< [size_t] Number of unread keystream bytes in stream. */
    bool exhausted;         /*!< [bool] True once the final RFC 8439 counter block has been generated. */
} qsc_chacha_state;

/*!
 * \struct qsc_chacha_keyparams
 * \brief Key parameters for the ChaCha20 cipher.
 *
 * Contains the secret key and nonce used to initialize the cipher.
 * The key must be 16 or 32 bytes; standard RFC 8439 uses 32 bytes and a 12-byte nonce.
 */
QSC_EXPORT_API typedef struct
{
    const uint8_t* key;         /*!< [const uint8_t*] Pointer to the secret key. */
    size_t keylen;              /*!< [size_t] Length of the secret key in bytes. */
    uint8_t* nonce;             /*!< [uint8_t*] Pointer to the nonce (initialization vector). */
} qsc_chacha_keyparams;

/**
 * \brief Dispose of the ChaCha20 cipher state.
 *
 * Securely clears the internal state, cached keystream, and counter-exhaustion flags.
 *
 * \param ctx: [qsc_chacha_state*] Pointer to the ChaCha20 state structure.
 */
QSC_EXPORT_API void qsc_chacha_dispose(qsc_chacha_state* ctx);

/**
 * \brief Initialize the ChaCha20 cipher state with the secret key and nonce.
 *
 * \warning The key must be either 16 or 32 bytes in length, and the nonce must be exactly 12 bytes.
 * Key parameters and their buffers must not overlap ctx.
 *
 * \param ctx: [qsc_chacha_state*] Pointer to the ChaCha20 state structure.
 * \param keyparams: [const qsc_chacha_keyparams*] Pointer to the key parameters structure containing the key and nonce.
 */
QSC_EXPORT_API void qsc_chacha_initialize(qsc_chacha_state* ctx, const qsc_chacha_keyparams* keyparams);

/**
 * \brief Process a block of input data using the ChaCha20 cipher.
 *
 * Encrypts (or decrypts) the input data using the ChaCha20 stream cipher.
 * Since ChaCha20 is a stream cipher, the same function is used for both encryption and decryption.
 * Partial-block keystream is retained between calls. On counter exhaustion this
 * legacy void function clears the requested output; use the checked form to
 * preserve output and report failure explicitly. Exact in-place operation is supported;
 * partially overlapping input/output buffers are not supported.
 *
 * \param ctx: [qsc_chacha_state*] Pointer to the ChaCha20 state structure.
 * \param output: [uint8_t*] Pointer to the output byte array.
 * \param input: [const uint8_t*] Pointer to the input byte array.
 * \param length: [size_t] The number of bytes to process.
 */
QSC_EXPORT_API void qsc_chacha_transform(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/**
 * \brief Transform ChaCha20 bytes with counter-exhaustion reporting.
 * \param ctx: [qsc_chacha_state*] Initialized cipher state.
 * \param output: [uint8_t*] Writable output, at least length bytes.
 * \param input: [const uint8_t*] Readable input, at least length bytes; may equal output.
 * \param length: [size_t] Number of bytes to transform.
 * \return [bool] True if all requested bytes were processed; false on invalid parameters or counter exhaustion.
 * \warning Changing the size of qsc_chacha_state requires rebuilding dependent binaries.
 * \note A failure leaves input/output and the cipher state unmodified.
 */
QSC_EXPORT_API bool qsc_chacha_transform_checked(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/* chacha-poly1305*/

QSC_EXPORT_API typedef struct 
{
    qsc_chacha_state cstate;      /*!< The ChaCha20 context. */
    qsc_poly1305_state pstate;    /*!< The Poly1305 context. */
    size_t aadlen;                /*!< The total AAD length */
    size_t msglen;                /*!< The total message length */
} qsc_chacha_poly1305_state;

/**
 * \brief Set the associated data (AAD) for ChaCha-Poly1305 authenticated encryption.
 *
 * The associated data authenticates headers and other data without encrypting them.
 * Call at most once per initialized record, before encryption or decryption.
 * The AAD is padded immediately; this is not an incremental AAD update API.
 * A NULL data pointer is accepted only when datalen is zero. The context is
 * single-use: initialize afresh for each record and nonce.
 *
 * \param ctx: [struct] Pointer to the qsc_chacha_poly1305_state structure.
 * \param data:	[const uint8_t*] Pointer to the associated data.
 * \param datalen: [size_t] Length of the associated data in bytes.
 *
 * \sa qsc_chacha_poly1305_encrypt
 */
QSC_EXPORT_API void qsc_chacha_poly1305_set_associated(qsc_chacha_poly1305_state* ctx, const uint8_t* data, size_t datalen);

/**
 * \brief Decrypt data using the ChaCha-Poly1305 authenticated encryption mode.
 *
 * Authenticates the ciphertext and appended 16-byte tag before producing plaintext.
 * On tag mismatch, no plaintext is written. The state is consumed even on
 * authentication failure; initialize a new context for the next record. Cipher and MAC
 * state are erased after each completed authentication attempt; reuse is rejected.
 *
 * \param ctx: [struct] Pointer to an initialized qsc_chacha_poly1305_state structure.
 * \param output: [uint8_t*] Pointer to the plaintext buffer.
 * \param input: [const uint8_t*] Pointer to the ciphertext data with the appended MAC.
 * \param length: [size_t] Total input length, including the appended 16-byte MAC.
 *
 * \return [bool] Returns \c true if the MAC verification and transformation was successful; otherwise, \c false.
 *
 * \sa qsc_chacha_poly1305_initialize, qsc_chacha_poly1305_set_associated
 */
QSC_EXPORT_API bool qsc_chacha_poly1305_decrypt(qsc_chacha_poly1305_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/*!
 * \brief Dispose of an ChaCha-Poly1305 state.
 *
 * Securely clears all internal state and keys used by the ChaCha-Poly1305 authenticated encryption mode.
 *
 * \param ctx: [struct] Pointer to a qsc_chacha_poly1305_state structure.
 *
 * \warning Must be called before the state goes out of scope.
 *
 * \sa qsc_chacha_poly1305_set_associated, qsc_chacha_poly1305_decrypt, qsc_chacha_poly1305_encrypt, qsc_chacha_poly1305_initialize
 */
QSC_EXPORT_API void qsc_chacha_poly1305_dispose(qsc_chacha_poly1305_state* ctx);

/**
 * \brief Initialize the ChaCha-Poly1305 state for authenticated encryption or decryption.
 *
 * Initializes the cipher and derives the one-time Poly1305 key from counter zero.
 * A 32-byte key is required for RFC 8439 interoperability. The existing 16-byte
 * key mode is retained for legacy compatibility, not as a standard RFC 8439 AEAD.
 * Each initialized state processes one authenticated record. Key parameters and their
 * buffers must not overlap ctx. Invalid parameters erase the previous state.
 * 
 * \warning When using a CTR based construction (ChachaP20 or ChachaP20-Poly1305), the nonce must be unique for a given key.
 * Re-using a nonce-key pair on a different plaintext input represents a catastrophic loss of security.
 *
 * \param ctx: [struct] Pointer to a qsc_chacha_poly1305_state structure to initialize.
 * \param keyparams: [const struct] Pointer to a constant qsc_chacha_keyparams structure that provides the key.
 *
 * \warning Must be called before using qsc_chacha_poly1305_set_associated, qsc_chacha_poly1305_encrypt or qsc_chacha_poly1305_decrypt.
 *
 * \sa qsc_chacha_poly1305_decrypt, qsc_chacha_poly1305_encrypt, qsc_chacha_poly1305_dispose
 */
QSC_EXPORT_API void qsc_chacha_poly1305_initialize(qsc_chacha_poly1305_state* ctx, const qsc_chacha_keyparams* keyparams);

/**
 * \brief Encrypt data using the ChaCha-Poly1305 authenticated encryption mode.
 *
 * In encryption mode, this function encrypts the plaintext using ChaCha20, computes a MAC
 * over the ciphertext, and appends the MAC to the output. On success, the entire
 * record state is erased and further operations require fresh initialization.
 *
 * \param ctx: [struct] Pointer to an initialized qsc_chacha_poly1305_state structure.
 * \param output: [uint8_t*] Pointer to the output buffer, must be large enough to hold ciphertext plus MAC.
 * \param input: [const uint8_t*] Pointer to the plaintext; may equal output. A NULL pointer is valid only for an empty plaintext.
 * \param length: [size_t] Length of the input data in bytes (excluding the MAC for decryption).
 *
 * \sa qsc_chacha_poly1305_initialize, qsc_chacha_poly1305_set_associated
 */
QSC_EXPORT_API void qsc_chacha_poly1305_encrypt(qsc_chacha_poly1305_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

/**
 * \brief Encrypt and authenticate with explicit counter-exhaustion reporting.
 * \param ctx: [qsc_chacha_poly1305_state*] Initialized cipher and authenticator.
 * \param output: [uint8_t*] Ciphertext plus 16-byte tag buffer.
 * \param input: [const uint8_t*] Plaintext buffer, may equal output.
 * \param length: [size_t] Plaintext byte count.
 * \return [bool] True on complete success, false if the record cannot be processed safely.
 * \note On error the output and stream counter are not modified. The caller
 * must provide space for length plus 16 authentication-tag bytes.
 */
QSC_EXPORT_API bool qsc_chacha_poly1305_encrypt_checked(qsc_chacha_poly1305_state* ctx, uint8_t* output,
    const uint8_t* input, size_t length);

QSC_CPLUSPLUS_ENABLED_END

#endif
