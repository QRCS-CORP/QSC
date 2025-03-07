/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
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
 * This software is subject to the Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL). The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_CHACHA20_H
#define QSC_CHACHA20_H

#include "common.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file chacha.h
 * \brief Contains the public API and documentation for the ChaCha20 implementation.
 *
 * \details
 * This header defines the API for the ChaCha20 stream cipher implementation. The cipher supports both
 * 128-bit and 256-bit key sizes (16 or 32 bytes respectively) and requires an 8-byte nonce for initialization.
 * The implementation includes support for AVX, AVX2, and AVX512 intrinsics where available, ensuring high-performance
 * encryption on modern processors. ChaCha20 is widely recognized for its security and efficiency in both software
 * and hardware implementations.
 *
 * \par Example Usage:
 * \code
 * #include "chacha.h"
 *
 * size_t const MSG_LEN = 1024;
 * uint8_t key[32] = { 0 };                  // 256-bit key
 * uint8_t nonce[QSC_CHACHA_NONCE_SIZE] = { 0 }; // 8-byte nonce
 * uint8_t msg[MSG_LEN] = { 0 };
 * uint8_t out[MSG_LEN] = { 0 };
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
#define QSC_CHACHA_BLOCK_SIZE 64ULL

/*!
 * \def QSC_CHACHA_KEY128_SIZE
 * \brief The size of the 128-bit secret key (in bytes).
 */
#define QSC_CHACHA_KEY128_SIZE 16ULL

/*!
 * \def QSC_CHACHA_KEY256_SIZE
 * \brief The size of the 256-bit secret key (in bytes).
 */
#define QSC_CHACHA_KEY256_SIZE 32ULL

/*!
 * \def QSC_CHACHA_NONCE_SIZE
 * \brief The size of the nonce (in bytes).
 */
#define QSC_CHACHA_NONCE_SIZE 8ULL

/*!
 * \def QSC_CHACHA_ROUND_COUNT
 * \brief The number of mixing rounds used by ChaCha20.
 */
#define QSC_CHACHA_ROUND_COUNT 20ULL

/*!
 * \struct qsc_chacha_state
 * \brief Internal state structure for the ChaCha20 cipher.
 *
 * This structure holds the 16-word internal state used during encryption/decryption.
 */
QSC_EXPORT_API typedef struct
{
    uint32_t state[16]; /*!< [uint32_t] The internal state array used by the cipher. */
} qsc_chacha_state;

/*!
 * \struct qsc_chacha_keyparams
 * \brief Key parameters for the ChaCha20 cipher.
 *
 * Contains the secret key and nonce used to initialize the cipher.
 * The key must be either 16 or 32 bytes in length, and the nonce must be 8 bytes.
 */
QSC_EXPORT_API typedef struct
{
    const uint8_t* key; /*!< [const uint8_t*] Pointer to the secret key. */
    size_t keylen;      /*!< [size_t] Length of the secret key in bytes. */
    uint8_t* nonce;     /*!< [uint8_t*] Pointer to the nonce (initialization vector). */
} qsc_chacha_keyparams;

/**
 * \brief Dispose of the ChaCha20 cipher state.
 *
 * Securely clears the internal state array.
 *
 * \param ctx:          [qsc_chacha_state*] Pointer to the ChaCha20 state structure.
 */
QSC_EXPORT_API void qsc_chacha_dispose(qsc_chacha_state* ctx);

/**
 * \brief Initialize the ChaCha20 cipher state with the secret key and nonce.
 *
 * \warning The key must be either 16 or 32 bytes in length, and the nonce must be exactly 8 bytes.
 *
 * \param ctx:          [qsc_chacha_state*] Pointer to the ChaCha20 state structure.
 * \param keyparams:    [const qsc_chacha_keyparams*] Pointer to the key parameters structure containing the key and nonce.
 */
QSC_EXPORT_API void qsc_chacha_initialize(qsc_chacha_state* ctx, const qsc_chacha_keyparams* keyparams);

/**
 * \brief Process a block of input data using the ChaCha20 cipher.
 *
 * Encrypts (or decrypts) the input data using the ChaCha20 stream cipher.
 * Since ChaCha20 is a stream cipher, the same function is used for both encryption and decryption.
 *
 * \param ctx:          [qsc_chacha_state*] Pointer to the ChaCha20 state structure.
 * \param output:       [uint8_t*] Pointer to the output byte array.
 * \param input:        [const uint8_t*] Pointer to the input byte array.
 * \param length:       [size_t] The number of bytes to process.
 */
QSC_EXPORT_API void qsc_chacha_transform(qsc_chacha_state* ctx, uint8_t* output, const uint8_t* input, size_t length);

QSC_CPLUSPLUS_ENABLED_END

#endif
