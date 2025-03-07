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
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_HCG_H
#define QSC_HCG_H

#include "common.h"
#include "sha2.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file hcg.h
 * \brief Contains the public API and documentation for the HCG pseudo-random bytes generator.
 *
 * \details
 * The HCG (HMAC-based Custom Generator) pseudo-random bytes generator is designed to produce
 * pseudo-random bytes using an HMAC-based construction similar to the HKDF Expand key derivation
 * function. It utilizes a 128-bit nonce, a default info parameter, and supports predictive resistance.
 * When predictive resistance is enabled, new random seed material is injected at initialization and
 * at defined output boundaries (default: 64 kilobytes) to convert the generator from deterministic
 * to non-deterministic. The generator state can be updated with new seed material via the update function,
 * and the dispose function must be called to securely erase the state.
 *
 * \code
 * // Example usage:
 * uint8_t seed[32] = { ... };
 * uint8_t info[32] = { ... };
 *
 * // Allocate state and output buffer
 * qsc_hcg_state ctx;
 * uint8_t rnd[200] = { 0 };
 *
 * // Initialize the generator with predictive resistance enabled
 * qsc_hcg_initialize(&ctx, seed, sizeof(seed), info, sizeof(info), true);
 *
 * // Generate pseudo-random output
 * qsc_hcg_generate(&ctx, rnd, sizeof(rnd));
 * \endcode
 *
 * \section hcg_links Reference Links:
 * - <a href="https://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf">NIST FIPS 180-4 (SHA-2 Standard)</a>
 * - <a href="https://tools.ietf.org/html/rfc2104">RFC 2104 (HMAC)</a>
 * - <a href="https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final">NIST SP 800-90A (Deterministic Random Bit Generators)</a>
 */

/*!
 * \def QSC_HCG_KEY_SIZE
 * \brief The HCG internal key size.
 */
#define QSC_HCG_KEY_SIZE 64ULL

/*!
 * \def QSC_HCG_INFO_SIZE
 * \brief The HCG default info size.
 */
#define QSC_HCG_INFO_SIZE 19ULL

/*!
 * \def QSC_HCG_MAX_INFO_SIZE
 * \brief The HCG maximum info size.
 */
#define QSC_HCG_MAX_INFO_SIZE 56ULL

/*!
 * \def QSC_HCG_NONCE_SIZE
 * \brief The HCG nonce size.
 */
#define QSC_HCG_NONCE_SIZE 8ULL

/*!
 * \def QSC_HCG_RESEED_THRESHHOLD
 * \brief The HCG reseed threshold.
 */
#define QSC_HCG_RESEED_THRESHHOLD 65535ULL

/*!
 * \def QSC_HCG_SEED_SIZE
 * \brief The HCG seed size.
 */
#define QSC_HCG_SEED_SIZE 64ULL

/*!
 * \struct qsc_hcg_state
 * \brief The HCG state structure.
 *
 * This structure holds the internal state of the HCG pseudo-random generator.
 *
 * Members:
 *   - key:    [uint8_t[QSC_HCG_KEY_SIZE]] The key cache.
 *   - info:   [uint8_t[QSC_HCG_MAX_INFO_SIZE]] The info string.
 *   - nonce:  [uint8_t[QSC_HCG_NONCE_SIZE]] The nonce array.
 *   - inflen: [size_t] The info string length.
 *   - rpos:   [size_t] The reseed position.
 *   - pres:   [bool] The predictive resistance flag.
 */
QSC_EXPORT_API typedef struct
{
    uint8_t key[QSC_HCG_KEY_SIZE];          /*!< The key cache. */
    uint8_t info[QSC_HCG_MAX_INFO_SIZE];    /*!< The info string. */
    uint8_t nonce[QSC_HCG_NONCE_SIZE];      /*!< The nonce array. */
    size_t inflen;                          /*!< The info string length. */
    size_t rpos;                            /*!< The reseed position. */
    bool pres;                              /*!< The predictive resistance flag. */
} qsc_hcg_state;

/**
 * \brief Dispose of the HCG DRBG state.
 *
 * \warning The dispose function must be called when disposing of the generator.
 *
 * \param ctx:      [qsc_hcg_state*] A pointer to the HCG state structure.
 */
QSC_EXPORT_API void qsc_hcg_dispose(qsc_hcg_state* ctx);

/**
 * \brief Initialize the pseudo-random provider state with a seed and optional personalization string.
 *
 * \param ctx:      [qsc_hcg_state*] A pointer to the HCG state structure.
 * \param seed:     [const uint8_t*] A pointer to the random seed. (32 bytes instantiates a 256-bit generator; 64 bytes instantiates a 512-bit generator.)
 * \param seedlen:  [size_t] The length of the input seed in bytes.
 * \param info:     [const uint8_t*] A pointer to the optional personalization string.
 * \param infolen:  [size_t] The length of the personalization string in bytes.
 * \param pres:     [bool] Enable predictive resistance; if true, random seed material is injected periodically.
 */
QSC_EXPORT_API void qsc_hcg_initialize(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool pres);

/**
 * \brief Generate pseudo-random bytes using the generator.
 *
 * \warning The generator must be initialized before calling this function.
 *
 * \param ctx:      [qsc_hcg_state*] A pointer to the HCG state structure.
 * \param output:   [uint8_t*] A pointer to the output buffer that will receive the pseudo-random bytes.
 * \param otplen:   [size_t] The requested number of bytes to generate.
 */
QSC_EXPORT_API void qsc_hcg_generate(qsc_hcg_state* ctx, uint8_t* output, size_t otplen);

/**
 * \brief Update the generator with new keying material.
 *
 * The new seed material is absorbed into the HMAC state.
 *
 * \param ctx:      [qsc_hcg_state*] A pointer to the HCG state structure.
 * \param seed:     [const uint8_t*] A pointer to the random update seed.
 * \param seedlen:  [size_t] The length of the update seed in bytes.
 */
QSC_EXPORT_API void qsc_hcg_update(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
