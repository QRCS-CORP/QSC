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

#ifndef QSC_HCG_H
#define QSC_HCG_H

#include "qsccommon.h"
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
 * uint8_t rnd[200] = { 0U };
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
 * \param ctx: [qsc_hcg_state*] A pointer to the HCG state structure.
 * \param seed: [const uint8_t*] A pointer to the random seed. (32 bytes instantiates a 256-bit generator; 64 bytes instantiates a 512-bit generator.)
 * \param seedlen: [size_t] The length of the input seed in bytes.
 * \param info: [const uint8_t*] A pointer to the optional personalization string.
 * \param infolen: [size_t] The length of the personalization string in bytes.
 * \param pres: [bool] Enable predictive resistance; if true, random seed material is injected periodically.
 */
QSC_EXPORT_API void qsc_hcg_initialize(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool pres);

/**
 * \brief Generate pseudo-random bytes using the generator.
 *
 * \warning The generator must be initialized before calling this function.
 *
 * \param ctx: [qsc_hcg_state*] A pointer to the HCG state structure.
 * \param output: [uint8_t*] A pointer to the output buffer that will receive the pseudo-random bytes.
 * \param otplen: [size_t] The requested number of bytes to generate.
 */
QSC_EXPORT_API void qsc_hcg_generate(qsc_hcg_state* ctx, uint8_t* output, size_t otplen);

/**
 * \brief Update the generator with new keying material.
 *
 * The new seed material is absorbed into the HMAC state.
 *
 * \param ctx: [qsc_hcg_state*] A pointer to the HCG state structure.
 * \param seed: [const uint8_t*] A pointer to the random update seed.
 * \param seedlen: [size_t] The length of the update seed in bytes.
 */
QSC_EXPORT_API void qsc_hcg_update(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
