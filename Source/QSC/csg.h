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

#ifndef QSC_CSG_H
#define QSC_CSG_H

#include "qsccommon.h"
#include "sha3.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file csg.h
 * \brief Contains the public API and documentation for the CSG pseudo-random bytes generator.
 *
 * \details
 * The CSG (Custom SHAKE Generator) pseudo-random bytes generator uses the Keccak cSHAKE XOF function
 * to produce pseudo-random bytes from seeded custom SHAKE generators. If a 32-byte seed is used, the implementation
 * uses cSHAKE-256; if a 64-byte seed is used, cSHAKE-512 is used. An optional predictive resistance feature,
 * enabled during initialization, injects random bytes periodically into the generator for non-deterministic output.
 *
 * \par Example Usage:
 * \code
 * // external key and optional custom arrays
 * uint8_t seed[32] = { ... };
 * uint8_t info[32] = { ... };
 *
 * // random bytes
 * uint8_t rnd[200] = { 0U };
 *
 * // initialize with seed and optional personalization; enable predictive resistance
 * qsc_csg_initialize(ctx, seed, sizeof(seed), info, sizeof(info), true);
 *
 * // generate the pseudo-random output
 * qsc_csg_generate(ctx, rnd, sizeof(rnd));
 * \endcode
 *
 * \remarks
 * CSG uses the Keccak cSHAKE XOF function for pseudo-random generation. It caches pseudo-random bytes internally
 * so that the generator can be reused without re-initialization in an online configuration. The generator can also be updated
 * with new seed material.
 *
 * \section csg_links Reference Links:
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS 202: SHA-3 Standard</a>
 * - <a href="https://csrc.nist.gov/publications/detail/sp/800-90a/rev-1/final">NIST Special Publication 800-90A</a>
 */

/*!
 * \def QSC_CSG_256_SEED_SIZE
 * \brief The CSG-256 seed size in bytes.
 */
#define QSC_CSG_256_SEED_SIZE 32UL

/*!
 * \def QSC_CSG_512_SEED_SIZE
 * \brief The CSG-512 seed size in bytes.
 */
#define QSC_CSG_512_SEED_SIZE 64UL

/*!
 * \def QSC_CSG_RESEED_THRESHHOLD
 * \brief The re-seed threshold interval in bytes.
 */
#define QSC_CSG_RESEED_THRESHHOLD 1024000UL

/*!
 * \struct qsc_csg_state
 * \brief The CSG state structure.
 *
 * This structure holds the internal state of the CSG pseudo-random generator.
 */
QSC_EXPORT_API typedef struct
{
    qsc_keccak_state kstate;            /*!< The Keccak state. */
    uint8_t cache[QSC_KECCAK_256_RATE]; /*!< The cache buffer. */
    size_t bctr;                        /*!< The bytes counter. */
    size_t cpos;                        /*!< The cache position. */
    size_t crmd;                        /*!< The cache remainder. */
    size_t rate;                        /*!< [The absorption rate. */
    bool pres;                          /*!< The predictive resistance flag. */
} qsc_csg_state;

/**
 * \brief Dispose of the DRBG state.
 *
 * Securely destroys the internal state of the DRBG.
 *
 * \param ctx:      [qsc_csg_state*] Pointer to the DRBG state structure.
 */
QSC_EXPORT_API void qsc_csg_dispose(qsc_csg_state* ctx);

/**
 * \brief Initialize the pseudo-random provider state with a seed and optional personalization string.
 *
 * The seed must be either 32 bytes (for a 256-bit generator) or 64 bytes (for a 512-bit generator).
 * An optional personalization string and a predictive resistance flag may also be provided.
 *
 * \param ctx:      [qsc_csg_state*] Pointer to the DRBG state structure.
 * \param seed:     [const uint8_t*] Pointer to the random seed. (32 bytes instantiates cSHAKE-256; 64 bytes instantiates cSHAKE-512.)
 * \param seedlen:  [size_t] The length of the seed in bytes.
 * \param info:     [const uint8_t*] Pointer to the optional personalization string.
 * \param infolen:  [size_t] The length of the personalization string in bytes.
 * \param predres:  [bool] Enable predictive resistance; if true, random bytes are injected periodically.
 */
QSC_EXPORT_API void qsc_csg_initialize(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predres);

/**
 * \brief Generate pseudo-random bytes.
 *
 * Generates pseudo-random output using the DRBG. The generator must be initialized first.
 *
 * \param ctx:      [qsc_csg_state*] Pointer to the DRBG state structure.
 * \param output:   [uint8_t*] Pointer to the output array for pseudo-random bytes.
 * \param otplen:   [size_t] The number of bytes to generate.
 */
QSC_EXPORT_API void qsc_csg_generate(qsc_csg_state* ctx, uint8_t* output, size_t otplen);

/**
 * \brief Update the DRBG with new seed material.
 *
 * The new seed material is absorbed into the Keccak state.
 *
 * \param ctx:      [qsc_csg_state*] Pointer to the DRBG state structure.
 * \param seed:     [const uint8_t*] Pointer to the update seed.
 * \param seedlen:  [size_t] The length of the update seed in bytes.
 */
QSC_EXPORT_API void qsc_csg_update(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
