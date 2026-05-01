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

#ifndef QSC_SCB_H
#define QSC_SCB_H

#include "qsccommon.h"
#include "sha3.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file scb.h
 * \brief Contains the public API and documentation for the SCB pseudo-random bytes generator.
 *
 * \details
 * SCB (SHAKE Cost Based Key Derivation Function) is a cost-based KDF that employs the Keccak cSHAKE XOF to 
 * generate pseudo-random bytes from a seeded custom SHAKE generator. Depending on the key length, it uses either 
 * cSHAKE-256 (for 32-byte keys) or cSHAKE-512 (for 64-byte keys). Additionally, SCB incorporates a cost mechanism 
 * with configurable CPU and memory costs to resist brute-force attacks.
 *
 * \par Example Usage:
 * \code
 * // External key and optional info arrays
 * uint8_t seed[32] = { ... };
 * uint8_t info[32] = { ... };
 *
 * // Output bytes buffer
 * uint8_t rnd[200] = { 0U };
 *
 * // Initialize with seed, optional info, CPU cost of 2 iterations, and memory cost of 1 MiB
 * qsc_scb_initialize(ctx, seed, sizeof(seed), info, sizeof(info), 2, 1);
 *
 * // Generate pseudo-random output
 * qsc_scb_generate(ctx, rnd, sizeof(rnd));
 * \endcode
 *
 * \section scb_links Reference Links:
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 Specification (FIPS 202)</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf">NIST Pseudorandom Generator Guidelines (SP 800-90A)</a>
 */

/*!
 * \def QSC_SCB_256_SEED_SIZE
 * \brief The SCB-256 seed size.
 */
#define QSC_SCB_256_SEED_SIZE 32U

/*!
 * \def QSC_SCB_512_SEED_SIZE
 * \brief The SCB-512 seed size.
 */
#define QSC_SCB_512_SEED_SIZE 64U

/*!
 * \def QSC_SCB_L2CACHE_DEFAULT_SIZE
 * \brief The default L2 cache size (256 KiB).
 */
#define QSC_SCB_L2CACHE_DEFAULT_SIZE (1024ULL * 256ULL)

/*!
 * \def QSC_SCB_MEMORY_COST_SIZE
 * \brief The base memory cost of 1 MiB.
 */
#define QSC_SCB_MEMORY_COST_SIZE (1024ULL * 1024ULL)

/*!
 * \def QSC_SCB_MEMORY_MAXIMUM
 * \brief The maximum memory cost.
 */
#define QSC_SCB_MEMORY_MAXIMUM 128U

/*!
 * \def QSC_SCB_MEMORY_MINIMUM
 * \brief The minimum memory cost.
 */
#define QSC_SCB_MEMORY_MINIMUM 1U

/*!
 * \def QSC_SCB_CPU_MINIMUM
 * \brief The minimum CPU cost multiplier.
 */
#define QSC_SCB_CPU_MINIMUM 1U

/*!
 * \def QSC_SCB_CPU_MAXIMUM
 * \brief The maximum CPU cost multiplier.
 */
#define QSC_SCB_CPU_MAXIMUM 1000U

/*!
 * \struct qsc_scb_state
 * \brief The SCB state structure.
 *
 * This structure holds the internal state of the SCB pseudo-random generator.
 */
QSC_EXPORT_API typedef struct
{
    uint8_t ckey[QSC_SCB_512_SEED_SIZE];    /*!< The cache generation key. */
    size_t cpuc;                            /*!< The CPU cost. */
    size_t memc;                            /*!< The memory cost. */
    size_t klen;                            /*!< The cache key length. */
    qsc_keccak_rate rate;                   /*!< The absorption rate. */
} qsc_scb_state;

/**
 * \brief [void] Dispose of the DRBG state.
 *
 * \param ctx:      [qsc_scb_state*] A pointer to the DRBG state structure.
 */
QSC_EXPORT_API void qsc_scb_dispose(qsc_scb_state* ctx);

/**
 * \brief [void] Initialize the pseudo-random provider state with a seed and optional personalization string.
 *
 * \param ctx: [qsc_scb_state*] A pointer to the function state.
 * \param seed: [const uint8_t*] A pointer to the random seed (32 bytes instantiates cSHAKE-256; 64 bytes instantiates cSHAKE-512).
 * \param seedlen: [size_t] The length of the input seed in bytes.
 * \param info: [const uint8_t*] A pointer to the optional personalization string.
 * \param infolen: [size_t] The length of the personalization string in bytes.
 * \param cpucost: [size_t] The number of iterations for the internal cost mechanism.
 * \param memcost: [size_t] The memory cost in mebibytes (minimum 1, maximum 10000).
 */
QSC_EXPORT_API void qsc_scb_initialize(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, size_t cpucost, size_t memcost);

/**
 * \brief [void] Generate pseudo-random bytes using the random provider.
 *
 * \param ctx: [qsc_scb_state*] A pointer to the function state.
 * \param output: [uint8_t*] A pointer to the pseudo-random output array.
 * \param otplen: [size_t] The number of bytes to generate.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_scb_generate(qsc_scb_state* ctx, uint8_t* output, size_t otplen);

/**
 * \brief [void] Update the random provider with new keying material.
 *
 * \param ctx: [qsc_scb_state*] A pointer to the function state.
 * \param seed: [const uint8_t*] A pointer to the random update seed.
 * \param seedlen: [size_t] The length of the update seed in bytes.
 */
QSC_EXPORT_API void qsc_scb_update(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
