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
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_SCB_H
#define QSC_SCB_H

#include "common.h"
#include "sha3.h"

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
 * uint8_t rnd[200] = { 0 };
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
#define QSC_SCB_256_SEED_SIZE 32ULL

/*!
 * \def QSC_SCB_512_SEED_SIZE
 * \brief The SCB-512 seed size.
 */
#define QSC_SCB_512_SEED_SIZE 64ULL

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
#define QSC_SCB_MEMORY_MAXIMUM 128ULL

/*!
 * \def QSC_SCB_MEMORY_MINIMUM
 * \brief The minimum memory cost.
 */
#define QSC_SCB_MEMORY_MINIMUM 1ULL

/*!
 * \def QSC_SCB_CPU_MINIMUM
 * \brief The minimum CPU cost multiplier.
 */
#define QSC_SCB_CPU_MINIMUM 1ULL

/*!
 * \def QSC_SCB_CPU_MAXIMUM
 * \brief The maximum CPU cost multiplier.
 */
#define QSC_SCB_CPU_MAXIMUM 1000ULL

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
 * \param ctx:      [qsc_scb_state*] A pointer to the function state.
 * \param seed:     [const uint8_t*] A pointer to the random seed (32 bytes instantiates cSHAKE-256; 64 bytes instantiates cSHAKE-512).
 * \param seedlen:  [size_t] The length of the input seed in bytes.
 * \param info:     [const uint8_t*] A pointer to the optional personalization string.
 * \param infolen:  [size_t] The length of the personalization string in bytes.
 * \param cpucost:  [size_t] The number of iterations for the internal cost mechanism.
 * \param memcost:  [size_t] The memory cost in mebibytes (minimum 1, maximum 10000).
 */
QSC_EXPORT_API void qsc_scb_initialize(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, size_t cpucost, size_t memcost);

/**
 * \brief [void] Generate pseudo-random bytes using the random provider.
 *
 * \param ctx:      [qsc_scb_state*] A pointer to the function state.
 * \param output:   [uint8_t*] A pointer to the pseudo-random output array.
 * \param otplen:   [size_t] The number of bytes to generate.
 */
QSC_EXPORT_API void qsc_scb_generate(qsc_scb_state* ctx, uint8_t* output, size_t otplen);

/**
 * \brief [void] Update the random provider with new keying material.
 *
 * \param ctx:      [qsc_scb_state*] A pointer to the function state.
 * \param seed:     [const uint8_t*] A pointer to the random update seed.
 * \param seedlen:  [size_t] The length of the update seed in bytes.
 */
QSC_EXPORT_API void qsc_scb_update(qsc_scb_state* ctx, const uint8_t* seed, size_t seedlen);

#endif
