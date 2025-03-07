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

#ifndef QSC_CSG_H
#define QSC_CSG_H

#include "common.h"
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
 * uint8_t rnd[200] = { 0 };
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
#define QSC_CSG_256_SEED_SIZE 32ULL

/*!
 * \def QSC_CSG_512_SEED_SIZE
 * \brief The CSG-512 seed size in bytes.
 */
#define QSC_CSG_512_SEED_SIZE 64ULL

/*!
 * \def QSC_CSG_RESEED_THRESHHOLD
 * \brief The re-seed threshold interval in bytes.
 */
#define QSC_CSG_RESEED_THRESHHOLD 1024000ULL

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
