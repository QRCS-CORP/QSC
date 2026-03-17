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

#ifndef QSCTEST_NISTRNG_H
#define QSCTEST_NISTRNG_H

 /* \cond NO_DOCUMENT */

/**
* \file nistrng.h
* \brief This is not a secure RNG, and should be used for testing purposes only.
*/

#include "qsccommon.h"

/*!
* \def QSCTEST_NIST_RNG_SEED_SIZE
* \brief The rng seed size
*/
#define QSCTEST_NIST_RNG_SEED_SIZE 48

/*!
* \def QSCTEST_NIST_RNG_SUCCESS
* \brief The success return value
*/
#define QSCTEST_NIST_RNG_SUCCESS 0

/*!
* \def QSCTEST_NIST_RNG_BAD_MAXLEN
* \brief The bad length return value
*/
#define QSCTEST_NIST_RNG_BAD_MAXLEN -1

/*!
* \def QSCTEST_NIST_RNG_BAD_OUTBUF
* \brief The bad buffer size return value
*/
#define QSCTEST_NIST_RNG_BAD_OUTBUF -2

/*!
* \def QSCTEST_NIST_RNG_BAD_REQ_LEN
* \brief The bad request return value
*/
#define QSCTEST_NIST_RNG_BAD_REQ_LEN -3

/*! \struct qsctest_nist_rng_state
* \brief The rng state
*/
typedef struct
{
    uint8_t state[16];  /*!< The internal state array */
    uint32_t bpos;      /*!< The byte position */
    uint32_t rmdr;      /*!< The remainder in a block */
    uint8_t key[32];    /*!< The input key */
    uint8_t ctr[16];    /*!< The internal nonce */
} qsctest_nist_rng_state;

/*! \struct qsctest_nist_aes256_state
* \brief The AES state structure
*/
typedef struct
{
    uint8_t key[32];    /*!< The aes key */
    uint8_t ctr[16];    /*!< The nonce */
	uint32_t rctr;      /*!< The block counter */
} qsctest_nist_aes256_state;

 /**
 * \brief Initialize a user supplied KDF state instance
 *
 * \param ctx stores the current state of an instance of the seed expander
 * \param seed a 32 byte random value
 * \param diversifier an 8 byte diversifier
 * \param maxlen maximum number of bytes (less than 2**32) generated under this seed and diversifier
 * 
 * \return 0 for success
 */
int32_t qsctest_nistrng_kdf_initialize(qsctest_nist_rng_state* ctx, const uint8_t* seed, const uint8_t* diversifier, uint32_t maxlen);

 /**
 * \brief Expand a seed into a larger array with a user supplied state instance
 *
 * \param ctx stores the current state of an instance of the seed expander
 * \param output the expanded seed
 * \param outlen the requested size of the expanded seed
 * 
 * \return 0 for success
 */
int32_t qsctest_nistrng_kdf_generate(qsctest_nist_rng_state* ctx, uint8_t* output, size_t outlen);

/**
* \brief Initialize the random provider state with a seed
* and optional personalization string
*
* \param seed 48 bytes of random seed
* \param info the optional personalization string
* \param infolen the length of the personalization string, can not exceed 48 bytes
*/
void qsctest_nistrng_prng_initialize(const uint8_t* seed, const uint8_t* info, size_t infolen);

/**
* \brief Generate pseudo-random bytes using the random provider
* Initialize must first be called with a random seed
*
* \param output the pseudo-random output array
* \param outlen the requested number of bytes to generate
* 
* \return true for success
*/
bool qsctest_nistrng_prng_generate(uint8_t* output, size_t outlen);

/**
* \brief Update the random provider with new keying material
*
* \param key the DRBG key
* \param counter the DRBG counter
* \param info the optional personalization string
* \param infolen the length of the personalization string, can not exceed 48 bytes
*/
void qsctest_nistrng_prng_update(uint8_t* key, uint8_t* counter, const uint8_t* info, size_t infolen);

/**
* \brief Initialize the SHAKE256-based random provider state with a seed
* and optional personalization string.
* Implements the HQC next-release PRNG: SHAKE256(seed[48] || info || 0x00),
* squeezing continuously on each generate call.
*
* \param seed 48 bytes of random seed
* \param info the optional personalization string, or NULL
* \param infolen the length of the personalization string in bytes, or 0
*/
void qsctest_nistrng2_prng_initialize(const uint8_t* seed, const uint8_t* info, size_t infolen);

/**
* \brief Generate pseudo-random bytes using the SHAKE256-based random provider.
* qsctest_nistrng2_prng_initialize must first be called with a random seed.
* Each call squeezes the requested bytes from the persistent SHAKE256 state;
* no re-keying is performed between calls.
*
* \param output the pseudo-random output array
* \param outlen the requested number of bytes to generate
*
* \return true for success, false if output is NULL or outlen is zero
*/
bool qsctest_nistrng2_prng_generate(uint8_t* output, size_t outlen);

/* \endcond NO_DOCUMENT */

#endif
