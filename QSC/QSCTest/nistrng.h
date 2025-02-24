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


#ifndef QSCTEST_NISTRNG_H
#define QSCTEST_NISTRNG_H

/* \cond DOXYGEN_IGNORE */

/**
* \file nistrng.h
* \brief This is not a secure RNG, and should be used for testing purposes only.
*/

#include "../QSC/common.h"

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

/* \endcond DOXYGEN_IGNORE */

#endif
