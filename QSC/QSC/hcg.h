/*
* 2022 John G. Underhill
* All Rights Reserved.
*
* NOTICE:  All information contained herein is, and remains
* the property of John G. Underhill.
* The intellectual and technical concepts contained
* herein are proprietary to John G. Underhill
* and his suppliers and may be covered by U.S. and Foreign Patents,
* patents in process, and are protected by trade secret or copyright law.
* Dissemination of this information or reproduction of this material
* is strictly forbidden unless prior written permission is obtained
* from Digital Freedom Defense Incorporated.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*
* This library was published publicly in hopes that it would aid in prototyping
* post-quantum secure primitives for educational purposes only.
* All and any commercial uses of this library are exclusively reserved by the author
* John G. Underhill.
* Any use of this library in a commercial context must be approved by the author
* in writing.
* All rights for commercial and/or non-educational purposes, are fully reserved
* by the author.
*/

#ifndef QSC_HCG_H
#define QSC_HCG_H

#include "sha2.h"

/**
* \file hcg.h
* \brief Contains the public api and documentation for the HCG pseudo-random bytes generator
* \author John Underhill
* \date August 31, 2020
*
* Usage Example \n
*
* Initialize the DRBG and generate output \n
* \code
* // external key and optional custom arrays
* uint8_t seed[32] = { ... };
* uint8_t info[32] = { ... };
*
* // random bytes
* uint8_t rnd[200] = { 0 };
*
* // initialize with seed, and optional customization array, with predictive resistance enabled
* qsc_hcg_initialize(seed, sizeof(seed), info, sizeof(info), true);
*
* // generate the pseudo-random
* qsc_hcg_generate(rnd, sizeof(rnd)));
*
* \endcode
*
* \remarks
* \par
* HCG has a similar configuration to the HKDF Expand pseudo-random generator, but with a 128-bit nonce, and a default info parameter.
* For additional usage examples, see hcg_test.h. \n
*
* The HKDF Scheme: Cryptographic Extraction and Key Derivation http://eprint.iacr.org/2010/264.pdf
* RFC 2104 HMAC: Keyed-Hashing for Message Authentication http://tools.ietf.org/html/rfc2104 \n
* Fips 198-1: The Keyed-Hash Message Authentication Code (HMAC) http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf \n
* Fips 180-4: Secure Hash Standard (SHS) http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
*/

/*!
* \def QSC_HCG_CACHE_SIZE
* \brief The HCG cache size size
*/
#define QSC_HCG_CACHE_SIZE 64

/*!
* \def QSC_HCG_MAX_INFO_SIZE
* \brief The HCG info size
*/
#define QSC_HCG_MAX_INFO_SIZE 56

/*!
* \def QSC_HCG_NONCE_SIZE
* \brief The HCG nonce size
*/
#define QSC_HCG_NONCE_SIZE 8

/*!
* \def QSC_HCG_RESEED_THRESHHOLD
* \brief The HCG re-seed size
*/
#define QSC_HCG_RESEED_THRESHHOLD 1024000

/*!
* \def QSC_HCG_SEED_SIZE
* \brief The HCG seed size
*/
#define QSC_HCG_SEED_SIZE 64

/*!
* \struct qsc_hcg_state
* \brief The HCG state structure
*/
QSC_EXPORT_API typedef struct
{
	qsc_hmac512_state hstate;				/*!< The hmac state  */
	uint8_t cache[QSC_HCG_CACHE_SIZE];		/*!< The cache buffer  */
	uint8_t info[QSC_HCG_MAX_INFO_SIZE];	/*!< The info string  */
	uint8_t nonce[QSC_HCG_NONCE_SIZE];		/*!< The nonce array  */
	size_t bctr;							/*!< The bytes counter  */
	size_t cpos;							/*!< The cache position  */
	size_t crmd;							/*!< The cache remainder  */
	bool pres;								/*!< The predictive resistance flag  */
} qsc_hcg_state;

/**
* \brief Dispose of the HCG DRBG state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The HCG state structure
*/
QSC_EXPORT_API void qsc_hcg_dispose(qsc_hcg_state* ctx);

/**
* \brief Initialize the pseudo-random provider state with a seed and optional personalization string
*
* \param ctx: [struct] The hcg state structure
* \param seed: [const] The random seed, 32 bytes of seed instantiates the 256-bit generator, 64 bytes the 512-bit generator
* \param seedlen: The length of the input seed
* \param info: [const] The optional personalization string
* \param infolen: The length of the personalization string
* \param pres: Enable periodic random injection; enables non deterministic pseudo-random generation
*/
QSC_EXPORT_API void qsc_hcg_initialize(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool pres);

/**
* \brief Generate pseudo-random bytes using the random provider.
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The HCG state structure
* \param output: The pseudo-random output array
* \param outlen: The requested number of bytes to generate
* \return The number of bytes generated
*/
QSC_EXPORT_API void qsc_hcg_generate(qsc_hcg_state* ctx, uint8_t* output, size_t outlen);

/**
* \brief Update the random provider with new keying material
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The HCG state structure
* \param seed: [const] The random update seed
* \param seedlen: The length of the update seed
*/
QSC_EXPORT_API void qsc_hcg_update(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen);

#endif
