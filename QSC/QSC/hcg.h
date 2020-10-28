/* The GPL version 3 License (GPLv3)
*
* Copyright (c) 2020 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*
*
* An implementation of a HMAC based DRBG.
* Written by John G. Underhill
* Updated on August 31, 2020
* Contact: develop@vtdev.com */

/**
* \file hcg.h
* \author John Underhill
* \date August 31, 2020
*
* \brief <b>An implementation of an HMAC based DRBG: CSG</b> \n
* Contains the public api and documentation for the HCG pseudo-random bytes generator.
*
* <b>Usage Example</b> \n
*
* <b>Initialize the DRBG and generate output</b> \n
* \code
* // external key and optional custom arrays
* uint8_t seed[32] = { ... };
* uint8_t info[32] = { ... };
*
* // random bytes
* uint8_t rnd[200] = { 0 };
*
* // initialize with seed, and optional cutomization array, with predictive resistance enabled
* qsc_hcg_initialize(seed, sizeof(seed), info, sizeof(info), true);
*
* // generate the pseudo-random
* qsc_hcg_generate(rnd, sizeof(rnd)));
*
* \endcode
*
* \remarks
* \paragraph 
* HCG has a similar configuration to the HKDF Expand pseudo-random generator, but with a 128-bit nonce, and a default info parameter.
* For additional usage examples, see hcg_test.h. \n
*
* \section Links
* The HKDF Scheme: Cryptographic Extraction and Key Derivation http://eprint.iacr.org/2010/264.pdf
* RFC 2104 HMAC: Keyed-Hashing for Message Authentication http://tools.ietf.org/html/rfc2104 \n
* Fips 198-1: The Keyed-Hash Message Authentication Code (HMAC) http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf \n
* Fips 180-4: Secure Hash Standard (SHS) http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
*/

#ifndef QSC_HCG_H
#define QSC_HCG_H

#include "sha2.h"

#define QSC_HCG_CACHE_SIZE 64
#define QSC_HCG_MAX_INFO_SIZE 56
#define QSC_HCG_NONCE_SIZE 8
#define QSC_HCG_RESEED_THRESHHOLD 1024000
#define QSC_HCG_SEED_SIZE 64

/*!
* \struct qsc_hcg_state
* \brief The HCG state structure
*/
QSC_EXPORT_API typedef struct
{
	qsc_hmac512_state hstate;
	uint8_t cache[QSC_HCG_CACHE_SIZE];
	uint8_t info[QSC_HCG_MAX_INFO_SIZE];
	uint8_t nonce[QSC_HCG_NONCE_SIZE];
	size_t bctr;
	size_t cpos;
	size_t crmd;
	bool pres;
} qsc_hcg_state;

/**
* \brief Dispose of the HCG cipher state.
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The cipher state structure
*/
QSC_EXPORT_API void qsc_hcg_dispose(qsc_hcg_state* ctx);

/**
* \brief Initialize the pseudo-random provider state with a seed and optional personalization string
*
* \param seed: [const] The random seed, 32 bytes of seed instantiates the 256-bit generator, 64 bytes the 512-bit generator
* \param seedlen: The length of the input seed
* \param info: [const] The optional personalization string
* \param infolen: The length of the personalization string
* \param predictive_resistance: Enable periodic random injection; enables non deterministic pseudo-random generation
*/
QSC_EXPORT_API void qsc_hcg_initialize(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predictive_resistance);

/**
* \brief Generate pseudo-random bytes using the random provider.
*
* \warning Initialize must first be called before this function can be used.
*
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
* \param seed: [const] The random update seed
* \param seedlen: The length of the update seed
*/
QSC_EXPORT_API void qsc_hcg_update(qsc_hcg_state* ctx, const uint8_t* seed, size_t seedlen);

#endif
