/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2021 Digital Freedom Defence Inc.
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef QSC_CSG_H
#define QSC_CSG_H

/**
* \file csg.h
* \brief Contains the public api and documentation for the CSG pseudo-random bytes generator
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
* qsc_csg_initialize(seed, sizeof(seed), info, sizeof(info), true);
*
* // generate the pseudo-random
* qsc_csg_generate(rnd, sizeof(rnd)));
*
* \endcode
*
* \remarks
* \par
* CSG uses the Keccak cSHAKE XOF function to produce pseudo-random bytes from a seeded custom SHAKE generator. \n
* If a 32-byte key is used, the implementation uses the cSHAKE-256 implementation for pseudo-random generation, if a 64-byte key is used, the generator uses cSHAKE-512. \n
* An optional predictive resistance feature, enabled through the initialize function, injects random bytes into the generator at initialization and 1MB intervals,
* creating a non-deterministic pseudo-random output. \n
* Pseudo random bytes are cached internally, and the generator can be initialized and then reused without requiring re-initialization in an online configuration. \n
* The generator can be updated with new seed material, which is absorbed into the Keccak state.
*
* For additional usage examples, see csg_test.h. \n
*
* NIST: SHA3 Fips202 http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
* NIST: SP800-185 http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pd
* NIST: SHA3 Keccak Submission http://keccak.noekeon.org/Keccak-submission-3.pdf
* NIST: SHA3 Keccak Slides http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf
* NIST: SHA3 Third-Round Report http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf
* Team Keccak: Specifications summary https://keccak.team/keccak_specs_summary.html
*/

#include "common.h"
#include "sha3.h"

/*!
* \def QSC_CSG256_SEED_SIZE
* \brief The CSG-256 seed size
*/
#define QSC_CSG256_SEED_SIZE 32

/*!
* \def QSC_CSG512_SEED_SIZE
* \brief The CSG-512 seed size
*/
#define QSC_CSG512_SEED_SIZE 64

/*!
* \def QSC_CSG_RESEED_THRESHHOLD
* \brief The CSG re-seed threshold interval
*/
#define QSC_CSG_RESEED_THRESHHOLD 1024000

/*!
* \struct qsc_csg_state
* \brief The CSG state structure
*/
QSC_EXPORT_API typedef struct
{
    qsc_keccak_state kstate;            /*!< The Keccak state  */
    uint8_t cache[QSC_KECCAK_256_RATE]; /*!< The cache buffer */
    size_t bctr;                        /*!< The bytes counter  */
    size_t cpos;                        /*!< The cache position  */
    size_t crmd;                        /*!< The cache remainder  */
    size_t rate;                        /*!< The absorption rate  */
    bool pres;                          /*!< The predictive resistance flag  */
} qsc_csg_state;

/**
* \brief Dispose of the DRBG state
*
* \warning The dispose function must be called when disposing of the cipher.
* This function destroys the internal state of the cipher.
*
* \param ctx: [struct] The DRBG state structure
*/
QSC_EXPORT_API void qsc_csg_dispose(qsc_csg_state* ctx);

/**
* \brief Initialize the pseudo-random provider state with a seed and optional personalization string
*
* \param ctx: [struct] The function state
* \param seed: [const] The random seed, 32 bytes of seed instantiates the 256-bit generator, 64 bytes the 512-bit generator
* \param seedlen: The length of the input seed
* \param info: [const] The optional personalization string
* \param infolen: The length of the personalization string
* \param predres: Enable periodic random injection; enables non deterministic pseudo-random generation
*/
QSC_EXPORT_API void qsc_csg_initialize(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen, const uint8_t* info, size_t infolen, bool predres);

/**
* \brief Generate pseudo-random bytes using the random provider.
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The function state
* \param output: The pseudo-random output array
* \param outlen: The requested number of bytes to generate
* \return The number of bytes generated
*/
QSC_EXPORT_API void qsc_csg_generate(qsc_csg_state* ctx, uint8_t* output, size_t outlen);

/**
* \brief Update the random provider with new keying material
*
* \warning Initialize must first be called before this function can be used.
*
* \param ctx: [struct] The function state
* \param seed: [const] The random update seed
* \param seedlen: The length of the update seed
*/
QSC_EXPORT_API void qsc_csg_update(qsc_csg_state* ctx, const uint8_t* seed, size_t seedlen);

#endif
