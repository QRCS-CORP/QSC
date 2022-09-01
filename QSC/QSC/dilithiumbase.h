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

#ifndef QSC_DILITHIUMBASE_H
#define QSC_DILITHIUMBASE_H

/* \cond DOXYGEN_IGNORE */

#include "common.h"

/* #define QSC_DILITHIUM_RANDOMIZED_SIGNING */

#if defined(QSC_DILITHIUM_S2N256Q8380417K4)
#   define QSC_DILITHIUM_MODE 2
#elif defined(QSC_DILITHIUM_S3N256Q8380417K6) 
#   define QSC_DILITHIUM_MODE 3
#elif defined(QSC_DILITHIUM_S5N256Q8380417K8)
#   define QSC_DILITHIUM_MODE 5
#else
#error The dilithium mode is not sdupported!
#endif

#define QSC_DILITHIUM_N 256

#if (QSC_DILITHIUM_MODE == 2)
#   define QSC_DILITHIUM_K 4
#   define QSC_DILITHIUM_L 4
#elif (QSC_DILITHIUM_MODE == 3)
#   define QSC_DILITHIUM_K 6
#   define QSC_DILITHIUM_L 5
#elif (QSC_DILITHIUM_MODE == 5)
#   define QSC_DILITHIUM_K 8
#   define QSC_DILITHIUM_L 7
#endif

/*!
* \struct qsc_dilithium_poly
* \brief Array of coefficients of length N
*/
typedef struct
{
    int32_t coeffs[QSC_DILITHIUM_N];            /*!< The coefficients  */
} qsc_dilithium_poly;

/*!
* \struct qsc_dilithium_polyvecl
* \brief Vectors of polynomials of length L
*/
typedef struct
{
    qsc_dilithium_poly vec[QSC_DILITHIUM_L];    /*!< The poly vector of L  */
} qsc_dilithium_polyvecl;

/*!
* \struct qsc_dilithium_polyveck
* \brief Vectors of polynomials of length K
*/
typedef struct
{
    qsc_dilithium_poly vec[QSC_DILITHIUM_K];    /*!< The poly vector of K  */
} qsc_dilithium_polyveck;

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to DILITHIUM_PUBLICKEY_SIZE and DILITHIUM_SECRETKEY_SIZE.
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_ref_generate_keypair(uint8_t *pk, uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature
*
* \param sig: The signed message
* \param siglen: The signed message length
* \param m: [const] The message to be signed
* \param mlen: The message length
* \param sk: [const] The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_ref_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message
*
* \param sm: The signed message
* \param smlen: The signed message length
* \param m: [const] The message to be signed
* \param mlen: The message length
* \param sk: [const] The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_ref_sign(uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen, const uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param sig: [const] The message to be signed
* \param siglen: The message length
* \param m: [const] The signed message
* \param mlen: The signed message length
* \param pk: [const] The public verification key
* \return Returns true for success
*/
bool qsc_dilithium_ref_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen, const uint8_t *pk);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param m: The message to be signed
* \param mlen: The message length
* \param sm: [const] The signed message
* \param smlen: The signed message length
* \param pk: [const] The public verification key
* \return Returns true for success
*/
bool qsc_dilithium_ref_open(uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen, const uint8_t *pk);

/* \endcond DOXYGEN_IGNORE */

#endif
