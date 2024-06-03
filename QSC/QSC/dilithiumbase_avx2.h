
/* 2024 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:  All information contained herein is, and remains
 * the property of Quantum Resistant Cryptographic Solutions Incorporated.
 * The intellectual and technical concepts contained
 * herein are proprietary to Quantum Resistant Cryptographic Solutions Incorporated
 * and its suppliers and may be covered by U.S. and Foreign Patents,
 * patents in process, and are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Quantum Resistant Cryptographic Solutions Incorporated.
 *
 * Written by John G. Underhill
 * Contact: develop@qrcs.ca
 */

#ifndef QSC_DILITHIUMBASE_AVX2_H
#define QSC_DILITHIUMBASE_AVX2_H

/* \cond DOXYGEN_IGNORE */

#include "common.h"

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to DILITHIUM_PUBLICKEY_SIZE and DILITHIUM_SECRETKEY_SIZE.
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_avx2_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

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
void qsc_dilithium_avx2_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

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
void qsc_dilithium_avx2_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

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
bool qsc_dilithium_avx2_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);

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
bool qsc_dilithium_avx2_open(uint8_t* m, size_t* mlen, const uint8_t* sm, size_t smlen, const uint8_t* pk);

/* \endcond DOXYGEN_IGNORE */

#endif
