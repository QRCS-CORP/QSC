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

#ifndef QSC_MCELIECEBASE_H
#define QSC_MCELIECEBASE_H

#include "common.h"

/* \cond DOXYGEN_IGNORE */

/* operations.h */

/**
* \brief Decapsulates the shared secret for a given cipher-text using a private-key
*
* \param key: Pointer to a shared secret key, an array of QSC_MCELIECE_SHAREDSECRET_SIZE constant size
* \param c: [const] Pointer to the cipher-text array of QSC_MCELIECE_CIPHERTEXT_SIZE constant size
* \param sk: [const] Pointer to the secret-key array of QSC_MCELIECE_PRIVATEKEY_SIZE constant size
* \return Returns 0 for success
*/
int32_t qsc_mceliece_ref_decapsulate(uint8_t *key, const uint8_t *c, const uint8_t *sk);

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
*
* \param secret: Pointer to a shared secret, a uint8_t array of QSC_MCELIECE_SHAREDSECRET_SIZE
* \param ciphertext: Pointer to the cipher-text array
* \param publickey: [const] Pointer to the public-key array
* \param rng_generate: Pointer to the random generator
* \return Returns 0 for success
*/
int32_t qsc_mceliece_ref_encapsulate(uint8_t *c, uint8_t *key, const uint8_t *pk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the McEliece key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_QSC_MCELIECE_PUBLICKEY_SIZE and QSC_QSC_MCELIECE_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array of QSC_MCELIECE_PUBLICKEY_SIZE constant size
* \param privatekey: Pointer to output private-key array of QSC_MCELIECE_PRIVATEKEY_SIZE constant size
* \param rng_generate: Pointer to the random generator function
* \return Returns 0 for success
*/
int32_t qsc_mceliece_ref_generate_keypair(uint8_t *pk, uint8_t *sk, bool (*rng_generate)(uint8_t*, size_t));

/* \endcond DOXYGEN_IGNORE */

#endif
