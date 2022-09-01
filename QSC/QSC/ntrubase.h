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

#ifndef QSC_NTRUBASE_H
#define QSC_NTRUBASE_H

 /* \cond DOXYGEN_IGNORE */

#include "common.h"

/* kem.h */

/**
* \brief Generates shared secret for given cipher text and private key
*
* \param ss: Pointer to output shared secret (an already allocated array of NTRU_SECRET_BYTES bytes)
* \param ct: [const] Pointer to input cipher text (an already allocated array of NTRU_CIPHERTEXT_SIZE bytes)
* \param sk: [const] Pointer to input private key (an already allocated array of NTRU_SECRETKEY_SIZE bytes)
* \return Returns true for success
*/
bool qsc_ntru_ref_decapsulate(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct: Pointer to output cipher text (an already allocated array of NTRU_CIPHERTEXT_SIZE bytes)
* \param ss: Pointer to output shared secret (an already allocated array of NTRU_BYTES bytes)
* \param pk: Pointer to input public key (an already allocated array of NTRU_PUBLICKEY_SIZE bytes)
* \param rng_generate: Pointer to the random generator function
*/
void qsc_ntru_ref_encapsulate(uint8_t* ct, uint8_t* ss, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
*
* \param pk: Pointer to output public key (an already allocated array of NTRU_PUBLICKEY_SIZE bytes)
* \param sk: Pointer to output private key (an already allocated array of NTRU_SECRETKEY_SIZE bytes)
* \param rng_generate: Pointer to the random generator function
*/
void qsc_ntru_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/* \endcond DOXYGEN_IGNORE */

#endif
