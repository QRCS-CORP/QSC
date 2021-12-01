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
