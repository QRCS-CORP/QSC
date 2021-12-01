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
* 
* Reference implementations:
* LibSodium by Frank Denis
* https://github.com/jedisct1/libsodium
* curve25519-donna by Adam Langley
* https://github.com/agl/curve25519-donna
* NaCI by Daniel J. Bernstein, Tanja Lange, Peter Schwabe
* https://nacl.cr.yp.to
* Rewritten for Misra compliance and optimizations by John G. Underhill
*/

#ifndef QSC_ECDHBASE_H
#define QSC_ECDHBASE_H

#include "common.h"

/* \cond DOXYGEN_IGNORE */

/**
* \brief Combine and external public key with an internal private key to produce a shared secret
*
* \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
*
* \param secret: The shared secret
* \param publickey: [const] Pointer to the output public-key array
* \param privatekey: [const] Pointer to output private-key array
*/
bool qsc_ed25519_key_exchange(uint8_t* secret, const uint8_t* publickey, const uint8_t* privatekey);

/**
* \brief Generates public and private key for the ECDH key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param seed: [const] A pointer to the random seed
*/
void qsc_ed25519_generate_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/* \endcond DOXYGEN_IGNORE */

#endif
