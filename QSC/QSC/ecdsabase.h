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

#ifndef QSC_ECDSABASE_H
#define QSC_ECDSABASE_H

/* \cond DOXYGEN_IGNORE */

#include "common.h"

/**
* \brief Combine and external public key with an internal private key to produce a shared secret
*
* \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param secret: The shared secret
*/
void qsc_ed25519_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: [const] The message to be signed
* \param msglen: The message length
* \param secretkey: [const] The private signature key
* \return Returns 0 for success
*/
int32_t qsc_ed25519_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: The message to be signed
* \param msglen: The message length
* \param signedmsg: [const] The signed message
* \param smsglen: The signed message length
* \param publickey: [const] The public verification key
* \return Returns 0 for success
*/
int32_t qsc_ed25519_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/* \endcond DOXYGEN_IGNORE */

#endif
