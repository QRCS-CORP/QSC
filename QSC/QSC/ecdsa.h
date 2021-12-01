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

#ifndef QSC_ECDSA_H
#define QSC_ECDSA_H

#include "common.h"

/**
* \file ecdsa.h
* \brief Contains the primary public api for the ECDSA asymmetric signature scheme implementation
* \date September 21, 2020
*
* \par Example
* \code
* // An example of key-pair creation, encryption, and decryption
* #define MSGLEN 32
* uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE];
* uint8_t sk[QSC_ECDSA_SECRETKEY_SIZE];
* uint8_t msg[32];
* uint8_t smsg[QSC_ECDSA_SIGNATURE_SIZE + MSGLEN];
* uint8_t rmsg[32];

* uint32_t rmsglen = 0;
* uint32_t smsglen = 0;
*
* // create the public and secret keys
* qsc_ecdsa_generate_seeded_keypair(pk, sk, random-seed);
* // returns the signed the message in smsg
* qsc_ecdsa_sign(smsg, &smsglen, msg, MSGLEN, sk);
* // test the signature and return the message bytes in rmsg
* if (qsc_ecdsa_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* Reference implementations:
* LibSodium by Frank Denis <a href="https://github.com/jedisct1/libsodium" /a>
* curve25519-donna by Adam Langley <a href="https://github.com/agl/curve25519-donna" /a>
* NaCI by Daniel J. Bernstein, Tanja Lange, Peter Schwabe <a href="https://nacl.cr.yp.to" /a>
*
* Rewritten for Misra compliance and library integration by John G. Underhill
* September 21, 2020
*/

#if defined(QSC_ECDSA_S1EC25519)

/*!
* \def QSC_ECDSA_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_ECDSA_SIGNATURE_SIZE 64

/*!
* \def QSC_ECDSA_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_ECDSA_PRIVATEKEY_SIZE 64

/*!
* \def QSC_ECDSA_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_ECDSA_PUBLICKEY_SIZE 32

#else
#	error "The ECDSA parameter set is invalid!"
#endif

/*!
* \def QSC_ECDSA_SEED_SIZE
* \brief The byte size of the random seed array
*/
#define QSC_ECDSA_SEED_SIZE 32

/*!
* \def QSC_ECDSA_ALGNAME
* \brief The formal algorithm name
*/
#define QSC_ECDSA_ALGNAME "ECDSA"

/**
* \brief Generates a ECDSA public/private key-pair.
*
* \warning Arrays must be sized to QSC_ECDSA_PUBLICKEY_SIZE and QSC_ECDSA_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param seed: [const] Pointer to the random 32-byte seed array
*/
QSC_EXPORT_API void qsc_ecdsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
* \brief Generates a ECDSA public/private key-pair.
*
* \warning Arrays must be sized to QSC_ECDSA_PUBLICKEY_SIZE and QSC_ECDSA_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
QSC_EXPORT_API void qsc_ecdsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_ECDSA_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: [const] Pointer to the signed message length
* \param message: Pointer to the message array
* \param msglen: The message length
* \param privatekey: [const] Pointer to the private signature-key array
*/
QSC_EXPORT_API void qsc_ecdsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: Pointer to the message array to be signed
* \param msglen: Pointer to the message length
* \param signedmsg: [const] Pointer to the signed message array
* \param smsglen: The signed message length
* \param publickey: [const] Pointer to the public verification-key array
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_ecdsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

#endif
