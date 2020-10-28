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
* Implementation Details:
* An implementation of the Elliptic Curve Diffie-Hellman asymmetric cipher
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com */

/**
* \file ecdh.h
* \date September 21, 2020
*
* \brief <b>The ECDH KEX definitions</b> \n
* Contains the primary public api for the Elliptic Curve Diffie Hellman key exchange.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* uint8_t pk[QSC_ECDH_PUBLICKEY_SIZE];
* uint8_t sk[QSC_ECDH_PRIVATEKEY_SIZE]; 
* uint8_t sec[QSC_ECDH_SHAREDSECRET_SIZE];
*
* // create the public and secret keys
* qsc_ecdh_generate_seeded_keypair(pk, sk, random-seed);
*
* // decrypt the cipher-text, and output the shared key
* if (qsc_ecdh_key_exchange(sec, sk, external-public-key) == false)
* {
*     // key exchange failed, do something..
* }
* \endcode
*
* \remarks
* Reference implementations:
* LibSodium by Frank Denis
* https://github.com/jedisct1/libsodium
*
* curve25519-donna by Adam Langley
* https://github.com/agl/curve25519-donna
*
* NaCI by Daniel J. Bernstein, Tanja Lange, Peter Schwabe
* https://nacl.cr.yp.to
*
* Rewritten for Misra compliance and optimizations by John G. Underhill
* September 21, 2020
*/

#ifndef QSC_ECDH_H
#define QSC_ECDH_H

#include "common.h"

/*!
* \def QSC_ECDH_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_ECDH_PRIVATEKEY_SIZE 32

/*!
* \def QSC_ECDH_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_ECDH_PUBLICKEY_SIZE 32

/*!
* \def QSC_ECDH_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
#define QSC_ECDH_SHAREDSECRET_SIZE 32

/*!
* \def QSC_ECDH_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
#define QSC_ECDH_SEED_SIZE 32

/*!
* \def QSC_ECDH_ALGNAME
* \brief The formal algorithm name
*/
#define QSC_ECDH_ALGNAME "ECDH"

/**
* \brief Decapsulates the shared secret for given cipher-text using a private-key
*
* \warning The shared secret array must be sized to the QSC_ECDH_SHAREDSECRET_SIZE.
*
* \param secret: Pointer to a shared secret key, an array of QSC_ECDH_SHAREDSECRET_SIZE
* \param ciphertext: [const] Pointer to the cipher-text array
* \param privatekey: [const] Pointer to the private-key array
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_ecdh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey);

/**
* \brief Generates public and private key for the ECDH key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param rng_generate: A pointer to the random generator
*/
QSC_EXPORT_API void qsc_ecdh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the ECDH key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param seed: A pointer to the random seed
*/
QSC_EXPORT_API void qsc_ecdh_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* seed);

#endif
