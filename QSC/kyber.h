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
* An implementation of the Kyber asymmetric cipher
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com */

/**
* \file kyber.h
* \date January 10, 2018
*
* \brief <b>The Kyber KEM definitions</b> \n
* Contains the primary public api for the Kyber CCA-secure Key Encapsulation Mechanism implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE];
* uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE];
* uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE];
* uint8_t ssa[QSC_KYBER_SHAREDSECRET_SIZE];
* uint8_t ssb[QSC_KYBER_SHAREDSECRET_SIZE];
*
* // create the public and secret keys
* qsc_kyber_generate_keypair(pk, sk);
*
* // output the cipher-text (ct), and the shared key
* qsc_kyber_encapsulate(ssb, ct, pk);
*
* // decrypt the cipher-text, and output the shared key
* if (qsc_kyber_decapsulate(ssa, ct, sk) == false)
* {
*     // decapsulation failed, do something..
* }
* \endcode
*
* \remarks 
* Based on the C reference branch of PQ-Crystals Kyber; including base code, comments, and api. \n
* PQ-Crystals <a href="https://github.com/pq-crystals/kyber">Kyber</a>. \n
* CRYSTALS - Kyber: <a href="http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">a CCA-secure module-lattice-based KEM</a>. \n
*/

#ifndef QSC_KYBER_H
#define QSC_KYBER_H

#include "common.h"

#if defined(QSC_KYBER_S1Q3329N256)

/*!
* \def QSC_KYBER_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_KYBER_CIPHERTEXT_SIZE 736

/*!
* \def QSC_KYBER_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_KYBER_PRIVATEKEY_SIZE 1632

/*!
* \def QSC_KYBER_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_KYBER_PUBLICKEY_SIZE 800


#elif defined(QSC_KYBER_S2Q3329N256)

/*!
* \def QSC_KYBER_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_KYBER_CIPHERTEXT_SIZE 1088

/*!
* \def QSC_KYBER_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_KYBER_PRIVATEKEY_SIZE 2400

/*!
* \def QSC_KYBER_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_KYBER_PUBLICKEY_SIZE 1184


#elif defined(QSC_KYBER_S3Q3329N256)

/*!
* \def QSC_KYBER_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_KYBER_CIPHERTEXT_SIZE 1568

/*!
* \def QSC_KYBER_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_KYBER_PRIVATEKEY_SIZE 3168

/*!
* \def QSC_KYBER_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_KYBER_PUBLICKEY_SIZE 1568

#else
#	error No Kyber implementation is defined, check common.h!
#endif

/*!
* \def QSC_KYBER_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
#define QSC_KYBER_SHAREDSECRET_SIZE 32

/*!
* \def QSC_KYBER_ALGNAME
* \brief The formal algorithm name
*/
#define QSC_KYBER_ALGNAME "KYBER"

/**
* \brief Decapsulates the shared secret for given cipher-text using a private-key
*
* \warning The shared secret array must be sized to the QSC_KYBER_SHAREDSECRET_SIZE.
*
* \param secret: Pointer to a shared secret key, an array of QSC_KYBER_SHAREDSECRET_SIZE
* \param ciphertext: [const] Pointer to the cipher-text array
* \param privatekey: [const] Pointer to the private-key array
* \return Returns true for success
*/
bool qsc_kyber_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
*
* \warning Ciphertext array must be sized to the QSC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret array, a uint8_t array of QSC_KYBER_SHAREDSECRET_SIZE
* \param ciphertext: Pointer to the cipher-text array
* \param publickey: [const] Pointer to the public-key array
* \param rng_generate: A pointer to the random generator
*/
void qsc_kyber_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the KYBER key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_KYBER_PUBLICKEY_SIZE and QSC_KYBER_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param rng_generate: A pointer to the random generator
*/
void qsc_kyber_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t));

#endif
