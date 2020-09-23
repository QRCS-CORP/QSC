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
* An implementation of the McEliece asymmetric cipher
* Written by John G. Underhill
* Updated on January 20, 2020
* Contact: develop@vtdev.com */

/**
* \file mceliece.h
* \date May 10, 2019
*
* \brief <b>The McEliece api definitions</b> \n
* Contains the primary public api for the Niederreiter dual form of the McEliece asymmetric cipher implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE];
* uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE];
* uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE];
* uint8_t ssa[QSC_MCELIECE_SHAREDSECRET_SIZE];
* uint8_t ssb[QSC_MCELIECE_SHAREDSECRET_SIZE];
*
* // create the public and secret keys
* qsc_mceliece_generate_keypair(pk, sk);
*
* // output the cipher-text (ct), and the shared key
* qsc_mceliece_encapsulate(ssb, ct, pk);
*
* // decrypt the cipher-text, and output the shared key
* if (qsc_mceliece_decapsulate(ssa, ct, sk) == false)
* {
*     // decapsulation failed, do something..
* }
* \endcode
*
* \remarks
* Classic McEliece is a KEM designed for IND-CCA2 security at a very high security level, even against quantum computers. \n
* The KEM is built conservatively from a PKE designed for OW-CPA security, namely Niederreiter's dual version of McEliece's PKE using binary Goppa codes. \n
* Every level of the construction is designed so that future cryptographic auditors can be confident in the long-term security of post-quantum public-key encryption. \n
* Based on the NIST PQ, SUPERCOP C reference branch of McEliece; including base code, and comments. \n
* McEliece NIST PQ Round 2: <a href="https://classic.mceliece.org/nist/mceliece-20171129.pdf">McEliece</a> conservative code-based cryptography. \n
* Source code: <a href="https://bench.cr.yp.to/supercop.html">SUPERCOP</a> McEliece implementation. \n
* The authors: <a href="https://classic.mceliece.org/">McEliece website</a>. \n
* Authors: Daniel J. Bernstein, Tung Chou, Tanja Lange, and Peter Schwabe. \n
* Updated by John Underhill, May 10 2019.
*/

#ifndef QSC_MCELIECE_H
#define QSC_MCELIECE_H

#include "common.h"

#if defined(QSC_MCELIECE_N8192T128)

	/*!
	* \def QSC_MCELIECE_CIPHERTEXT_SIZE
	* \brief The byte size of the cipher-text array
	*/
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 240

	/*!
	* \def QSC_MCELIECE_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array
	*/
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 14080

	/*!
	* \def QSC_MCELIECE_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array
	*/
#	define QSC_MCELIECE_PUBLICKEY_SIZE 1357824

#elif defined(QSC_MCELIECE_N6960T119)

/*!
* \def QSC_MCELIECE_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 226

/*!
* \def QSC_MCELIECE_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 13908

/*!
* \def QSC_MCELIECE_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_MCELIECE_PUBLICKEY_SIZE 1047319


#else
#	error No McEliece implementation is defined, check common.h!
#endif

/*!
* \def QSC_MCELIECE_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
#	define QSC_MCELIECE_SHAREDSECRET_SIZE 32

/*!
* \def QSC_MCELIECE_ALGNAME
* \brief The formal algorithm name
*/
#define QSC_MCELIECE_ALGNAME "MCELIECE"

/**
* \brief Decapsulates the shared secret for given cipher-text using a private-key
*
* \warning The shared secret array must be sized to the QSC_MCELIECE_SHAREDSECRET_SIZE.
*
* \param secret: Pointer to a shared secret key, an array of QSC_MCELIECE_SHAREDSECRET_SIZE
* \param ciphertext: [const] Pointer to the cipher-text array
* \param privatekey: [const] Pointer to the private-key array
* \return Returns true for success
*/
bool qsc_mceliece_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
*
* \warning Ciphertext array must be sized to the QSC_MCELIECE_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to a shared secret, a uint8_t array of QSC_MCELIECE_SHAREDSECRET_SIZE
* \param ciphertext: Pointer to the cipher-text array
* \param publickey: [const] Pointer to the public-key array
* \param rng_generate: Pointer to the random generator
*/
void qsc_mceliece_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the McEliece key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_QSC_MCELIECE_PUBLICKEY_SIZE and QSC_QSC_MCELIECE_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array
* \param privatekey: Pointer to output private-key array
* \param rng_generate: Pointer to the random generator
*/
void qsc_mceliece_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t));

#endif
