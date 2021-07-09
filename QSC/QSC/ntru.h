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
*
* Implementation Details:
* An implementation of the NTRU asymmetric cipher
* Rewritten for Misra compliance and library integration by John G. Underhill
* Contact: support@vtdev.com
* Updated on July 5, 2021
*/

/**
* \file ntru.h
* \date July 5, 2021
*
* \brief <b>The NTRU KEM definitions</b> \n
* Contains the primary public api for the NTRU CCA-secure Key Encapsulation Mechanism implementation.
*
* \para <b>Example</b> \n
* \code
* // An example of key-pair creation, encryption, and decryption
* uint8_t ct[QSC_NTRU_CIPHERTEXT_SIZE];
* uint8_t pk[QSC_NTRU_PUBLICKEY_SIZE];
* uint8_t sk[QSC_NTRU_PRIVATEKEY_SIZE];
* uint8_t ssa[QSC_NTRU_SHAREDSECRET_SIZE];
* uint8_t ssb[QSC_NTRU_SHAREDSECRET_SIZE];
*
* // create the public and secret keys
* qsc_ntru_generate_keypair(pk, sk);
*
* // output the cipher-text (ct), and the shared secret (ssb)
* qsc_ntru_encapsulate(ssb, ct, pk);
*
* // decrypt the cipher-text, and output the shared key (ssa)
* if (qsc_ntru_decapsulate(ssa, ct, sk) == false)
* {
*     // decapsulation failed, do something..
* }
* \endcode
*
* \remarks
* Based on the C reference branch of NIST PQC Round 3 submission; including base code, comments, and api. \n
* The NIST Post Quantum Competition <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">Round 3</a> Finalists. \n
* NIST PQC Round 3: <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">NTRU</a>. \n
* The NTRU <a href="https://ntru.org/f/ntru-20190330.pdf">Algorithm.</a> Specifications. \n
*/

#ifndef QSC_NTRU_H
#define QSC_NTRU_H

#include "common.h"
//#if defined(QSC_SYSTEM_HAS_AVX2)
//#	include "ntrubase_avx2.h"
//#else
#	include "ntrubase.h"
//#endif

#if defined(QSC_NTRU_S1HPS2048509)

/*!
* \def QSC_NTRU_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_NTRU_CIPHERTEXT_SIZE 699

/*!
* \def QSC_NTRU_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_NTRU_PRIVATEKEY_SIZE 935

/*!
* \def QSC_NTRU_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_NTRU_PUBLICKEY_SIZE 699

#elif defined(QSC_NTRU_HPSS32048677)

/*!
* \def QSC_NTRU_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_NTRU_CIPHERTEXT_SIZE 930

/*!
* \def QSC_NTRU_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_NTRU_PRIVATEKEY_SIZE 1234

/*!
* \def QSC_NTRU_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_NTRU_PUBLICKEY_SIZE 930

#elif defined(QSC_NTRU_S5HPS4096821)

/*!
* \def QSC_NTRU_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_NTRU_CIPHERTEXT_SIZE 1230

/*!
* \def QSC_NTRU_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_NTRU_PRIVATEKEY_SIZE 1590

/*!
* \def QSC_NTRU_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_NTRU_PUBLICKEY_SIZE 1230

#elif defined(QSC_NTRU_S5HRSS701)

/*!
* \def QSC_NTRU_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#	define QSC_NTRU_CIPHERTEXT_SIZE 1138

/*!
* \def QSC_NTRU_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_NTRU_PRIVATEKEY_SIZE 1450

/*!
* \def QSC_NTRU_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_NTRU_PUBLICKEY_SIZE 1138

#else
#	error "The NTRU parameter set is invalid!"
#endif


/*!
* \def QSC_NTRU_SHAREDSECRET_SIZE
* \brief The byte size of the shared secret-key array
*/
#define QSC_NTRU_SHAREDSECRET_SIZE 32

/*!
* \def QSC_NTRU_ALGNAME
* \brief The formal algorithm name
*/
#define QSC_NTRU_ALGNAME "NTRU"

/**
* \brief Decapsulates the shared secret for a given cipher-text using a private-key
*
* \param secret: Pointer to the output shared secret key, an array of QSC_NTRU_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QSC_NTRU_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the secret-key array of QSC_NTRU_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_ntru_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
*
* \warning Ciphertext array must be sized to the QSC_NTRU_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QSC_NTRU_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QSC_NTRU_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QSC_NTRU_PUBLICKEY_SIZE constant size
* \param rng_generate: A pointer to the random generator function
*/
QSC_EXPORT_API void qsc_ntru_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, void (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the NTRU key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_NTRU_PUBLICKEY_SIZE and QSC_NTRU_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array of QSC_NTRU_PUBLICKEY_SIZE constant size
* \param privatekey: Pointer to output private-key array of QSC_NTRU_PRIVATEKEY_SIZE constant size
* \param rng_generate: A pointer to the random generator function
*/
QSC_EXPORT_API void qsc_ntru_generate_keypair(uint8_t* publickey, uint8_t* privatekey, void (*rng_generate)(uint8_t*, size_t));

#endif
