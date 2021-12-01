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

#ifndef QSC_KYBER_H
#define QSC_KYBER_H

/**
* \file kyber.h
* \brief Contains the primary public api for the Kyber CCA-secure Key Encapsulation Mechanism implementation
* \date January 10, 2018
* \updated July 2, 2021
*
*
* \par Example
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
* // output the cipher-text (ct), and the shared secret (ssb)
* qsc_kyber_encapsulate(ssb, ct, pk);
*
* // decrypt the cipher-text, and output the shared key (ssa)
* if (qsc_kyber_decapsulate(ssa, ct, sk) == false)
* {
*     // decapsulation failed, do something..
* }
* \endcode
*
* \remarks
* Based on the C reference branch of PQ-Crystals Kyber; including base code, comments, and api. \n
* Removed the K=2 parameter, and added a K=5. The NIST '512' parameter has fallen below the threshold
* required by NIST PQ S1 minimum. \n
* The new K5 parameter may have a better chance of long-term security, with only a small increase in cost. \n
*
* Based entirely on the C reference branch of Dilithium taken from the NIST Post Quantum Competition Round 3 submission. \n
* The NIST Post Quantum Competition <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">Round 3</a> Finalists. \n
* The <a href="https://pq-crystals.org/kyber/index.shtml">Kyber</a> website. \n
* The Kyber <a href="https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf">Algorithm</a> Specification. \n
*/

#include "common.h"
#if defined(QSC_SYSTEM_HAS_AVX2)
#	include "kyberbase_avx2.h"
#else
#	include "kyberbase.h"
#endif

/*!
* \def QSC_KYBER_CIPHERTEXT_SIZE
* \brief The byte size of the cipher-text array
*/
#define QSC_KYBER_CIPHERTEXT_SIZE (QSC_KYBER_INDCPA_BYTES)

/*!
* \def QSC_KYBER_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#define QSC_KYBER_PRIVATEKEY_SIZE (QSC_KYBER_INDCPA_SECRETKEY_BYTES +  QSC_KYBER_INDCPA_PUBLICKEY_BYTES + (2 * QSC_KYBER_SYMBYTES))

/*!
* \def QSC_KYBER_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#define QSC_KYBER_PUBLICKEY_SIZE (QSC_KYBER_INDCPA_PUBLICKEY_BYTES)

/*!
* \def QSC_KYBER_SEED_SIZE
* \brief The byte size of the seed array
*/
#define QSC_KYBER_SEED_SIZE 32

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
* \brief Decapsulates the shared secret for a given cipher-text using a private-key.
* Used in conjunction with the encapsulate function.
*
* \param secret: Pointer to the output shared secret key, an array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the secret-key array of QSC_KYBER_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_kyber_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
* \brief Decrypts the shared secret for a given cipher-text using a private-key
* Used in conjunction with the encrypt function.
*
* \param secret: Pointer to the output shared secret key, an array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: [const] Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param privatekey: [const] Pointer to the secret-key array of QSC_KYBER_PRIVATEKEY_SIZE constant size
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_kyber_decrypt(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key.
* Used in conjunction with the decapsulate function.
*
* \warning Ciphertext array must be sized to the QSC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QSC_KYBER_PUBLICKEY_SIZE constant size
* \param rng_generate: A pointer to the random generator function
*/
QSC_EXPORT_API void qsc_kyber_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
* Used in conjunction with the encrypt function.
* 
* \warning Ciphertext array must be sized to the QSC_KYBER_CIPHERTEXT_SIZE.
*
* \param secret: Pointer to the shared secret key, a uint8_t array of QSC_KYBER_SHAREDSECRET_SIZE constant size
* \param ciphertext: Pointer to the cipher-text array of QSC_KYBER_CIPHERTEXT_SIZE constant size
* \param publickey: [const] Pointer to the public-key array of QSC_KYBER_PUBLICKEY_SIZE constant size
* \param seed: [const] A pointer to the random seed array
*/
QSC_EXPORT_API void qsc_kyber_encrypt(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_KYBER_SEED_SIZE]);

/**
* \brief Generates public and private key for the KYBER key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_KYBER_PUBLICKEY_SIZE and QSC_KYBER_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the output public-key array of QSC_KYBER_PUBLICKEY_SIZE constant size
* \param privatekey: Pointer to output private-key array of QSC_KYBER_PRIVATEKEY_SIZE constant size
* \param rng_generate: A pointer to the random generator function
*/
QSC_EXPORT_API void qsc_kyber_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

#endif
