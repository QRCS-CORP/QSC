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

#ifndef QSC_DILITHIUM_H
#define QSC_DILITHIUM_H

#include "common.h"

/**
* \file dilithium.h
* \brief Contains the primary public api for the Dilithium asymmetric signature scheme implementation
* \updated July 2, 2021
*
* \par Example
* \code
* // An example of key-pair creation, encryption, and decryption
* #define MSGLEN 32
* uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE];
* uint8_t sk[QSC_DILITHIUM_SECRETKEY_SIZE];
* uint8_t msg[32];
* uint8_t smsg[QSC_DILITHIUM_SIGNATURE_SIZE + MSGLEN];
* uint8_t rmsg[32];

* uint32_t rmsglen = 0;
* uint32_t smsglen = 0;
*
* // create the public and secret keys
* qsc_dilithium_generate(pk, sk);
* // returns the signed the message in smsg
* qsc_dilithium_sign(smsg, &smsglen, msg, MSGLEN, sk);
* // test the signature and return the message bytes in rmsg
* if (qsc_dilithium_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* \remarks
* Based entirely on the C reference branch of Dilithium taken from the NIST Post Quantum Competition Round 3 submission. \n
* The NIST Post Quantum Competition <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">Round 3</a> Finalists. \n
* The <a href="https://pq-crystals.org/dilithium/index.shtml">Dilithium</a> web-site. \n
* The Dilithium <a href="https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf">Algorithm</a> Specification.
*/

#if defined(QSC_DILITHIUM_S2N256Q8380417K4)

/*!
* \def QSC_DILITHIUM_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 2544

/*!
* \def QSC_DILITHIUM_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1312

/*!
* \def QSC_DILITHIUM_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_DILITHIUM_SIGNATURE_SIZE 2420

#elif defined(QSC_DILITHIUM_S3N256Q8380417K6)

/*!
* \def QSC_DILITHIUM_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 4016

/*!
* \def QSC_DILITHIUM_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1952

/*!
* \def QSC_DILITHIUM_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_DILITHIUM_SIGNATURE_SIZE 3293

#elif defined(QSC_DILITHIUM_S5N256Q8380417K8)

/*!
* \def QSC_DILITHIUM_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 4880

/*!
* \def QSC_DILITHIUM_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 2592

/*!
* \def QSC_DILITHIUM_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_DILITHIUM_SIGNATURE_SIZE 4595

#else
#	error "The Dilithium parameter set is invalid!"
#endif

/*!
* \def QSC_DILITHIUM_ALGNAME
* \brief The formal algorithm name
*/
#define QSC_DILITHIUM_ALGNAME "DILITHIUM"

/**
* \brief Generates a Dilithium public/private key-pair.
*
* \warning Arrays must be sized to QSC_DILITHIUM_PUBLICKEY_SIZE and QSC_DILITHIUM_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
QSC_EXPORT_API void qsc_dilithium_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_DILITHIUM_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: The signed message length
* \param message: [const] Pointer to the message array
* \param msglen: The message array length
* \param privatekey: [const] Pointer to the private signature-key
* \param rng_generate: Pointer to the random generator
*/
QSC_EXPORT_API void qsc_dilithium_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: Pointer to the message output array
* \param msglen: Length of the message array
* \param signedmsg: [const] Pointer to the signed message array
* \param smsglen: The signed message length
* \param publickey: [const] Pointer to the public verification-key array
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_dilithium_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

#endif
