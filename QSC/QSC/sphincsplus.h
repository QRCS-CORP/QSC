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

#ifndef QSC_SPHINCSPLUS_H
#define QSC_SPHINCSPLUS_H

#include "common.h"

/**
* \file sphincsplus.h
* \date June 14, 2018
* \updated July 2, 2021
*
* \brief The SphincsPlus API definitions \n
* Contains the primary public api for the Sphincs+ asymmetric signature scheme implementation.
*
* \par Example
* \code
* #define MSGLEN 32
* uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE];
* uint8_t sk[QSC_SPHINCSPLUS_SECRETKEY_SIZE];
* uint8_t msg[32];
* uint8_t smsg[QSC_SPHINCSPLUS_SIGNATURE_SIZE + MSGLEN];
* uint8_t rmsg[32];
* uint32_t rmsglen = 0;
* uint32_t smsglen = 0;
*
* qsc_sphincsplus_generate(pk, sk);
* qsc_sphincsplus_sign(smsg, &smsglen, msg, MSGLEN, sk);
* 
* if (qsc_sphincsplus_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
* {
*     authentication failed, do something..
* }
* \endcode
*
* Based entirely on the C reference branch of SPHINCS+ taken from the NIST Post Quantum Competition Round 3 submission. \n
* The NIST Post Quantum Competition <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">Round 3</a> Finalists. \n
* The <a href="https://sphincs.org/">SPHINCS+</a> website. \n
* The SPHINCS+ <a href="https://sphincs.org/data/sphincs+-specification.pdf">Algorithm</a> Specification. \n
*/

#if defined(QSC_SPHINCSPLUS_S3S192SHAKERS)

/*!
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_SPHINCSPLUS_SIGNATURE_SIZE 16224

/*!
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_SPHINCSPLUS_PRIVATEKEY_SIZE 96

/*!
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_SPHINCSPLUS_PUBLICKEY_SIZE 48

#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERF)

/*!
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_SPHINCSPLUS_SIGNATURE_SIZE 35664

/*!
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_SPHINCSPLUS_PRIVATEKEY_SIZE 96

/*!
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_SPHINCSPLUS_PUBLICKEY_SIZE 48

#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)

/*!
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_SPHINCSPLUS_SIGNATURE_SIZE 29792

/*!
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_SPHINCSPLUS_PRIVATEKEY_SIZE 128

/*!
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_SPHINCSPLUS_PUBLICKEY_SIZE 64

#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERF)

/*!
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_SPHINCSPLUS_SIGNATURE_SIZE 49856

/*!
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_SPHINCSPLUS_PRIVATEKEY_SIZE 128

/*!
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_SPHINCSPLUS_PUBLICKEY_SIZE 64

#elif defined(QSC_SPHINCSPLUS_S6S512SHAKERS)

/* The hash is 512-bit extended */
#	define QSC_SPHINCSPLUS_EXTENDED

/*!
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_SPHINCSPLUS_SIGNATURE_SIZE 113344

/*!
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_SPHINCSPLUS_PRIVATEKEY_SIZE 256

/*!
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_SPHINCSPLUS_PUBLICKEY_SIZE 128

#elif defined(QSC_SPHINCSPLUS_S6S512SHAKERF)

/* The hash is 512-bit extended */
#	define QSC_SPHINCSPLUS_EXTENDED

/*!
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_SPHINCSPLUS_SIGNATURE_SIZE 165056

/*!
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_SPHINCSPLUS_PRIVATEKEY_SIZE 256

/*!
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_SPHINCSPLUS_PUBLICKEY_SIZE 128

#else
#	error "The SPHINCS+ parameter set is invalid!"
#endif

/*!
* \def QSC_SPHINCSPLUS_ALGNAME
* \brief The formal algorithm name
*/
#define QSC_SPHINCSPLUS_ALGNAME "SPHINCSPLUS"

/**
* \brief Generates a Sphincs+ public/private key-pair.
*
* \warning Arrays must be sized to QSC_SPHINCSPLUS_PUBLICKEY_SIZE and QSC_SPHINCSPLUS_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
QSC_EXPORT_API void qsc_sphincsplus_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_SPHINCSPLUS_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: [const] Pointer to the signed message length
* \param message: Pointer to the message array
* \param msglen: The message length
* \param privatekey: [const] Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*/
QSC_EXPORT_API void qsc_sphincsplus_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

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
QSC_EXPORT_API bool qsc_sphincsplus_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

#endif
