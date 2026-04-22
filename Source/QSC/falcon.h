/* 2020-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */
#ifndef QSC_FALCON_H
#define QSC_FALCON_H

/**
* \file falcon.h
* \brief Contains the primary public api for the Falcon asymmetric signature scheme implementation
*
* \par Example
* \code
* // An example of key-pair creation, encryption, and decryption
* #define MSGLEN 32
* uint8_t pk[QSC_FALCON_PUBLICKEY_SIZE];
* uint8_t sk[QSC_FALCON_SECRETKEY_SIZE];
* uint8_t msg[32];
* uint8_t smsg[QSC_FALCON_SIGNATURE_SIZE + MSGLEN];
* uint8_t rmsg[32];

* uint32_t rmsglen = 0;
* uint32_t smsglen = 0;
*
* // create the public and secret keys
* qsc_falcon_generate(pk, sk);
* // returns the signed the message in smsg
* qsc_falcon_sign(smsg, &smsglen, msg, MSGLEN, sk);
* // test the signature and return the message bytes in rmsg
* if (qsc_falcon_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
* {
*     // authentication failed, do something..
* }
* \endcode
*
* Based entirely on the C reference branch of Falcon taken from the NIST Post Quantum Competition Round 3 submission. \n
* The NIST Post Quantum Competition <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions">Round 3</a> Finalists. \n
* The <a href="https://falcon-sign.info/">Falcon</a> website. \n
* The Falcon <a href="https://falcon-sign.info/falcon.pdf">Algorithm</a> Specification.
*/

#include "qsccommon.h"

#if defined(QSC_FALCON_S3SHAKE256F512)

	/*!
	* \def QSC_FALCON_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array
	*/
#	define QSC_FALCON_PRIVATEKEY_SIZE 1281

	/*!
	* \def QSC_FALCON_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array
	*/
#	define QSC_FALCON_PUBLICKEY_SIZE 897

	/*!
	* \def QSC_FALCON_SIGNATURE_SIZE
	* \brief The byte size of the signature array
	*/
#	define QSC_FALCON_SIGNATURE_SIZE 658

	/*!
	* \def QSC_FALCON_ALGNAME
	* \brief The formal algorithm name
	*/
#	define QSC_FALCON_ALGNAME "FALCON-P512"

#elif defined(QSC_FALCON_S5SHAKE256F1024)

	/*!
	* \def QSC_FALCON_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array
	*/
#	define QSC_FALCON_PRIVATEKEY_SIZE 2305

	/*!
	* \def QSC_FALCON_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array
	*/
#	define QSC_FALCON_PUBLICKEY_SIZE 1793

	/*!
	* \def QSC_FALCON_SIGNATURE_SIZE
	* \brief The byte size of the signature array
	*/
#	define QSC_FALCON_SIGNATURE_SIZE 1276

	/*!
	* \def QSC_FALCON_ALGNAME
	* \brief The formal algorithm name
	*/
#	define QSC_FALCON_ALGNAME "FALCON-P1024"

#else
#	error "The Falcon parameter set is invalid!"
#endif

/**
* \brief Generates a Falcon public/private key-pair.
*
* \warning Arrays must be sized to QSC_FALCON_PUBLICKEY_SIZE and QSC_FALCON_SECRETKEY_SIZE.
*
* \param publickey: Pointer to the public verification-key array
* \param privatekey: Pointer to the private signature-key array
* \param rng_generate: Pointer to the random generator
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_falcon_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_FALCON_SIGNATURE_SIZE.
*
* \param signedmsg: Pointer to the signed-message array
* \param smsglen: The signed message length
* \param message: [const] Pointer to the message array
* \param msglen: The message array length
* \param privatekey: [const] Pointer to the private signature-key
* \param rng_generate: Pointer to the random generator
*
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_falcon_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: Pointer to the message output array
* \param msglen: Length of the message array
* \param signedmsg: [const] Pointer to the signed message array
* \param smsglen: The signed message length
* \param publickey: [const] Pointer to the public verification-key array
* 
* \return Returns true for success
*/
QSC_EXPORT_API bool qsc_falcon_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

#endif
