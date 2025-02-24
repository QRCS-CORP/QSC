/*
 * 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: john.underhill@protonmail.com
 */

#ifndef QSC_FALCON_H
#define QSC_FALCON_H

#include "common.h"

/*!
 * \file falcon.h
 * \brief Contains the primary public API for the Falcon asymmetric signature scheme implementation.
 * 
 * \details
 * This file provides the API for the Falcon signature scheme implementation. It defines functions to generate key pairs, sign messages, 
 * and verify signature-message pairs using the Falcon algorithm. The implementation is based on the NIST PQC Round 3 submission, with parameters 
 * selected via preprocessor definitions.
 *
 * \code
 * // Example of key-pair creation, signing, and verification:
 * #define MSGLEN 32
 * uint8_t pk[QSC_FALCON_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_FALCON_PRIVATEKEY_SIZE];
 * uint8_t msg[MSGLEN];
 * uint8_t smsg[QSC_FALCON_SIGNATURE_SIZE + MSGLEN];
 * uint8_t rmsg[MSGLEN];
 * uint32_t smsglen = 0;
 * 
 * // Create the public and secret keys
 * qsc_falcon_generate_keypair(pk, sk, rng_generate);
 * 
 * // Sign the message; the signed message contains the signature followed by the message
 * qsc_falcon_sign(smsg, &smsglen, msg, MSGLEN, sk, rng_generate);
 * 
 * // Verify the signature and recover the message in rmsg
 * if (qsc_falcon_verify(rmsg, &smsglen, smsg, smsglen, pk) != true)
 * {
 *     // Authentication failed, handle accordingly...
 * }
 * \endcode
 * 
 * \section falcon_links Reference Links:
 * - <a href="https://falcon-sign.info/falcon.pdf">Falcon Specification</a>
 */

/*!
 * \def QSC_FALCON_PRIVATEKEY_SIZE
 * \brief [uint8_t] The byte size of the secret private-key array.
 */
#if defined(QSC_FALCON_S3SHAKE256F512)
	#define QSC_FALCON_PRIVATEKEY_SIZE 1281ULL
#elif defined(QSC_FALCON_S5SHAKE256F1024)
	#define QSC_FALCON_PRIVATEKEY_SIZE 2305ULL
#else
	#error "The Falcon parameter set is invalid!"
#endif

/*!
 * \def QSC_FALCON_PUBLICKEY_SIZE
 * \brief [uint8_t] The byte size of the public-key array.
 */
#if defined(QSC_FALCON_S3SHAKE256F512)
	#define QSC_FALCON_PUBLICKEY_SIZE 897ULL
#elif defined(QSC_FALCON_S5SHAKE256F1024)
	#define QSC_FALCON_PUBLICKEY_SIZE 1793ULL
#else
	#error "The Falcon parameter set is invalid!"
#endif

/*!
 * \def QSC_FALCON_SIGNATURE_SIZE
 * \brief [uint8_t] The byte size of the signature array.
 */
#if defined(QSC_FALCON_S3SHAKE256F512)
	#define QSC_FALCON_SIGNATURE_SIZE 658ULL
#elif defined(QSC_FALCON_S5SHAKE256F1024)
	#define QSC_FALCON_SIGNATURE_SIZE 1276ULL
#else
	#error "The Falcon parameter set is invalid!"
#endif

/*!
 * \def QSC_FALCON_ALGNAME
 * \brief [char*] The formal algorithm name.
 */
#define QSC_FALCON_ALGNAME "FALCON"

/**
 * \brief Generates a Falcon public/private key-pair.
 *
 * \warning Arrays must be sized to QSC_FALCON_PUBLICKEY_SIZE and QSC_FALCON_PRIVATEKEY_SIZE.
 *
 * \param publickey:	[uint8_t*] Pointer to the public verification-key array.
 * \param privatekey:	[uint8_t*] Pointer to the private signature-key array.
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to the random generator function.
 */
QSC_EXPORT_API void qsc_falcon_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Signs a message and returns an array containing the signature followed by the message.
 *
 * \warning The signed message array must be sized to the size of the message plus QSC_FALCON_SIGNATURE_SIZE.
 *
 * \param signedmsg:	[uint8_t*] Pointer to the signed-message array.
 * \param smsglen:		[size_t*] Pointer to the signed message length.
 * \param message:		[const uint8_t*] Pointer to the message array.
 * \param msglen:		[size_t] The message array length.
 * \param privatekey:	[const uint8_t*] Pointer to the private signature-key.
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to the random generator function.
 */
QSC_EXPORT_API void qsc_falcon_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Verifies a signature-message pair with the public key.
 *
 * \param message:		[uint8_t*] Pointer to the message output array.
 * \param msglen:		[size_t*] Pointer to the message length.
 * \param signedmsg:	[const uint8_t*] Pointer to the signed message array.
 * \param smsglen:		[size_t] The signed message length.
 * \param publickey:	[const uint8_t*] Pointer to the public verification-key array.
 *
 * \return				[bool] Returns true for success.
 */
QSC_EXPORT_API bool qsc_falcon_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

#endif
