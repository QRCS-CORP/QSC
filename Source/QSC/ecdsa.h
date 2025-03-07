/* 2025 Quantum Resistant Cryptographic Solutions Corporation
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

#ifndef QSC_ECDSA_H
#define QSC_ECDSA_H

#include "common.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file ecdsa.h
 * \brief Contains the primary public API for the ECDSA asymmetric signature scheme implementation.
 *
 * \details
 * This header defines the API for the ECDSA (Elliptic Curve Digital Signature Algorithm) asymmetric signature scheme,
 * operating over the Ed25519 elliptic curve. It provides functions for generating key pairs (either randomly or via a seeded generator),
 * signing messages, and verifying signatures.
 *
 * \par Example:
 * \code
 * // An example of key-pair creation, signing, and verification using ECDSA
 * #define MSGLEN 32
 * uint8_t pk[QSC_ECDSA_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_ECDSA_SECRETKEY_SIZE];
 * uint8_t msg[32];
 * uint8_t smsg[QSC_ECDSA_SIGNATURE_SIZE + MSGLEN];
 * uint8_t rmsg[32];
 *
 * uint32_t rmsglen = 0;
 * uint32_t smsglen = 0;
 *
 * // Create the public and secret keys using a seeded generator
 * qsc_ecdsa_generate_seeded_keypair(pk, sk, random_seed);
 * // Sign the message; the signature is prepended to the message
 * qsc_ecdsa_sign(smsg, &smsglen, msg, MSGLEN, sk);
 * // Verify the signature and retrieve the message bytes
 * if (qsc_ecdsa_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
 * {
 *     // Authentication failed; handle error.
 * }
 * \endcode
 *
 * \remarks
 * This ECDSA implementation utilizes the Ed25519 elliptic curve along with its underlying field arithmetic over the prime field defined by 2^255 - 19.
 * It supports standard digital signature operations including key pair generation, signing, and verification.
 * The design emphasizes constant-time execution to mitigate timing attacks and is suitable for secure applications in modern cryptographic protocols.
 *
 * \section ecdsa_links Reference Links
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Official Ed25519 Documentation</a>
 *  - <a href="https://cr.yp.to/ecdh.html">Curve25519 ECDH Specification</a>
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Ed25519 Field Arithmetic Details</a>
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
#define QSC_ECDSA_SEED_SIZE 32ULL

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
* \param publickey:		[uint8_t*] Pointer to the public verification-key array
* \param privatekey:	[uint8_t*] Pointer to the private signature-key array
* \param seed:			[const uint8_t*] Pointer to the random 32-byte seed array
*/
QSC_EXPORT_API void qsc_ecdsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
* \brief Generates a ECDSA public/private key-pair.
*
* \warning Arrays must be sized to QSC_ECDSA_PUBLICKEY_SIZE and QSC_ECDSA_SECRETKEY_SIZE.
*
* \param publickey:		[uint8_t*] Pointer to the public verification-key array
* \param privatekey:	[uint8_t*] Pointer to the private signature-key array
* \param rng_generate:	[uint8_t*, size_t] Pointer to the random generator
*/
QSC_EXPORT_API void qsc_ecdsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_ECDSA_SIGNATURE_SIZE.
*
* \param signedmsg:		[uint8_t*] Pointer to the signed-message array
* \param smsglen:		[size_t*] Pointer to the signed message length
* \param message:		[const uint8_t*] Pointer to the message array
* \param msglen:		[size_t] The message length
* \param privatekey:	[const uint8_t*] Pointer to the private signature-key array
*/
QSC_EXPORT_API void qsc_ecdsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message:		[uint8_t*] Pointer to the message array to be signed
* \param msglen:		[size_t*]Pointer to the message length
* \param signedmsg:		[const uint8_t*] Pointer to the signed message array
* \param smsglen:		[size_t] The signed message length
* \param publickey:		[const uint8_t*] Pointer to the public verification-key array
* \return				[bool] Returns true for success
*/
QSC_EXPORT_API bool qsc_ecdsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
