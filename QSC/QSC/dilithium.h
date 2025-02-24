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

#ifndef QSC_DILITHIUM_H
#define QSC_DILITHIUM_H

#include "common.h"

/**
 * \file dilithium.h
 * \brief Contains the primary public API for the Dilithium asymmetric signature scheme implementation.
 *
 * \details
 * This header provides the interface for the FIPS 204 version of the Dilithium asymmetric signature scheme.
 * It includes functions for key-pair generation, signing messages, and verifying signatures.
 * The implementation is based entirely on the C reference branch of Dilithium from the FIPS 204 implementation. 
 * Dilithium is a lattice-based, CCA-secure digital signature scheme designed for post-quantum security.
 *
 * \par Example:
 * \code
 * // An example of key-pair creation, signing, and verification
 * #define MSGLEN 32
 * uint8_t pk[QSC_DILITHIUM_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_DILITHIUM_PRIVATEKEY_SIZE];
 * uint8_t msg[32];
 * uint8_t smsg[QSC_DILITHIUM_SIGNATURE_SIZE + MSGLEN];
 * uint8_t rmsg[32];
 *
 * uint32_t rmsglen = 0;
 * uint32_t smsglen = 0;
 *
 * // Create the public and secret keys.
 * qsc_dilithium_generate_keypair(pk, sk, rng_generate);
 * // Sign the message; the signature is prepended to the message.
 * qsc_dilithium_sign(smsg, &smsglen, msg, MSGLEN, sk, rng_generate);
 * // Verify the signature and retrieve the message bytes.
 * if (qsc_dilithium_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
 * {
 *     // Authentication failed; handle error.
 * }
 * \endcode
 *
 * \section dilithium_links Reference Links:
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf">Official Dilithium Specification (FIPS 204)</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">FIPS 202: SHA-3 Standard</a>
 */

#if defined(QSC_DILITHIUM_S1P2544)

/*!
 * \def QSC_DILITHIUM_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 2560

/*!
 * \def QSC_DILITHIUM_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1312

/*!
 * \def QSC_DILITHIUM_SIGNATURE_SIZE
 * \brief The byte size of the signature array.
 */
#	define QSC_DILITHIUM_SIGNATURE_SIZE 2420

#elif defined(QSC_DILITHIUM_S3P4016)

/*!
 * \def QSC_DILITHIUM_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 4032

/*!
 * \def QSC_DILITHIUM_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1952

/*!
 * \def QSC_DILITHIUM_SIGNATURE_SIZE
 * \brief The byte size of the signature array.
 */
#	define QSC_DILITHIUM_SIGNATURE_SIZE 3309

#elif defined(QSC_DILITHIUM_S5P4880)

/*!
 * \def QSC_DILITHIUM_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 4896

/*!
 * \def QSC_DILITHIUM_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 2592

/*!
 * \def QSC_DILITHIUM_SIGNATURE_SIZE
 * \brief The byte size of the signature array.
 */
#	define QSC_DILITHIUM_SIGNATURE_SIZE 4627

#else
#	error "The Dilithium parameter set is invalid!"
#endif

/*!
 * \def QSC_DILITHIUM_ALGNAME
 * \brief The formal algorithm name.
 */
#define QSC_DILITHIUM_ALGNAME "DILITHIUM"

///*!
// * \def QSC_DILITHIUM_RANDOMIZED_SIGNING
// * \brief Enables randomized signing.
// */
//#define QSC_DILITHIUM_RANDOMIZED_SIGNING

/**
 * \brief Generates a Dilithium public/private key-pair.
 *
 * \warning Arrays must be sized to QSC_DILITHIUM_PUBLICKEY_SIZE and QSC_DILITHIUM_PRIVATEKEY_SIZE.
 *
 * \param publickey:	[uint8_t*] Pointer to the public verification-key array.
 * \param privatekey:	[uint8_t*] Pointer to the private signature-key array.
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to the random generator.
 */
QSC_EXPORT_API void qsc_dilithium_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Takes the message as input and returns an array containing the signature followed by the message.
 *
 * \warning The signed-message array must be sized to the size of the message plus QSC_DILITHIUM_SIGNATURE_SIZE.
 *
 * \param signedmsg:	[uint8_t*] Pointer to the signed-message array.
 * \param smsglen:		[size_t*] Pointer to the signed message length.
 * \param message:		[const uint8_t*] Pointer to the message array.
 * \param msglen:		[size_t] The message array length.
 * \param privatekey:	[const uint8_t*] Pointer to the private signature-key.
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to the random generator.
 */
QSC_EXPORT_API void qsc_dilithium_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Takes the message as input and returns an array containing the signature followed by the message.
 *
 * \warning The signed-message array must be sized to the size of the message plus QSC_DILITHIUM_SIGNATURE_SIZE.
 *
 * \param signedmsg:	[uint8_t*] Pointer to the signed-message array.
 * \param smsglen:		[size_t*] Pointer to the signed message length.
 * \param message:		[const uint8_t*] Pointer to the message array.
 * \param msglen:		[size_t] The message array length.
 * \param context:		[const uint8_t*] Pointer to the context array.
 * \param contextlen:	[size_t] The context array length.
 * \param privatekey:	[const uint8_t*] Pointer to the private signature-key.
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to the random generator.
 */
QSC_EXPORT_API void qsc_dilithium_sign_ex(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t contextlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Verifies a signature-message pair with the public key.
 *
 * \param message:		[uint8_t*] Pointer to the message output array.
 * \param msglen:		[size_t*] Pointer to the length of the message array.
 * \param signedmsg:	[const uint8_t*] Pointer to the signed message array.
 * \param smsglen:		[size_t] The signed message length.
 * \param publickey:	[const uint8_t*] Pointer to the public verification-key array.
 *
 * \return				[bool] Returns true if the signature is valid; otherwise, false.
 */
QSC_EXPORT_API bool qsc_dilithium_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/**
 * \brief Verifies a signature-message pair with the public key.
 *
 * \param message:		[uint8_t*] Pointer to the message output array.
 * \param msglen:		[size_t*] Pointer to the length of the message array.
 * \param signedmsg:	[const uint8_t*] Pointer to the signed message array.
 * \param smsglen:		[size_t] The signed message length.
 * \param context:		[const uint8_t*] Pointer to the context array.
 * \param contextlen:	[size_t] The context array length.
 * \param publickey:	[const uint8_t*] Pointer to the public verification-key array.
 *
 * \return				[bool] Returns true if the signature is valid; otherwise, false.
 */
QSC_EXPORT_API bool qsc_dilithium_verify_ex(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* context, size_t contextlen, const uint8_t* publickey);

#endif
