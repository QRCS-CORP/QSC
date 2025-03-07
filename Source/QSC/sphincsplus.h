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

#ifndef QSC_SPHINCSPLUS_H
#define QSC_SPHINCSPLUS_H

#include "common.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file sphincsplus.h
 * \brief The FIPS 205 implementation of the Sphincs+ Asymmetric Signature Scheme.
 *
 * \details
 * This header defines the primary public API for the FIPS 205 Sphincs+ asymmetric signature scheme implementation.
 * It provides functions for generating key pairs, signing messages, and verifying signatures.
 * The implementation is based on the C reference branch of SPHINCS+ from the FIPS 205 implementation.
 *
 * \code
 * // Example usage:
 * #define MSGLEN 32
 * uint8_t pk[QSC_SPHINCSPLUS_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_SPHINCSPLUS_PRIVATEKEY_SIZE];
 * uint8_t msg[MSGLEN];
 * uint8_t smsg[QSC_SPHINCSPLUS_SIGNATURE_SIZE + MSGLEN];
 * uint8_t rmsg[MSGLEN];
 * uint32_t smsglen = 0;
 * uint32_t rmsglen = 0;
 *
 * // Generate the key pair
 * qsc_sphincsplus_generate_keypair(pk, sk, rng_generate);
 *
 * // Sign the message
 * qsc_sphincsplus_sign(smsg, &smsglen, msg, MSGLEN, sk, rng_generate);
 *
 * // Verify the signature and recover the message
 * if (!qsc_sphincsplus_verify(rmsg, &rmsglen, smsg, smsglen, pk))
 * {
 *     // Signature verification failed; handle error.
 * }
 * \endcode
 *
 * \section sphincs_links Reference Links:
 * <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.205.pdf">NIST FIPS-205 SPHINCS+ Specification</a>
 * <a href="https://sphincs.org/">SPHINCS+ Website</a>
 */

#if defined(QSC_SPHINCSPLUS_S1S128SHAKERF)

/*!
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_SPHINCSPLUS_SIGNATURE_SIZE 17088

/*!
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_SPHINCSPLUS_PRIVATEKEY_SIZE 64

/*!
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_SPHINCSPLUS_PUBLICKEY_SIZE 32

#elif defined(QSC_SPHINCSPLUS_S1S128SHAKERS)

/*!
* \def QSC_SPHINCSPLUS_SIGNATURE_SIZE
* \brief The byte size of the signature array
*/
#	define QSC_SPHINCSPLUS_SIGNATURE_SIZE 7856

/*!
* \def QSC_SPHINCSPLUS_PRIVATEKEY_SIZE
* \brief The byte size of the secret private-key array
*/
#	define QSC_SPHINCSPLUS_PRIVATEKEY_SIZE 64

/*!
* \def QSC_SPHINCSPLUS_PUBLICKEY_SIZE
* \brief The byte size of the public-key array
*/
#	define QSC_SPHINCSPLUS_PUBLICKEY_SIZE 32

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
#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)

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
* \param publickey:		[uint8_t*] Pointer to the public verification-key array
* \param privatekey:	[uint8_t*] Pointer to the private signature-key array
* \param rng_generate:	[(uint8_t*, size_t)] Pointer to the random generator
*/
QSC_EXPORT_API void qsc_sphincsplus_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_SPHINCSPLUS_SIGNATURE_SIZE.
*
* \param signedmsg:		[uint8_t*] Pointer to the signed-message array
* \param smsglen:		[size_t*] Pointer to the signed message length
* \param message:		[const uint8_t*] Pointer to the message array
* \param msglen:		[size_t] The message length
* \param privatekey:	[const uint8_t*] Pointer to the private signature-key array
* \param rng_generate:	[(uint8_t*, size_t)] Pointer to the random generator
*/
QSC_EXPORT_API void qsc_sphincsplus_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message:		[uint8_t*] Pointer to the message array to be signed
* \param msglen:		[size_t*] Pointer to the message length
* \param signedmsg:		[const uint8_t*] Pointer to the signed message array
* \param smsglen:		[size_t] The signed message length
* \param publickey:		[const uint8_t*] Pointer to the public verification-key array
* \return				[bool] Returns true for success
*/
QSC_EXPORT_API bool qsc_sphincsplus_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
