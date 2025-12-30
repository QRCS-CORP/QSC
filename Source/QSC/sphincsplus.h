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

#ifndef QSC_SPHINCSPLUS_H
#define QSC_SPHINCSPLUS_H

#include "qsccommon.h"

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

#if defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
/*!
* \def QSC_SPHINCSPLUS_GENERATE_SEED_SIZE
* \brief The byte size of the key generation seed
*/
#	define QSC_SPHINCSPLUS_GENERATE_SEED_SIZE 48

/*!
* \def QSC_SPHINCSPLUS_SIGN_SEED_SIZE
* \brief The byte size of the signing key array
*/
#	define QSC_SPHINCSPLUS_SIGN_SEED_SIZE 16

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

#elif defined(QSC_SPHINCSPLUS_S3S192SHAKERS)

/*!
* \def QSC_SPHINCSPLUS_GENERATE_SEED_SIZE
* \brief The byte size of the key generation seed
*/
#	define QSC_SPHINCSPLUS_GENERATE_SEED_SIZE 72

/*!
* \def QSC_SPHINCSPLUS_SIGN_SEED_SIZE
* \brief The byte size of the signing key array
*/
#	define QSC_SPHINCSPLUS_SIGN_SEED_SIZE 24

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

#elif defined(QSC_SPHINCSPLUS_S5S256SHAKERS)

/*!
* \def QSC_SPHINCSPLUS_GENERATE_SEED_SIZE
* \brief The byte size of the key generation seed
*/
#	define QSC_SPHINCSPLUS_GENERATE_SEED_SIZE 96

/*!
* \def QSC_SPHINCSPLUS_SIGN_SEED_SIZE
* \brief The byte size of the signing key array
*/
#	define QSC_SPHINCSPLUS_SIGN_SEED_SIZE 32

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

#elif defined(QSC_SPHINCSPLUS_S6S512SHAKERS)

/*!
* \def QSC_SPHINCSPLUS_GENERATE_SEED_SIZE
* \brief The byte size of the key generation seed
*/
#	define QSC_SPHINCSPLUS_GENERATE_SEED_SIZE 192

/*!
* \def QSC_SPHINCSPLUS_SIGN_SEED_SIZE
* \brief The byte size of the signing key array
*/
#	define QSC_SPHINCSPLUS_SIGN_SEED_SIZE 64

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
* \return				[bool] Returns true for success
*/
QSC_EXPORT_API bool qsc_sphincsplus_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates a Sphincs+ public/private key-pair using a seed.
*
* \warning Arrays must be sized to QSC_SPHINCSPLUS_PUBLICKEY_SIZE and QSC_SPHINCSPLUS_SECRETKEY_SIZE, seed to QSC_SPHINCSPLUS_GENERATE_SEED_SIZE.
*
* \param publickey:		[uint8_t*] Pointer to the public verification-key array
* \param privatekey:	[uint8_t*] Pointer to the private signature-key array
* \param seed:			[const uint8_t*] Pointer to the random generator
* \return				[bool] Returns true for success
*/
QSC_EXPORT_API bool qsc_sphincsplus_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t seed[QSC_SPHINCSPLUS_GENERATE_SEED_SIZE]);

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
* \return				[bool] Returns true for success
*/
QSC_EXPORT_API bool qsc_sphincsplus_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Takes the message as input with the additional context parameter and returns an array containing the signature followed by the message.
 *
 * \warning The signed-message array must be sized to the size of the message plus QSC_SPHINCSPLUS_SIGNATURE_SIZE.
 *
 * \param signedmsg:	[uint8_t*] Pointer to the signed-message array.
 * \param smsglen:		[size_t*] Pointer to the signed message length.
 * \param message:		[const uint8_t*] Pointer to the message array.
 * \param msglen:		[size_t] The message array length.
 * \param context:		[const uint8_t*] Pointer to the context array.
 * \param ctxlen:		[size_t] The context array length.
 * \param privatekey:	[const uint8_t*] Pointer to the private signature-key.
 * \param seed:			[const uint8_t*] Pointer to the random generator.
 * \return				[bool] Returns true if the message was signed successfully.
 */
QSC_EXPORT_API bool qsc_sphincsplus_sign_ex(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message and a seed as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_SPHINCSPLUS_SIGNATURE_SIZE.
*
* \param signedmsg:		[uint8_t*] Pointer to the signed-message array
* \param smsglen:		[size_t*] Pointer to the signed message length
* \param message:		[const uint8_t*] Pointer to the message array
* \param msglen:		[size_t] The message length
* \param context:		[const uint8_t*] Pointer to the context array.
* \param ctxlen:		[size_t] The context array length.
* \param privatekey:	[const uint8_t*] Pointer to the private signature-key array
* \param seed:			[const uint8_t*] Pointer to the random seed
* \return				[bool] Returns true for success
*/
QSC_EXPORT_API bool qsc_sphincsplus_seeded_sign_ex(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, const uint8_t* seed);

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

/**
 * \brief Verifies a signature-message pair and context parameter with the public key.
 *
 * \param message:		[uint8_t*] Pointer to the message output array.
 * \param msglen:		[size_t*] Pointer to the length of the message array.
 * \param context:		[const uint8_t*] Pointer to the context array.
 * \param ctxlen:		[size_t] The context array length.
 * \param signedmsg:	[const uint8_t*] Pointer to the signed message array.
 * \param smsglen:		[size_t] The signed message length.
 * \param publickey:	[const uint8_t*] Pointer to the public verification-key array.
 * \return				[bool] Returns true if the signature is valid.
 */
QSC_EXPORT_API bool qsc_sphincsplus_verify_ex(uint8_t* message, size_t* msglen, const uint8_t* context, size_t ctxlen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
