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

#ifndef QSC_DILITHIUM_H
#define QSC_DILITHIUM_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

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
 * uint32_t rmsglen = 0U;
 * uint32_t smsglen = 0U;
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

/*!
 * \def QSC_DILITHIUM_GENERATE_SEED_SIZE
 * \brief The byte size of the seeded generator seed array.
 */
#define QSC_DILITHIUM_GENERATE_SEED_SIZE 32U

#if defined(QSC_DILITHIUM_S1P44)

	/*!
	 * \def QSC_DILITHIUM_PRIVATEKEY_SIZE
	 * \brief The byte size of the secret private-key array.
	 */
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 2560U

	/*!
	 * \def QSC_DILITHIUM_PUBLICKEY_SIZE
	 * \brief The byte size of the public-key array.
	 */
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1312U

	/*!
	 * \def QSC_DILITHIUM_SIGNATURE_SIZE
	 * \brief The byte size of the signature array.
	 */
#	define QSC_DILITHIUM_SIGNATURE_SIZE 2420U

	/*!
	 * \def QSC_DILITHIUM_ALGNAME
	 * \brief The formal algorithm name.
	 */
#define QSC_DILITHIUM_ALGNAME "DILITHIUM-P44"

#elif defined(QSC_DILITHIUM_S3P65)

	/*!
	 * \def QSC_DILITHIUM_PRIVATEKEY_SIZE
	 * \brief The byte size of the secret private-key array.
	 */
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 4032U

	/*!
	 * \def QSC_DILITHIUM_PUBLICKEY_SIZE
	 * \brief The byte size of the public-key array.
	 */
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 1952U

	/*!
	 * \def QSC_DILITHIUM_SIGNATURE_SIZE
	 * \brief The byte size of the signature array.
	 */
#	define QSC_DILITHIUM_SIGNATURE_SIZE 3309U

	/*!
	 * \def QSC_DILITHIUM_ALGNAME
	 * \brief The formal algorithm name.
	 */
#	define QSC_DILITHIUM_ALGNAME "DILITHIUM-P65"

#elif defined(QSC_DILITHIUM_S5P87)

	/*!
	 * \def QSC_DILITHIUM_PRIVATEKEY_SIZE
	 * \brief The byte size of the secret private-key array.
	 */
#	define QSC_DILITHIUM_PRIVATEKEY_SIZE 4896U

	/*!
	 * \def QSC_DILITHIUM_PUBLICKEY_SIZE
	 * \brief The byte size of the public-key array.
	 */
#	define QSC_DILITHIUM_PUBLICKEY_SIZE 2592U

	/*!
	 * \def QSC_DILITHIUM_SIGNATURE_SIZE
	 * \brief The byte size of the signature array.
	 */
#	define QSC_DILITHIUM_SIGNATURE_SIZE 4627U

	/*!
	 * \def QSC_DILITHIUM_ALGNAME
	 * \brief The formal algorithm name.
	 */
#	define QSC_DILITHIUM_ALGNAME "DILITHIUM-P87"

#else
#	error "The Dilithium parameter set is invalid!"
#endif

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
 * \param publickey: [uint8_t*] Pointer to the public verification-key array.
 * \param privatekey: [uint8_t*] Pointer to the private signature-key array.
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to the random generator.
 * 
 * \return [bool] Returns true if the key pair was generated successfully.
 */
QSC_EXPORT_API bool qsc_dilithium_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a Dilithium public/private key-pair using a random input seed.
* \note Used exclusively for the NIST ACVP KAT tests, use the other call to generate the key-pair.
 *
 * \warning Arrays must be sized to QSC_DILITHIUM_PUBLICKEY_SIZE, QSC_DILITHIUM_PRIVATEKEY_SIZE, and the seed to DILITHIUM_SEEDBYTES.
 *
 * \param publickey: [uint8_t*] Pointer to the public verification-key array.
 * \param privatekey: [uint8_t*] Pointer to the private signature-key array.
 * \param seed: [const uint8_t*] Pointer to the random seed.
 */
QSC_EXPORT_API void qsc_dilithium_seeded_generate_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Takes the message as input and returns an array containing the signature followed by the message.
 *
 * \warning The signed-message array must be sized to the size of the message plus QSC_DILITHIUM_SIGNATURE_SIZE.
 *
 * \param signedmsg: [uint8_t*] Pointer to the signed-message array.
 * \param smsglen: [size_t*] Pointer to the signed message length.
 * \param message: [const uint8_t*] Pointer to the message array.
 * \param msglen: [size_t] The message array length.
 * \param privatekey: [const uint8_t*] Pointer to the private signature-key.
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to the random generator.
 * 
 * \return [bool] Returns true if the message was signed successfully.
 */
QSC_EXPORT_API bool qsc_dilithium_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Takes the message as input with the additional context parameter, and returns an array containing the signature followed by the message.
 *
 * \warning The signed-message array must be sized to the size of the message plus QSC_DILITHIUM_SIGNATURE_SIZE.
 *
 * \param signedmsg: [uint8_t*] Pointer to the signed-message array.
 * \param smsglen: [size_t*] Pointer to the signed message length.
 * \param message: [const uint8_t*] Pointer to the message array.
 * \param msglen: [size_t] The message array length.
 * \param context: [const uint8_t*] Pointer to the context array.
 * \param ctxlen: [size_t] The context array length.
 * \param privatekey: [const uint8_t*] Pointer to the private signature-key.
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to the random generator.
 * 
 * \return [bool] Returns true if the message was signed successfully.
 */
QSC_EXPORT_API bool qsc_dilithium_sign_ex(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Verifies a signature-message pair with the public key.
 *
 * \param message: [uint8_t*] Pointer to the message output array.
 * \param msglen: [size_t*] Pointer to the length of the message array.
 * \param signedmsg: [const uint8_t*] Pointer to the signed message array.
 * \param smsglen: [size_t] The signed message length.
 * \param publickey: [const uint8_t*] Pointer to the public verification-key array.
 * 
 * \return [bool] Returns true if the signature is valid.
 */
QSC_EXPORT_API bool qsc_dilithium_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

/**
 * \brief Verifies a signature-message pair and context parameter with the public key.
 *
 * \param message: [uint8_t*] Pointer to the message output array.
 * \param msglen: [size_t*] Pointer to the length of the message array.
 * \param context: [const uint8_t*] Pointer to the context array.
 * \param ctxlen: [size_t] The context array length.
 * \param signedmsg: [const uint8_t*] Pointer to the signed message array.
 * \param smsglen: [size_t] The signed message length.
 * \param publickey: [const uint8_t*] Pointer to the public verification-key array.
 * 
 * \return [bool] Returns true if the signature is valid.
 */
QSC_EXPORT_API bool qsc_dilithium_verify_ex(uint8_t* message, size_t* msglen, const uint8_t* context, size_t ctxlen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
