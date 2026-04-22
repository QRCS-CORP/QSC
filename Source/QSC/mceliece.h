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

#ifndef QSC_MCELIECE_H
#define QSC_MCELIECE_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file mceliece.h
 * \brief Contains the primary public API for the Niederreiter dual form of the McEliece asymmetric cipher implementation.
 *
 * \details
 * This header defines the functions and constants for the McEliece Key Encapsulation Mechanism (KEM) implementation.
 * Depending on the defined parameter set (e.g. QSC_MCELIECE_S1N3488T64, QSC_MCELIECE_S3N4608T96, etc.), the sizes of the ciphertext,
 * private key, and public key vary. The API supports key encapsulation (encryption) and decapsulation (decryption) operations.
 *
 * \code
 * uint8_t ct[QSC_MCELIECE_CIPHERTEXT_SIZE];
 * uint8_t pk[QSC_MCELIECE_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_MCELIECE_PRIVATEKEY_SIZE];
 * uint8_t ssa[QSC_MCELIECE_SHAREDSECRET_SIZE];
 * uint8_t ssb[QSC_MCELIECE_SHAREDSECRET_SIZE];
 *
 * // Create the public and secret keys.
 * qsc_mceliece_generate_keypair(pk, sk, rng_generate);
 *
 * // Output the ciphertext and the shared secret.
 * qsc_mceliece_encapsulate(ssb, ct, pk, rng_generate);
 *
 * // Decapsulate to retrieve the shared secret.
 * if (qsc_mceliece_decapsulate(ssa, ct, sk) == false)
 * {
 *     // Decapsulation failed; handle error.
 * }
 * \endcode
 *
 * \section mceliece_links Reference Links:
 * - <a href="https://classicmceliece.org/specification/">Classic McEliece Specification</a>
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA3 Standard (FIPS 202)</a>
 */

/**
 * \def QSC_MCELIECE_KEYGEN_STACK_BYTES
 * \brief Minimum stack size required to call qsc_mceliece_generate_keypair.
 *
 * Key generation allocates a ~1.7 MiB Gaussian-elimination matrix on the
 * stack (matching the NIST round-4 reference implementation).  Callers
 * running on threads with small default stacks (macOS secondary threads:
 * 512 KiB, Windows default: 1 MiB, musl libc: 128 KiB) MUST either set
 * a larger stack size before creating the thread, or use the provided
 * qsc_mceliece_generate_keypair_ex() wrapper which spawns a dedicated
 * thread with the correct stack size.
 */
#define QSC_MCELIECE_KEYGEN_STACK_BYTES  (4U * 1024U * 1024U)

/* Parameter definitions for different McEliece parameter sets */
#if defined(QSC_MCELIECE_S1N3488T64)

	/*!
	* \def QSC_MCELIECE_CIPHERTEXT_SIZE
	* \brief The byte size of the ciphertext array.
	*/
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 128U

	/*!
	* \def QSC_MCELIECE_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array.
	*/
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 6492U

	/*!
	* \def QSC_MCELIECE_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array.
	*/
#	define QSC_MCELIECE_PUBLICKEY_SIZE 261120U

	/*!
	* \def QSC_MCELIECE_ALGNAME
	* \brief The formal algorithm name.
	*/
#	define QSC_MCELIECE_ALGNAME "MCELIECE-P3488T64"

#elif defined(QSC_MCELIECE_S3N4608T96)

	/*!
	* \def QSC_MCELIECE_CIPHERTEXT_SIZE
	* \brief The byte size of the ciphertext array.
	*/
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 188U

	/*!
	* \def QSC_MCELIECE_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array.
	*/
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 13608U

	/*!
	* \def QSC_MCELIECE_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array.
	*/
#	define QSC_MCELIECE_PUBLICKEY_SIZE 524160U

	/*!
	* \def QSC_MCELIECE_ALGNAME
	* \brief The formal algorithm name.
	*/
#	define QSC_MCELIECE_ALGNAME "MCELIECE-P4608T96"

#elif defined(QSC_MCELIECE_S5N6688T128)

	/*!
	* \def QSC_MCELIECE_CIPHERTEXT_SIZE
	* \brief The byte size of the ciphertext array.
	*/
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 240U

	/*!
	* \def QSC_MCELIECE_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array.
	*/
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 13932U

	/*!
	* \def QSC_MCELIECE_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array.
	*/
#	define QSC_MCELIECE_PUBLICKEY_SIZE 1044992U

	/*!
	* \def QSC_MCELIECE_ALGNAME
	* \brief The formal algorithm name.
	*/
#	define QSC_MCELIECE_ALGNAME "MCELIECE-P6688T128"

#elif defined(QSC_MCELIECE_S6N6960T119)

	/*!
	* \def QSC_MCELIECE_CIPHERTEXT_SIZE
	* \brief The byte size of the ciphertext array.
	*/
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 226U

	/*!
	* \def QSC_MCELIECE_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array.
	*/
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 13948U

	/*!
	* \def QSC_MCELIECE_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array.
	*/
#	define QSC_MCELIECE_PUBLICKEY_SIZE 1047319U

	/*!
	* \def QSC_MCELIECE_ALGNAME
	* \brief The formal algorithm name.
	*/
#	define QSC_MCELIECE_ALGNAME "MCELIECE-P6960T119"

#elif defined(QSC_MCELIECE_S7N8192T128)

	/*!
	* \def QSC_MCELIECE_CIPHERTEXT_SIZE
	* \brief The byte size of the ciphertext array.
	*/
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 240U

	/*!
	* \def QSC_MCELIECE_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array.
	*/
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 14120U

	/*!
	* \def QSC_MCELIECE_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array.
	*/
#	define QSC_MCELIECE_PUBLICKEY_SIZE 1357824U

	/*!
	* \def QSC_MCELIECE_ALGNAME
	* \brief The formal algorithm name.
	*/
#	define QSC_MCELIECE_ALGNAME "MCELIECE-P8192T128"

#else
#	error "The McEliece parameter set is invalid!"
#endif

/*!
 * \def QSC_MCELIECE_SEED_SIZE
 * \brief The byte size of the seed array.
 */
#define QSC_MCELIECE_SEED_SIZE 32ULL

/*!
 * \def QSC_MCELIECE_SHAREDSECRET_SIZE
 * \brief The byte size of the shared secret-key array.
 */
#define QSC_MCELIECE_SHAREDSECRET_SIZE 32ULL

/**
 * \brief Decapsulates the shared secret for a given ciphertext using a private key.
 *
 * \param secret: [uint8_t*] Pointer to the output shared secret key (array of QSC_MCELIECE_SHAREDSECRET_SIZE).
 * \param ciphertext: [const uint8_t*] Pointer to the ciphertext array (size QSC_MCELIECE_CIPHERTEXT_SIZE).
 * \param privatekey: [const uint8_t*] Pointer to the private key array (size QSC_MCELIECE_PRIVATEKEY_SIZE).
 * \return [bool] Returns true if decapsulation succeeds.
 */
QSC_EXPORT_API bool qsc_mceliece_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates a shared secret key using a public key.
 *
 * \param secret: [uint8_t*] Pointer to the output shared secret key (array of QSC_MCELIECE_SHAREDSECRET_SIZE).
 * \param ciphertext: [uint8_t*] Pointer to the output ciphertext array (size QSC_MCELIECE_CIPHERTEXT_SIZE).
 * \param publickey: [const uint8_t*] Pointer to the public key array (size QSC_MCELIECE_PUBLICKEY_SIZE).
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 * \return [bool] Returns true if encapsulation succeeds.
 */
QSC_EXPORT_API bool qsc_mceliece_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates a McEliece public/private key pair.
 *
 * \param publickey: [uint8_t*] Pointer to the output public key array (size QSC_MCELIECE_PUBLICKEY_SIZE).
 * \param privatekey: [uint8_t*] Pointer to the output private key array (size QSC_MCELIECE_PRIVATEKEY_SIZE).
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 * \return [bool] Returns true if key generation succeeds.
 */
QSC_EXPORT_API bool qsc_mceliece_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

QSC_CPLUSPLUS_ENABLED_END

#endif
