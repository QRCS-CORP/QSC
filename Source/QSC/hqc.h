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

#ifndef QSC_HQC_H
#define QSC_HQC_H

#include "qsccommon.h"
#if defined(QSC_SYSTEM_HAS_AVX2)
	#include "hqcbase_avx2.h"
#else
	#include "hqcbase.h"
#endif

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file hqc.h
 * \brief Contains the public API for the HQC CCA-secure Key Encapsulation Mechanism.
 *
 * \details
 * The Hamming Quasi-Cyclic (HQC) key encapsulation mechanism provides functionality for
 * generating key pairs, encapsulating a shared secret using a public key, and decapsulating
 * the shared secret using a private key.
 *
 * This interface supports the HQC parameter sets corresponding to NIST security categories
 * 1, 3, and 5. The active implementation is selected at compile time using one of the
 * parameter guard macros QSC_HQC_S1N2321, QSC_HQC_S3N4602, or QSC_HQC_S5N7333.
 *
 * \code
 * // Example usage:
 * uint8_t pk[QSC_HQC_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_HQC_PRIVATEKEY_SIZE];
 * uint8_t ct[QSC_HQC_CIPHERTEXT_SIZE];
 * uint8_t ss[QSC_HQC_SHAREDSECRET_SIZE];
 *
 * qsc_hqc_generate_keypair(pk, sk, rng_generate);
 * qsc_hqc_encapsulate(ss, ct, pk, rng_generate);
 * if (qsc_hqc_decapsulate(ss, ct, sk) == false)
 * {
 *     // Decapsulation failed.
 * }
 * \endcode
 *
 * \section hqc_links Reference Links:
 * - <a href="https://pqc-hqc.org/">HQC Project Page</a>
 * - <a href="https://csrc.nist.gov/Projects/post-quantum-cryptography/round-4-submissions">NIST Post-Quantum Cryptography Round 4 Submissions</a>
 */

#if defined(QSC_HQC_S1N2321)

	/*!
	* \def QSC_HQC_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array.
	*/
#	define QSC_HQC_PUBLICKEY_SIZE 2241U

	/*!
	* \def QSC_HQC_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array.
	*/
#	define QSC_HQC_PRIVATEKEY_SIZE 2321U

	/*!
	* \def QSC_HQC_CIPHERTEXT_SIZE
	* \brief The byte size of the ciphertext array.
	*/
#	define QSC_HQC_CIPHERTEXT_SIZE 4433U

	/*!
	 * \def QSC_HQC_ALGNAME
	 * \brief The formal algorithm name.
	 */
#	define QSC_HQC_ALGNAME "HQC-2321"

#elif defined(QSC_HQC_S3N4602)

	/*!
	* \def QSC_HQC_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array.
	*/
#	define QSC_HQC_PUBLICKEY_SIZE 4514U

	/*!
	* \def QSC_HQC_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array.
	*/
#	define QSC_HQC_PRIVATEKEY_SIZE 4602U

	/*!
	* \def QSC_HQC_CIPHERTEXT_SIZE
	* \brief The byte size of the ciphertext array.
	*/
#	define QSC_HQC_CIPHERTEXT_SIZE 8978U

	/*!
	 * \def QSC_HQC_ALGNAME
	 * \brief The formal algorithm name.
	 */
#	define QSC_HQC_ALGNAME "HQC-4602"

#elif defined(QSC_HQC_S5N7333)

	/*!
	* \def QSC_HQC_PUBLICKEY_SIZE
	* \brief The byte size of the public-key array.
	*/
#	define QSC_HQC_PUBLICKEY_SIZE 7237U

	/*!
	* \def QSC_HQC_PRIVATEKEY_SIZE
	* \brief The byte size of the secret private-key array.
	*/
#	define QSC_HQC_PRIVATEKEY_SIZE 7333U

	/*!
	* \def QSC_HQC_CIPHERTEXT_SIZE
	* \brief The byte size of the ciphertext array.
	*/
#	define QSC_HQC_CIPHERTEXT_SIZE 14421U

	/*!
	 * \def QSC_HQC_ALGNAME
	 * \brief The formal algorithm name.
	 */
#	define QSC_HQC_ALGNAME "HQC-7333"

#else
#	error "A valid HQC parameter set must be defined: QSC_HQC_S1N2321, QSC_HQC_S3N4602, or QSC_HQC_S5N7333."
#endif

/*!
 * \def QSC_HQC_SEED_SIZE
 * \brief The byte size of the seed array.
 */
#define QSC_HQC_SEED_SIZE 32U

/*!
 * \def QSC_HQC_SHAREDSECRET_SIZE
 * \brief The byte size of the shared secret-key array.
 */
#define QSC_HQC_SHAREDSECRET_SIZE 32U

/**
 * \brief Decapsulates the shared secret for a given ciphertext using a private key.
 *
 * Combines the ciphertext with the private key to derive the shared secret.
 *
 * \param secret: [uint8_t*] Pointer to the output shared secret key (array of QSC_HQC_SHAREDSECRET_SIZE).
 * \param ciphertext: [const uint8_t*] Pointer to the ciphertext array (size QSC_HQC_CIPHERTEXT_SIZE).
 * \param privatekey: [const uint8_t*] Pointer to the secret key array (size QSC_HQC_PRIVATEKEY_SIZE).
 * 
 * \return [bool] Returns true if decapsulation succeeds.
 */
QSC_EXPORT_API bool qsc_hqc_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates a shared secret key using a public key.
 *
 * Generates ciphertext and a shared secret; used for key encapsulation.
 *
 * \param secret: [uint8_t*] Pointer to the output shared secret key (array of QSC_HQC_SHAREDSECRET_SIZE).
 * \param ciphertext: [uint8_t*] Pointer to the output ciphertext array (size QSC_HQC_CIPHERTEXT_SIZE).
 * \param publickey: [const uint8_t*] Pointer to the public key array (size QSC_HQC_PUBLICKEY_SIZE).
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 * 
 * \return [bool] Returns true if encapsulation succeeds.
 */
QSC_EXPORT_API bool qsc_hqc_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates cipher text and shared secret for given public key and a random seed.
* \note Used exclusively for the NIST ACVP KAT tests, use the other call to encapsulate a key.
* 
* \param ct: [uint8_t*] Pointer to output cipher text (an already allocated array of HQC_CIPHERTEXT_SIZE bytes)
* \param ss: [uint8_t*] Pointer to output shared secret (an already allocated array of HQC_BYTES bytes)
* \param pk: [const uint8_t*] Pointer to input public key (an already allocated array of HQC_PUBLICKEY_SIZE bytes)
* \param seed: [const uint8_t*] Pointer to the random seed (a populated random array of QSC_HQC_SEED_SIZE bytes)
*/
void qsc_hqc_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_HQC_SEED_SIZE]);

/**
 * \brief Generates a Kyber public/private key pair.
 *
 * Produces a key pair for the Kyber key encapsulation mechanism.
 *
 * \param publickey: [uint8_t*] Pointer to the output public key array (size QSC_HQC_PUBLICKEY_SIZE)
 * \param privatekey: [uint8_t*] Pointer to the output private key array (size QSC_HQC_PRIVATEKEY_SIZE)
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 * 
 * \return [bool] Returns true if key generation succeeds.
 */
QSC_EXPORT_API bool qsc_hqc_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism using input seeds.
* \note Used exclusively for the NIST ACVP KAT tests, use the other call to generate the key-pair.
*
* \param publickey:	[uint8_t*] Pointer to output public key (an already allocated array of HQC_PUBLICKEY_SIZE bytes)
* \param privatekey: [uint8_t*] Pointer to output private key (an already allocated array of HQC_SECRETKEY_SIZE bytes)
* \param seed: [uint8_t*] Pointer to the random seed
*/
QSC_EXPORT_API void qsc_hqc_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* seed);

QSC_CPLUSPLUS_ENABLED_END

#endif
