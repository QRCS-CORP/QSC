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

#ifndef QSC_KYBER_H
#define QSC_KYBER_H

#include "qsccommon.h"
#if defined(QSC_SYSTEM_HAS_AVX2)
	#include "kyberbase_avx2.h"
#else
	#include "kyberbase.h"
#endif

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file kyber.h
 * \brief Contains the public API for the FIPS 203 implementation of the Kyber CCA-secure Key Encapsulation Mechanism.
 *
 * \details
 * The Kyber key encapsulation mechanism (KEM) provides functionality for generating key pairs,
 * encapsulating a shared secret using a public key, and decapsulating the shared secret using a private key.
 * It is the FIPS 203 Kyber implementation with an additional K=5 parameter to enhance security.
 *
 * \code
 * // Example usage:
 * uint8_t pk[QSC_KYBER_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_KYBER_PRIVATEKEY_SIZE];
 * uint8_t ct[QSC_KYBER_CIPHERTEXT_SIZE];
 * uint8_t ss[QSC_KYBER_SHAREDSECRET_SIZE];
 *
 * qsc_kyber_generate_keypair(pk, sk, rng_generate);
 * qsc_kyber_encapsulate(ss, ct, pk, rng_generate);
 * if (!qsc_kyber_decapsulate(ss, ct, sk))
 * {
 *     // Decapsulation failed.
 * }
 * \endcode
 *
 * \section kyber_links Reference Links:
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf">Kyber Specification (FIPS 203) </a>
 */

/*!
 * \def QSC_KYBER_CIPHERTEXT_SIZE
 * \brief The byte size of the ciphertext array.
 */
#define QSC_KYBER_CIPHERTEXT_SIZE (QSC_KYBER_INDCPA_BYTES)

/*!
 * \def QSC_KYBER_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#define QSC_KYBER_PRIVATEKEY_SIZE (QSC_KYBER_INDCPA_SECRETKEY_BYTES + QSC_KYBER_INDCPA_PUBLICKEY_BYTES + (2 * QSC_KYBER_SYMBYTES))

/*!
 * \def QSC_KYBER_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#define QSC_KYBER_PUBLICKEY_SIZE (QSC_KYBER_INDCPA_PUBLICKEY_BYTES)

/*!
 * \def QSC_KYBER_SEED_SIZE
 * \brief The byte size of the seed array.
 */
#define QSC_KYBER_SEED_SIZE 32U

/*!
 * \def QSC_KYBER_SHAREDSECRET_SIZE
 * \brief The byte size of the shared secret-key array.
 */
#define QSC_KYBER_SHAREDSECRET_SIZE 32U

/*!
 * \def QSC_KYBER_ALGNAME
 * \brief The formal algorithm name.
 */
#define QSC_KYBER_ALGNAME "KYBER"

/**
 * \brief Decapsulates the shared secret for a given ciphertext using a private key.
 *
 * Combines the ciphertext with the private key to derive the shared secret.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_KYBER_SHAREDSECRET_SIZE).
 * \param ciphertext:	[const uint8_t*] Pointer to the ciphertext array (size QSC_KYBER_CIPHERTEXT_SIZE).
 * \param privatekey:	[const uint8_t*] Pointer to the secret key array (size QSC_KYBER_PRIVATEKEY_SIZE).
 * \return				[bool] Returns true if decapsulation succeeds.
 */
QSC_EXPORT_API bool qsc_kyber_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates a shared secret key using a public key.
 *
 * Generates ciphertext and a shared secret; used for key encapsulation.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_KYBER_SHAREDSECRET_SIZE).
 * \param ciphertext:	[uint8_t*] Pointer to the output ciphertext array (size QSC_KYBER_CIPHERTEXT_SIZE).
 * \param publickey:	[const uint8_t*] Pointer to the public key array (size QSC_KYBER_PUBLICKEY_SIZE).
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 * \return				[bool] Returns true if encapsulation succeeds.
 */
QSC_EXPORT_API bool qsc_kyber_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates cipher text and shared secret for given public key and a random seed.
* \note Used exclusively for the NIST ACVP KAT tests, use the other call to encapsulate a key.
* 
* \param ct:	[uint8_t*] Pointer to output cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
* \param ss:	[uint8_t*] Pointer to output shared secret (an already allocated array of KYBER_BYTES bytes)
* \param pk:	[const uint8_t*] Pointer to input public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param m:		[const uint8_t*] Pointer to the random coin (a populated random array of QSC_KYBER_SYMBYTES bytes)
*/
void qsc_kyber_seeded_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t m[QSC_KYBER_SYMBYTES]);

/**
 * \brief Generates a Kyber public/private key pair.
 *
 * Produces a key pair for the Kyber key encapsulation mechanism.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public key array (size QSC_KYBER_PUBLICKEY_SIZE)
 * \param privatekey:	[uint8_t*] Pointer to the output private key array (size QSC_KYBER_PRIVATEKEY_SIZE)
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 * \return				[bool] Returns true if key generation succeeds.
 */
QSC_EXPORT_API bool qsc_kyber_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism using input seeds.
* \note Used exclusively for the NIST ACVP KAT tests, use the other call to generate the key-pair.
*
* \param pk:	[uint8_t*] Pointer to output public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param sk:	[uint8_t*] Pointer to output private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
* \param d:		[uint8_t*] Pointer to the random d coin (a populated random array of QSC_KYBER_SYMBYTES bytes)
* \param z:		[uint8_t*] Pointer to the random z coin (a populated random array of QSC_KYBER_SYMBYTES bytes)
*/
QSC_EXPORT_API void qsc_kyber_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, uint8_t* d, uint8_t* z);

QSC_CPLUSPLUS_ENABLED_END

#endif
