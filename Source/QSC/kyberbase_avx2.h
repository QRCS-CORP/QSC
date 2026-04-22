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

#ifndef QSC_KYBERBASE_AVX2_H
#define QSC_KYBERBASE_AVX2_H

#include "qsccommon.h"

 /* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/**
* \file kyberbase_avx2.h
* \brief The Kyber AVX2	functions
*/

#if defined(QSC_SYSTEM_HAS_AVX2)

 /*!
 \def QSC_KYBER_K
 * Read Only: The k level
 */
#if defined(QSC_KYBER_S1K2P512)
#	define QSC_KYBER_K 2
#elif defined(QSC_KYBER_S3K3P768)
#	define QSC_KYBER_K 3
#elif defined(QSC_KYBER_S5K4P1024)
#	define QSC_KYBER_K 4
#elif defined(QSC_KYBER_S6K5P1280)
#	define QSC_KYBER_K 5
#else
#	error "The Kyber parameter set is invalid!"
#endif

 /*!
 \def QSC_KYBER_N
 * Read Only: The polynomial dimension N
 */
#define QSC_KYBER_N 256

 /*!
 \def QSC_KYBER_Q
 * Read Only: The modulus prime factor Q
 */
#define QSC_KYBER_Q 3329

 /*!
 \def QSC_KYBER_ETA2
 * Read Only: The binomial distribution factor
 */
#define QSC_KYBER_ETA2 2

 /*!
 \def QSC_KYBER_MSGBYTES
 * Read Only: The size in bytes of the shared secret
 */
#define QSC_KYBER_MSGBYTES 32

 /*!
 \def QSC_KYBER_SYMBYTES
 * Read Only: The size in bytes of hashes, and seeds
 */
#define QSC_KYBER_SYMBYTES 32

 /*!
 \def QSC_KYBER_POLYBYTES
 * Read Only: The secret key base multiplier
 */
#define QSC_KYBER_POLYBYTES 384

#if (QSC_KYBER_K == 2)
#	define QSC_KYBER_POLYVECBASE_BYTES 320
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 128
#	define QSC_KYBER_ETA1 3
#elif (QSC_KYBER_K == 3)
#	define QSC_KYBER_POLYVECBASE_BYTES 320
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 128
#	define QSC_KYBER_ETA1 2
#elif (QSC_KYBER_K == 4)
#	define QSC_KYBER_POLYVECBASE_BYTES 352
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 160
#	define QSC_KYBER_ETA1 2
#elif (QSC_KYBER_K == 5)
#	define QSC_KYBER_POLYVECBASE_BYTES 352
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 160
#	define QSC_KYBER_ETA1 2
#endif

 /*!
 \def QSC_KYBER_POLYVEC_COMPRESSED_BYTES
 * Read Only: The base size of the public key
 */
#define QSC_KYBER_POLYVEC_COMPRESSED_BYTES (QSC_KYBER_K * QSC_KYBER_POLYVECBASE_BYTES)

 /*!
 \def QSC_KYBER_POLYVEC_BYTES
 * Read Only: The base size of the secret key
 */
#define QSC_KYBER_POLYVEC_BYTES (QSC_KYBER_K * QSC_KYBER_POLYBYTES)

 /*!
 \def QSC_KYBER_INDCPA_PUBLICKEY_BYTES
 * Read Only: The base INDCPA formatted public key size in bytes
 */
#define QSC_KYBER_INDCPA_PUBLICKEY_BYTES (QSC_KYBER_POLYVEC_BYTES + QSC_KYBER_SYMBYTES)

 /*!
 \def QSC_KYBER_INDCPA_SECRETKEY_BYTES
 * Read Only: The base INDCPA formatted private key size in bytes
 */
#define QSC_KYBER_INDCPA_SECRETKEY_BYTES (QSC_KYBER_POLYVEC_BYTES)

 /*!
 \def QSC_KYBER_INDCPA_BYTES
 * Read Only: The size of the INDCPA formatted output cipher-text
 */
#define QSC_KYBER_INDCPA_BYTES (QSC_KYBER_POLYVEC_COMPRESSED_BYTES + QSC_KYBER_POLYCOMPRESSED_BYTES)

 /*!
 \def QSC_KYBER_PUBLICKEY_BYTES
 * Read Only: The byte size of the public-key array
 */
#define QSC_KYBER_PUBLICKEY_BYTES  (QSC_KYBER_INDCPA_PUBLICKEY_BYTES)

 /*!
 \def QSC_KYBER_SECRETKEY_BYTES
 * Read Only: The byte size of the secret private-key array
 */
#define QSC_KYBER_SECRETKEY_BYTES  (QSC_KYBER_INDCPA_SECRETKEY_BYTES + QSC_KYBER_INDCPA_PUBLICKEY_BYTES + 2 * QSC_KYBER_SYMBYTES)

 /*!
 \def QSC_KYBER_CIPHERTEXT_BYTES
 * Read Only: The byte size of the cipher-text array
 */
#define QSC_KYBER_CIPHERTEXT_BYTES (QSC_KYBER_INDCPA_BYTES)

/* kem.h */

/**
* \brief Generates shared secret for given cipher text and private key
*
* \param ss: Pointer to output shared secret (an already allocated array of KYBER_SECRET_BYTES bytes)
* \param ct: [const] Pointer to input cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
* \param sk: [const] Pointer to input private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
* \return Returns true for success
*/
bool qsc_kyber_avx2_decapsulate(uint8_t ss[QSC_KYBER_MSGBYTES], const uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES],
	const uint8_t sk[QSC_KYBER_SECRETKEY_BYTES]);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct: [uint8_t*] Pointer to output cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
* \param ss: [uint8_t*] Pointer to output shared secret (an already allocated array of KYBER_BYTES bytes)
* \param pk: [const uint8_t*] Pointer to input public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param rng_generate: [func*] Pointer to the random generator function
* \return Returns true for success
*/
bool qsc_kyber_avx2_encapsulate(uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES], uint8_t ss[QSC_KYBER_MSGBYTES], const uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates cipher text and shared secret for given public key and a random seed
* \note Used exclusively for the NIST ACVP KAT tests, use the other call to encapsulate a key
* 
* \param ct: [uint8_t*] Pointer to output cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
* \param ss: [uint8_t*] Pointer to output shared secret (an already allocated array of KYBER_BYTES bytes)
* \param pk: [const uint8_t*] Pointer to input public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param m:	 [const uint8_t*] Pointer to the random coin (a populated array of QSC_KYBER_SYMBYTES bytes)
*/
void qsc_kyber_avx2_seeded_encapsulate(uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES], uint8_t ss[QSC_KYBER_MSGBYTES], const uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], const uint8_t m[QSC_KYBER_SYMBYTES]);

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
*
* \param pk: [uint8_t*] Pointer to output public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param sk: [uint8_t*] Pointer to output private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
* \param rng_generate: [func*] Pointer to the random generator function
* \return Returns true for success
*/
bool qsc_kyber_avx2_generate_keypair(uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], uint8_t sk[QSC_KYBER_SECRETKEY_BYTES], bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism using input seeds
*
* \param pk: [uint8_t*] Pointer to output public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param sk: [uint8_t*] Pointer to output private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
* \param d:	[uint8_t*] Pointer to the random d coin
* \param z:	[uint8_t*] Pointer to the random z coin
*/
void qsc_kyber_avx2_generate_seeded_keypair(uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], uint8_t sk[QSC_KYBER_SECRETKEY_BYTES], uint8_t d[QSC_KYBER_SYMBYTES], uint8_t z[QSC_KYBER_SYMBYTES]);

#endif

QSC_CPLUSPLUS_ENABLED_END

/* \cond NO_DOCUMENT */

#endif
