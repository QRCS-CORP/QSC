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

#ifndef QSC_KYBERBASE_H
#define QSC_KYBERBASE_H

#include "common.h"

 /* \cond */

 /*!
 \def QSC_KYBER_K
 * Read Only: The k level
 */
#if defined(QSC_KYBER_S1P1632)
#	define QSC_KYBER_K 2
#elif defined(QSC_KYBER_S3P2400)
#	define QSC_KYBER_K 3
#elif defined(QSC_KYBER_S5P3168)
#	define QSC_KYBER_K 4
#elif defined(QSC_KYBER_S6P3936)
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
#define QSC_KYBER_MSGBYTES 32ULL

/*!
\def QSC_KYBER_SYMBYTES
* Read Only: The size in bytes of hashes, and seeds
*/
#define QSC_KYBER_SYMBYTES 32ULL

/*!
\def QSC_KYBER_POLYBYTES
* Read Only: The secret key base multiplier
*/
#define QSC_KYBER_POLYBYTES 384ULL

#if (QSC_KYBER_K == 2)
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 128
#	define QSC_KYBER_POLYVECBASE_BYTES 320
#	define QSC_KYBER_ETA1 3
#elif (QSC_KYBER_K == 3)
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 128
#	define QSC_KYBER_POLYVECBASE_BYTES 320
#	define QSC_KYBER_ETA1 2
#elif (QSC_KYBER_K == 4)
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 160
#	define QSC_KYBER_POLYVECBASE_BYTES 352
#	define QSC_KYBER_ETA1 2
#elif (QSC_KYBER_K == 5)
#	define QSC_KYBER_POLYCOMPRESSED_BYTES 160
#	define QSC_KYBER_POLYVECBASE_BYTES 352
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
* \param ss:	[uint8_t*] Pointer to output shared secret (an already allocated array of KYBER_SECRET_BYTES bytes)
* \param ct:	[const uint8_t*] Pointer to input cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
* \param sk:	[const uint8_t*] Pointer to input private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
* \return		[bool] Returns true for success
*/
bool qsc_kyber_ref_decapsulate(uint8_t ss[QSC_KYBER_MSGBYTES], const uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES],
	const uint8_t sk[QSC_KYBER_SECRETKEY_BYTES]);

/**
* \brief Generates cipher text and shared secret for given public key
*
* \param ct:	[uint8_t*] Pointer to output cipher text (an already allocated array of KYBER_CIPHERTEXT_SIZE bytes)
* \param ss:	[uint8_t*] Pointer to output shared secret (an already allocated array of KYBER_BYTES bytes)
* \param pk:	[const uint8_t*] Pointer to input public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param rng_generate: [uint8_t*, size_t] Pointer to the random generator function
*/
void qsc_kyber_ref_encapsulate(uint8_t ct[QSC_KYBER_CIPHERTEXT_BYTES], uint8_t ss[QSC_KYBER_MSGBYTES],
	const uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the CCA-Secure Kyber key encapsulation mechanism
*
* \param pk:	[uint8_t*] Pointer to output public key (an already allocated array of KYBER_PUBLICKEY_SIZE bytes)
* \param sk:	[uint8_t*] Pointer to output private key (an already allocated array of KYBER_SECRETKEY_SIZE bytes)
* \param rng_generate: [uint8_t*, size_t] Pointer to the random generator function
*/
void qsc_kyber_ref_generate_keypair(uint8_t pk[QSC_KYBER_PUBLICKEY_BYTES], uint8_t sk[QSC_KYBER_SECRETKEY_BYTES], 
	bool (*rng_generate)(uint8_t*, size_t));

/* \endcond */

#endif
