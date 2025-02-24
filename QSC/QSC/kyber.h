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

#ifndef QSC_KYBER_H
#define QSC_KYBER_H

#include "common.h"
#if defined(QSC_SYSTEM_HAS_AVX2)
	#include "kyberbase_avx2.h"
#else
	#include "kyberbase.h"
#endif

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
 * - <a href="https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf">SHA-3 Standard (FIPS 202)</a>
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
#define QSC_KYBER_SEED_SIZE 32ULL

/*!
 * \def QSC_KYBER_SHAREDSECRET_SIZE
 * \brief The byte size of the shared secret-key array.
 */
#define QSC_KYBER_SHAREDSECRET_SIZE 32ULL

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
 * \brief Decrypts the shared secret for a given ciphertext using a private key.
 *
 * Alternative decryption function; functionally equivalent to decapsulation.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_KYBER_SHAREDSECRET_SIZE).
 * \param ciphertext:	[const uint8_t*] Pointer to the ciphertext array (size QSC_KYBER_CIPHERTEXT_SIZE).
 * \param privatekey:	[const uint8_t*] Pointer to the secret key array (size QSC_KYBER_PRIVATEKEY_SIZE).
 * \return				[bool] Returns true if decryption succeeds.
 */
QSC_EXPORT_API bool qsc_kyber_decrypt(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates a shared secret key using a public key.
 *
 * Generates ciphertext and a shared secret; used for key encapsulation.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_KYBER_SHAREDSECRET_SIZE).
 * \param ciphertext:	[uint8_t*] Pointer to the output ciphertext array (size QSC_KYBER_CIPHERTEXT_SIZE).
 * \param publickey:	[const uint8_t*] Pointer to the public key array (size QSC_KYBER_PUBLICKEY_SIZE).
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 */
QSC_EXPORT_API void qsc_kyber_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Encrypts to encapsulate a shared secret key using a public key.
 *
 * Generates ciphertext and a shared secret based on a public key and a given seed.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_KYBER_SHAREDSECRET_SIZE).
 * \param ciphertext:	[uint8_t*] Pointer to the output ciphertext array (size QSC_KYBER_CIPHERTEXT_SIZE).
 * \param publickey:	[const uint8_t*] Pointer to the public key array (size QSC_KYBER_PUBLICKEY_SIZE).
 * \param seed:			[const uint8_t[QSC_KYBER_SEED_SIZE]] Pointer to the random seed array.
 */
QSC_EXPORT_API void qsc_kyber_encrypt(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_KYBER_SEED_SIZE]);

/**
 * \brief Generates a Kyber public/private key pair.
 *
 * Produces a key pair for the Kyber key encapsulation mechanism.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public key array (size QSC_KYBER_PUBLICKEY_SIZE).
 * \param privatekey:	[uint8_t*] Pointer to the output private key array (size QSC_KYBER_PRIVATEKEY_SIZE).
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 */
QSC_EXPORT_API void qsc_kyber_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

#endif
