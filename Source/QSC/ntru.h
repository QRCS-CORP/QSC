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

#ifndef QSC_NTRU_H
#define QSC_NTRU_H

#include "common.h"
#include "ntrubase.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file ntru.h
 * \brief Contains the public API for the NTRU CCA-secure Key Encapsulation Mechanism implementation.
 *
 * \details
 * This header provides function declarations for generating key pairs, encapsulating and decapsulating 
 * shared secrets using the NTRU algorithm. Multiple parameter sets are supported and are selected at 
 * compile-time via definitions (e.g. QSC_NTRU_S1HPS2048509, QSC_NTRU_S3HPS2048677, etc.). The API is designed 
 * for secure post-quantum cryptographic applications.
 *
 * \section ntru_links Reference Links:
 * - <a href="https://ntru.org/f/ntru-20190330.pdf">Formal NTRU Specification</a>
 */

#if defined(QSC_NTRU_S1HPS2048509)

/*!
 * \def QSC_NTRU_CIPHERTEXT_SIZE
 * \brief The size of the ciphertext array.
 */
#	define QSC_NTRU_CIPHERTEXT_SIZE 699ULL

/*!
 * \def QSC_NTRU_PRIVATEKEY_SIZE
 * \brief The size of the secret private-key array.
 */
#	define QSC_NTRU_PRIVATEKEY_SIZE 6492ULL

/*!
 * \def QSC_NTRU_PUBLICKEY_SIZE
 * \brief The size of the public-key array.
 */
#	define QSC_NTRU_PUBLICKEY_SIZE 699ULL

#elif defined(QSC_NTRU_S3HPS2048677)

/*!
 * \def QSC_NTRU_CIPHERTEXT_SIZE
 * \brief The size of the ciphertext array.
 */
#	define QSC_NTRU_CIPHERTEXT_SIZE 930ULL

/*!
 * \def QSC_NTRU_PRIVATEKEY_SIZE
 * \brief The size of the secret private-key array.
 */
#	define QSC_NTRU_PRIVATEKEY_SIZE 1234ULL

/*!
 * \def QSC_NTRU_PUBLICKEY_SIZE
 * \brief The size of the public-key array.
 */
#	define QSC_NTRU_PUBLICKEY_SIZE 930ULL

#elif defined(QSC_NTRU_S5HPS4096821)

/*!
 * \def QSC_NTRU_CIPHERTEXT_SIZE
 * \brief The size of the ciphertext array.
 */
#	define QSC_NTRU_CIPHERTEXT_SIZE 1230ULL

/*!
 * \def QSC_NTRU_PRIVATEKEY_SIZE
 * \brief The size of the secret private-key array.
 */
#	define QSC_NTRU_PRIVATEKEY_SIZE 1590ULL

/*!
 * \def QSC_NTRU_PUBLICKEY_SIZE
 * \brief The size of the public-key array.
 */
#	define QSC_NTRU_PUBLICKEY_SIZE 1230ULL

#elif defined(QSC_NTRU_S5HRSS701)

/*!
 * \def QSC_NTRU_CIPHERTEXT_SIZE
 * \brief The size of the ciphertext array.
 */
#	define QSC_NTRU_CIPHERTEXT_SIZE 1138ULL

/*!
 * \def QSC_NTRU_PRIVATEKEY_SIZE
 * \brief The size of the secret private-key array.
 */
#	define QSC_NTRU_PRIVATEKEY_SIZE 1450ULL

/*!
 * \def QSC_NTRU_PUBLICKEY_SIZE
 * \brief The size of the public-key array.
 */
#	define QSC_NTRU_PUBLICKEY_SIZE 1138ULL

#else
#	error "The NTRU parameter set is invalid!"
#endif

/*!
 * \def QSC_NTRU_SEED_SIZE
 * \brief The size of the seed array.
 */
#define QSC_NTRU_SEED_SIZE 32ULL

/*!
 * \def QSC_NTRU_SHAREDSECRET_SIZE
 * \brief The size of the shared secret-key array.
 */
#define QSC_NTRU_SHAREDSECRET_SIZE 32ULL

/*!
 * \def QSC_NTRU_ALGNAME
 * \brief The formal algorithm name.
 */
#define QSC_NTRU_ALGNAME "NTRU"

/**
 * \brief Decapsulates the shared secret using a private-key.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (size: QSC_NTRU_SHAREDSECRET_SIZE).
 * \param ciphertext:	[const uint8_t*] Pointer to the ciphertext array (size: QSC_NTRU_CIPHERTEXT_SIZE).
 * \param privatekey:	[const uint8_t*] Pointer to the secret-key array (size: QSC_NTRU_PRIVATEKEY_SIZE).
 *
 * \return [bool] Returns true if decapsulation is successful.
 */
QSC_EXPORT_API bool qsc_ntru_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Decrypts the shared secret using a private-key.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (size: QSC_KYBER_SHAREDSECRET_SIZE).
 * \param ciphertext:	[const uint8_t*] Pointer to the ciphertext array (size: QSC_KYBER_CIPHERTEXT_SIZE).
 * \param privatekey:	[const uint8_t*] Pointer to the secret-key array (size: QSC_KYBER_PRIVATEKEY_SIZE).
 *
 * \return				[bool] Returns true if decryption is successful.
 */
QSC_EXPORT_API bool qsc_ntru_decrypt(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates a shared secret using a public-key.
 *
 * \warning The ciphertext array must be sized to QSC_NTRU_CIPHERTEXT_SIZE.
 *
 * \param secret:		[uint8_t*] Pointer to the shared secret key (size: QSC_NTRU_SHAREDSECRET_SIZE).
 * \param ciphertext:	[uint8_t*] Pointer to the ciphertext array (size: QSC_NTRU_CIPHERTEXT_SIZE).
 * \param publickey:	[const uint8_t*] Pointer to the public-key array (size: QSC_NTRU_PUBLICKEY_SIZE).
 * \param rng_generate:	[function pointer] Pointer to the random generator function.
 */
QSC_EXPORT_API void qsc_ntru_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Encrypts and encapsulates a shared secret using a public-key.
 *
 * \warning The ciphertext array must be sized to QSC_KYBER_CIPHERTEXT_SIZE.
 *
 * \param secret:		[uint8_t*] Pointer to the shared secret key (size: QSC_KYBER_SHAREDSECRET_SIZE).
 * \param ciphertext:	[uint8_t*] Pointer to the ciphertext array (size: QSC_KYBER_CIPHERTEXT_SIZE).
 * \param publickey:	[const uint8_t*] Pointer to the public-key array (size: QSC_KYBER_PUBLICKEY_SIZE).
 * \param seed:			[const uint8_t[QSC_NTRU_SEED_SIZE]] Pointer to the random seed array.
 */
QSC_EXPORT_API void qsc_ntru_encrypt(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_NTRU_SEED_SIZE]);

/**
 * \brief Generates a public/private key pair for NTRU.
 *
 * \warning Arrays must be sized to QSC_NTRU_PUBLICKEY_SIZE and QSC_NTRU_PRIVATEKEY_SIZE.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public-key array (size: QSC_NTRU_PUBLICKEY_SIZE).
 * \param privatekey:	[uint8_t*] Pointer to the output private-key array (size: QSC_NTRU_PRIVATEKEY_SIZE).
 * \param rng_generate:	[function pointer] Pointer to the random generator function.
 */
QSC_EXPORT_API void qsc_ntru_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

QSC_CPLUSPLUS_ENABLED_END

#endif
