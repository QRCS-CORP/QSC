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

#ifndef QSC_MCELIECE_H
#define QSC_MCELIECE_H

#include "common.h"

QSC_CPLUSPLUS_ENABLED_START

// TODO: malloc large arrays and translate GAS to MASM and implement

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

/* Parameter definitions for different McEliece parameter sets */
#if defined(QSC_MCELIECE_S1N3488T64)

/*!
 * \def QSC_MCELIECE_CIPHERTEXT_SIZE
 * \brief The byte size of the ciphertext array.
 */
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 128

/*!
 * \def QSC_MCELIECE_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 6492

/*!
 * \def QSC_MCELIECE_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#	define QSC_MCELIECE_PUBLICKEY_SIZE 261120

#elif defined(QSC_MCELIECE_S3N4608T96)

/*!
 * \def QSC_MCELIECE_CIPHERTEXT_SIZE
 * \brief The byte size of the ciphertext array.
 */
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 188

/*!
 * \def QSC_MCELIECE_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 13608

/*!
 * \def QSC_MCELIECE_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#	define QSC_MCELIECE_PUBLICKEY_SIZE 524160

#elif defined(QSC_MCELIECE_S5N6688T128)

/*!
 * \def QSC_MCELIECE_CIPHERTEXT_SIZE
 * \brief The byte size of the ciphertext array.
 */
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 240

/*!
 * \def QSC_MCELIECE_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 13932

/*!
 * \def QSC_MCELIECE_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#	define QSC_MCELIECE_PUBLICKEY_SIZE 1044992

#elif defined(QSC_MCELIECE_S6N6960T119)

/*!
 * \def QSC_MCELIECE_CIPHERTEXT_SIZE
 * \brief The byte size of the ciphertext array.
 */
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 226

/*!
 * \def QSC_MCELIECE_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 13948

/*!
 * \def QSC_MCELIECE_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#	define QSC_MCELIECE_PUBLICKEY_SIZE 1047319

#elif defined(QSC_MCELIECE_S7N8192T128)

/*!
 * \def QSC_MCELIECE_CIPHERTEXT_SIZE
 * \brief The byte size of the ciphertext array.
 */
#	define QSC_MCELIECE_CIPHERTEXT_SIZE 240 

/*!
 * \def QSC_MCELIECE_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#	define QSC_MCELIECE_PRIVATEKEY_SIZE 14120

/*!
 * \def QSC_MCELIECE_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#	define QSC_MCELIECE_PUBLICKEY_SIZE 1357824

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

/*!
 * \def QSC_MCELIECE_ALGNAME
 * \brief The formal algorithm name.
 */
#define QSC_MCELIECE_ALGNAME "MCELIECE"

/**
 * \brief Decapsulates the shared secret for a given ciphertext using a private key.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_MCELIECE_SHAREDSECRET_SIZE).
 * \param ciphertext:	[const uint8_t*] Pointer to the ciphertext array (size QSC_MCELIECE_CIPHERTEXT_SIZE).
 * \param privatekey:	[const uint8_t*] Pointer to the private key array (size QSC_MCELIECE_PRIVATEKEY_SIZE).
 * \return				[bool] Returns true if decapsulation succeeds.
 */
QSC_EXPORT_API bool qsc_mceliece_decapsulate(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Decrypts the shared secret for a given ciphertext using a private key.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_MCELIECE_SHAREDSECRET_SIZE).
 * \param ciphertext:	[const uint8_t*] Pointer to the ciphertext array (size QSC_MCELIECE_CIPHERTEXT_SIZE).
 * \param privatekey:	[const uint8_t*] Pointer to the private key array (size QSC_MCELIECE_PRIVATEKEY_SIZE).
 * \return				[bool] Returns true if decryption succeeds.
 */
QSC_EXPORT_API bool qsc_mceliece_decrypt(uint8_t* secret, const uint8_t* ciphertext, const uint8_t* privatekey);

/**
 * \brief Encapsulates a shared secret key using a public key.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_MCELIECE_SHAREDSECRET_SIZE).
 * \param ciphertext:	[uint8_t*] Pointer to the output ciphertext array (size QSC_MCELIECE_CIPHERTEXT_SIZE).
 * \param publickey:	[const uint8_t*] Pointer to the public key array (size QSC_MCELIECE_PUBLICKEY_SIZE).
 * \param rng_generate:	[bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 */
QSC_EXPORT_API void qsc_mceliece_encapsulate(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Encrypts to encapsulate a shared secret key using a public key.
 *
 * \param secret:		[uint8_t*] Pointer to the output shared secret key (array of QSC_MCELIECE_SHAREDSECRET_SIZE).
 * \param ciphertext:	[uint8_t*] Pointer to the output ciphertext array (size QSC_MCELIECE_CIPHERTEXT_SIZE).
 * \param publickey:	[const uint8_t*] Pointer to the public key array (size QSC_MCELIECE_PUBLICKEY_SIZE).
 * \param seed:			[const uint8_t[QSC_MCELIECE_SEED_SIZE]] Pointer to the random seed array.
 */
QSC_EXPORT_API void qsc_mceliece_encrypt(uint8_t* secret, uint8_t* ciphertext, const uint8_t* publickey, const uint8_t seed[QSC_MCELIECE_SEED_SIZE]);

/**
 * \brief Generates a McEliece public/private key pair.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public key array (size QSC_MCELIECE_PUBLICKEY_SIZE).
 * \param privatekey:	[uint8_t*] Pointer to the output private key array (size QSC_MCELIECE_PRIVATEKEY_SIZE).
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to a random generator function.
 */
QSC_EXPORT_API void qsc_mceliece_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

QSC_CPLUSPLUS_ENABLED_END

#endif
