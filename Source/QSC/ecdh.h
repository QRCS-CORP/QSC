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

#ifndef QSC_ECDH_H
#define QSC_ECDH_H

#include "common.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file ecdh.h
 * \brief Contains the primary public API for the Elliptic Curve Diffie-Hellman key exchange.
 *
 * \details
 * This header defines the API for the ECDH key encapsulation mechanism using the Curve25519/Ed25519 elliptic curve.
 * It provides functions for generating key pairs (either randomly or seeded) and for performing the key exchange operation
 * (decapsulation) to derive a shared secret.
 *
 * The implementation is based on established protocols for elliptic curve cryptography and leverages the underlying field
 * arithmetic and curve operations of the Ed25519 signature scheme. It is designed for secure key encapsulation in cryptographic
 * protocols and has been optimized for performance and constant-time execution to mitigate side-channel attacks.
 *
 * \par Example:
 * \code
 * // An example of key-pair creation and shared secret derivation using ECDH
 * uint8_t pk[QSC_ECDH_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_ECDH_PRIVATEKEY_SIZE];
 * uint8_t sec[QSC_ECDH_SHAREDSECRET_SIZE];
 *
 * // Generate the key pair using a seeded generator
 * qsc_ecdh_generate_seeded_keypair(pk, sk, random_seed);
 *
 * // Derive the shared secret using the private key and an external public key
 * if (qsc_ecdh_key_exchange(sec, sk, external_public_key) == false)
 * {
 *     // Key exchange failed; handle error...
 * }
 * \endcode
 *
 * \remarks
 * This ECDH implementation uses the Curve25519/Ed25519 elliptic curve for performing key exchange operations.
 * It is intended for secure key encapsulation and is suitable for cryptographic protocols requiring robust,
 * constant-time elliptic curve operations.
 *
 * \section ecdh_links Reference Links:
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Official ECurve25519 ECDH Specificationd25519 Documentation</a>
 *  - <a href="https://cr.yp.to/ecdh.html"></a>
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Ed25519 Field Operations</a>
 */

/*!
 * \def QSC_ECDH_PRIVATEKEY_SIZE
 * \brief The byte size of the secret private-key array.
 */
#define QSC_ECDH_PRIVATEKEY_SIZE 32ULL

/*!
 * \def QSC_ECDH_PUBLICKEY_SIZE
 * \brief The byte size of the public-key array.
 */
#define QSC_ECDH_PUBLICKEY_SIZE 32ULL

/*!
 * \def QSC_ECDH_SHAREDSECRET_SIZE
 * \brief The byte size of the shared secret-key array.
 */
#define QSC_ECDH_SHAREDSECRET_SIZE 32ULL

/*!
 * \def QSC_ECDH_SEED_SIZE
 * \brief The byte size of the seed array.
 */
#define QSC_ECDH_SEED_SIZE 32ULL

/*!
 * \def QSC_ECDH_ALGNAME
 * \brief The formal algorithm name.
 */
#define QSC_ECDH_ALGNAME "ECDH"

/**
 * \brief Decapsulates the shared secret for a given cipher-text using a private-key.
 *
 * \warning The shared secret array must be sized to QSC_ECDH_SHAREDSECRET_SIZE.
 *
 * \param secret:		[uint8_t*] Pointer to the shared secret key array.
 * \param privatekey:	[const uint8_t*] Pointer to the private-key array.
 * \param publickey:	[const uint8_t*] Pointer to the public-key array.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey);

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_PRIVATEKEY_SIZE.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public-key array.
 * \param privatekey:	[uint8_t*] Pointer to the output private-key array.
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to the random generator function.
 */
QSC_EXPORT_API void qsc_ecdh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism using a seed.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_PRIVATEKEY_SIZE.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public-key array.
 * \param privatekey:	[uint8_t*] Pointer to the output private-key array.
 * \param seed:			[const uint8_t*] Pointer to the random seed.
 */
QSC_EXPORT_API void qsc_ecdh_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

QSC_CPLUSPLUS_ENABLED_END

#endif
