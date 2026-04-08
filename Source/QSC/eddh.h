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

#ifndef QSC_EDDH_H
#define QSC_EDDH_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file eddh.h
 * \brief Contains the primary public API for the Edwards Elliptic Curve Diffie-Hellman key exchange.
 *
 * \details
 * This header defines the API for the EDDH key encapsulation mechanism using the Curve25519/Ed25519 elliptic curve.
 * It provides functions for generating key pairs (either randomly or seeded) and for performing the key exchange operation
 * (decapsulation) to derive a shared secret.
 *
 * The implementation is based on established protocols for elliptic curve cryptography and leverages the underlying field
 * arithmetic and curve operations of the Ed25519 signature scheme. It is designed for secure key encapsulation in cryptographic
 * protocols and has been optimized for performance and constant-time execution to mitigate side-channel attacks.
 *
 * \par Example:
 * \code
 * // An example of key-pair creation and shared secret derivation using EDDH
 * uint8_t pk[QSC_EDDH_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_EDDH_PRIVATEKEY_SIZE];
 * uint8_t sec[QSC_EDDH_SHAREDSECRET_SIZE];
 *
 * // Generate the key pair using a seeded generator
 * qsc_eddh_generate_seeded_keypair(pk, sk, random_seed);
 *
 * // Derive the shared secret using the private key and an external public key
 * if (qsc_eddh_key_exchange(sec, sk, external_public_key) == false)
 * {
 *     // Key exchange failed; handle error...
 * }
 * \endcode
 *
 * \remarks
 * This EDDH implementation uses the Curve25519/Ed25519 elliptic curve for performing key exchange operations.
 * It is intended for secure key encapsulation and is suitable for cryptographic protocols requiring robust,
 * constant-time elliptic curve operations.
 *
 * \section ecdh_links Reference Links:
 *  - <a href="https://github.com/jedisct1/libsodium/tree/master">Adapted from libsodium source by Frank Denis</a>
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Official ECurve25519 EDDH Specificationd25519 Documentation</a>
 *  - <a href="https://cr.yp.to/ecdh.html"></a>
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Ed25519 Field Operations</a>
 */

#if defined(QSC_EDDH_S1EC25519)
    /*!
    * \def QSC_EDDH_PUBLICKEY_SIZE
    * \brief The EDDH public-key size in bytes.
    */
#   define QSC_EDDH_PUBLICKEY_SIZE 32U

    /*!
     * \def QSC_EDDH_PRIVATEKEY_SIZE
     * \brief The EDDH private-key size in bytes.
     */
#   define QSC_EDDH_PRIVATEKEY_SIZE 32U

    /*!
     * \def QSC_EDDH_SECRET_SIZE
     * \brief The EDDH shared-secret size in bytes.
     */
#   define QSC_EDDH_SHAREDSECRET_SIZE 32U

     /*!
      * \def QSC_EDDH_SEED_SIZE
      * \brief The byte size of the seed array.
      */
#   define QSC_EDDH_SEED_SIZE 32U

     /*!
      * \def QSC_EDDH_ALGNAME
      * \brief The formal algorithm name.
      */
#   define QSC_EDDH_ALGNAME "EDDH25519"

#elif defined(QSC_EDDH_S3EC448)

    /*!
     * \def QSC_EDDH_PUBLICKEY_SIZE
     * \brief The X448 public-key size in bytes.
     */
#   define QSC_EDDH_PUBLICKEY_SIZE 56U

    /*!
     * \def QSC_EDDH_PRIVATEKEY_SIZE
     * \brief The X448 private-key size in bytes.
     */
#   define QSC_EDDH_PRIVATEKEY_SIZE 56U

    /*!
     * \def QSC_EDDH_SECRET_SIZE
     * \brief The X448 shared-secret size in bytes.
     */
#   define QSC_EDDH_SHAREDSECRET_SIZE 56U

     /*!
      * \def QSC_EDDH_SEED_SIZE
      * \brief The byte size of the seed array.
      */
#   define QSC_EDDH_SEED_SIZE 56U

      /*!
      * \def QSC_EDDH_ALGNAME
      * \brief The formal algorithm name.
      */
#   define QSC_EDDH_ALGNAME "EDDH448"

#else
#   error "No EDDH parameter set defined. Define QSC_EDDH_S1EC25519 or QSC_EDDH_S3EC448."
#endif

/**
 * \brief Derives an X25519 public key from an existing private key.
 *
 * The private key is interpreted as 32 raw bytes. Scalar clamping is applied
 * internally during public key derivation, as specified by RFC 7748.
 *
 * This function is intended for use when importing or reconstructing keys from
 * external representations such as PKCS#8 or application-defined storage.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and
 * QSC_EDDH_PRIVATEKEY_SIZE.
 *
 * \param publickey:  [uint8_t*] Pointer to the output public-key array.
 * \param privatekey:[const uint8_t*] Pointer to the input private-key array.
 */
QSC_EXPORT_API void qsc_eddh_public_from_private(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Generates public and private keys for the EDDH key encapsulation mechanism.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_PRIVATEKEY_SIZE.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public-key array.
 * \param privatekey:	[uint8_t*] Pointer to the output private-key array.
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to the random generator function.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_eddh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates public and private keys for the EDDH key encapsulation mechanism using a seed.
 *
 * \warning Arrays must be sized to QSC_EDDH_PUBLICKEY_SIZE and QSC_EDDH_PRIVATEKEY_SIZE.
 *
 * \param publickey:	[uint8_t*] Pointer to the output public-key array.
 * \param privatekey:	[uint8_t*] Pointer to the output private-key array.
 * \param seed:			[const uint8_t*] Pointer to the random seed.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_eddh_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Decapsulates the shared secret for a given cipher-text using a private-key.
 *
 * \warning The shared secret array must be sized to QSC_EDDH_SHAREDSECRET_SIZE.
 *
 * \param secret:		[uint8_t*] Pointer to the shared secret key array.
 * \param privatekey:	[const uint8_t*] Pointer to the private-key array.
 * \param publickey:	[const uint8_t*] Pointer to the public-key array.
 * \return				[bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_eddh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
