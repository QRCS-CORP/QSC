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

#ifndef QSC_ECDH_H
#define QSC_ECDH_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file ecdh.h
 * \brief Contains the primary public API for Elliptic Curve Diffie-Hellman (ECDH) using NIST prime curves.
 *
 * \details
 * This header defines the API for the Elliptic Curve Diffie-Hellman (ECDH) key agreement mechanism
 * over the NIST prime field curves P-256, P-384, and P-521. The implementation supports generation
 * of elliptic curve key pairs (random or seeded) and computation of a shared secret using a peer's
 * public key.
 *
 * The construction follows the ECDH primitive defined in NIST SP 800-56A and is compatible with
 * the domain parameters specified in FIPS 186-4 / FIPS 186-5. The implementation reuses the
 * underlying field arithmetic and point operations provided by the corresponding NIST ECDSA
 * implementations (P-256, P-384, P-521).
 *
 * Scalar multiplication is performed in constant time to mitigate timing and side-channel attacks.
 * Public key validation and coordinate checks are expected to conform to the requirements defined
 * in NIST SP 800-56A.
 *
 * \par Supported Curves:
 * - NIST P-256 (secp256r1)
 * - NIST P-384 (secp384r1)
 * - NIST P-521 (secp521r1)
 *
 * \par Example:
 * \code
 * // Example: ECDH key pair generation and shared secret derivation
 * uint8_t pk[QSC_ECDH_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_ECDH_PRIVATEKEY_SIZE];
 * uint8_t sec[QSC_ECDH_SHAREDSECRET_SIZE];
 *
 * // Generate a key pair using a seeded generator
 * qsc_ecdh_generate_seeded_keypair(pk, sk, random_seed);
 *
 * // Derive a shared secret using the private key and a peer public key
 * if (qsc_ecdh_key_exchange(sec, sk, external_public_key) == false)
 * {
 *     // Key exchange failed; handle error
 * }
 * \endcode
 *
 * \remarks
 * This implementation performs standard ECDH as defined by NIST. The shared secret output is the raw x-coordinate
 * of the resulting elliptic curve point and should be processed through a key derivation function
 * (e.g., SHAKE, HKDF, or KMAC) before use in symmetric cryptographic contexts.
 *
 * \section ecdh_links Reference Links:
 *  - NIST SP 800-56A Rev. 3: https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final
 *  - FIPS 186-5 (Digital Signature Standard - DSS): https://csrc.nist.gov/publications/detail/fips/186/5/final
 *  - SEC 2: Recommended Elliptic Curve Domain Parameters: https://www.secg.org/sec2-v2.pdf
 *  - RFC 5480 (ECC SubjectPublicKeyInfo Format): https://datatracker.ietf.org/doc/html/rfc5480
 *  - RFC 8446 (TLS 1.3 - Supported Groups / ECDH usage): https://datatracker.ietf.org/doc/html/rfc8446
 */

#if defined(QSC_ECDH_S1P256)
    /*!
    * \def QSC_ECDH_PUBLICKEY_SIZE
    * \brief The ECDH public-key size in bytes.
    */
#   define QSC_ECDH_PUBLICKEY_SIZE 64U

    /*!
    * \def QSC_ECDH_PRIVATEKEY_SIZE
    * \brief The ECDH private-key size in bytes.
    */
#   define QSC_ECDH_PRIVATEKEY_SIZE 32U

    /*!
    * \def QSC_ECDH_SECRET_SIZE
    * \brief The ECDH shared-secret size in bytes.
    */
#   define QSC_ECDH_SHAREDSECRET_SIZE 32U

    /*!
    * \def QSC_ECDH_SEED_SIZE
    * \brief The byte size of the seed array.
    */
#   define QSC_ECDH_SEED_SIZE 32U

    /*!
     * \def QSC_ECDH_ALGNAME
     * \brief The formal algorithm name.
     */
#   define QSC_ECDH_ALGNAME "ECDH-P256"

#elif defined(QSC_ECDH_S3P384)

   /*!
    * \def QSC_ECDH_PUBLICKEY_SIZE
    * \brief The public-key size in bytes.
    */
#   define QSC_ECDH_PUBLICKEY_SIZE 96U

   /*!
    * \def QSC_ECDH_PRIVATEKEY_SIZE
    * \brief The private-key size in bytes.
    */
#   define QSC_ECDH_PRIVATEKEY_SIZE 48U

   /*!
    * \def QSC_ECDH_SECRET_SIZE
    * \brief The shared-secret size in bytes.
    */
#   define QSC_ECDH_SHAREDSECRET_SIZE 48U

   /*!
    * \def QSC_ECDH_SEED_SIZE
    * \brief The byte size of the seed array.
    */
#   define QSC_ECDH_SEED_SIZE 48U

   /*!
    * \def QSC_ECDH_ALGNAME
    * \brief The formal algorithm name.
    */
#   define QSC_ECDH_ALGNAME "ECDH-P384"

#elif defined(QSC_ECDH_S5P521)

   /*!
    * \def QSC_ECDH_PUBLICKEY_SIZE
    * \brief The public-key size in bytes.
    */
#   define QSC_ECDH_PUBLICKEY_SIZE 132U

   /*!
    * \def QSC_ECDH_PRIVATEKEY_SIZE
    * \brief The private-key size in bytes.
    */
#   define QSC_ECDH_PRIVATEKEY_SIZE 66U

   /*!
    * \def QSC_ECDH_SECRET_SIZE
    * \brief The shared-secret size in bytes.
    */
#   define QSC_ECDH_SHAREDSECRET_SIZE 66U

   /*!
    * \def QSC_ECDH_SEED_SIZE
    * \brief The byte size of the seed array.
    */
#   define QSC_ECDH_SEED_SIZE 66U

   /*!
    * \def QSC_ECDH_ALGNAME
    * \brief The formal algorithm name.
    */
#   define QSC_ECDH_ALGNAME "ECDH-P521"

#else
#   error "No ECDH parameter set defined. Define QSC_ECDH_S1EC25519 or QSC_ECDH_S3EC448."
#endif

 /**
  * \brief Derives a public key from an existing private key.
  *
  * The private key is interpreted as 32 raw bytes. Scalar clamping is applied
  * internally during public key derivation, as specified by RFC 7748.
  *
  * This function is intended for use when importing or reconstructing keys from
  * external representations such as PKCS#8 or application-defined storage.
  *
  * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and
  * QSC_ECDH_PRIVATEKEY_SIZE.
  *
  * \param publickey: [uint8_t*] Pointer to the output public-key array.
  * \param privatekey: [const uint8_t*] Pointer to the input private-key array.
  */
QSC_EXPORT_API void qsc_ecdh_public_from_private(uint8_t* publickey, const uint8_t* privatekey);

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_PRIVATEKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param rng_generate: [bool (*)(uint8_t*, size_t)] Pointer to the random generator function.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdh_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
 * \brief Generates public and private keys for the ECDH key encapsulation mechanism using a seed.
 *
 * \warning Arrays must be sized to QSC_ECDH_PUBLICKEY_SIZE and QSC_ECDH_PRIVATEKEY_SIZE.
 *
 * \param publickey: [uint8_t*] Pointer to the output public-key array.
 * \param privatekey: [uint8_t*] Pointer to the output private-key array.
 * \param seed: [const uint8_t*] Pointer to the random seed.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdh_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
 * \brief Decapsulates the shared secret for a given cipher-text using a private-key.
 *
 * \warning The shared secret array must be sized to QSC_ECDH_SHAREDSECRET_SIZE.
 *
 * \param secret: [uint8_t*] Pointer to the shared secret key array.
 * \param privatekey: [const uint8_t*] Pointer to the private-key array.
 * \param publickey: [const uint8_t*] Pointer to the public-key array.
 * 
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_ecdh_key_exchange(uint8_t* secret, const uint8_t* privatekey, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
