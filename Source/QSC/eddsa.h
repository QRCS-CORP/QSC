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

#ifndef QSC_EDDSA_H
#define QSC_EDDSA_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file ecdsa.h
 * \brief Contains the primary public API for the Edwards Curve EDDSA asymmetric signature scheme implementation.
 *
 * \details
 * This header defines the API for the EDDSA (Elliptic Curve Digital Signature Algorithm) asymmetric signature scheme,
 * operating over the Ed25519 elliptic curve. It provides functions for generating key pairs (either randomly or via a seeded generator),
 * signing messages, and verifying signatures.
 *
 * \par Example:
 * \code
 * // An example of key-pair creation, signing, and verification using EDDSA
 * #define MSGLEN 32
 * uint8_t pk[QSC_EDDSA_PUBLICKEY_SIZE];
 * uint8_t sk[QSC_EDDSA_SECRETKEY_SIZE];
 * uint8_t msg[32];
 * uint8_t smsg[QSC_EDDSA_SIGNATURE_SIZE + MSGLEN];
 * uint8_t rmsg[32];
 *
 * uint32_t rmsglen = 0;
 * uint32_t smsglen = 0;
 *
 * // Create the public and secret keys using a seeded generator
 * qsc_eddsa_generate_seeded_keypair(pk, sk, random_seed);
 * // Sign the message; the signature is prepended to the message
 * qsc_eddsa_sign(smsg, &smsglen, msg, MSGLEN, sk);
 * // Verify the signature and retrieve the message bytes
 * if (qsc_eddsa_verify(rmsg, &rmsglen, smsg, smsglen, pk) != true)
 * {
 *     // Authentication failed; handle error.
 * }
 * \endcode
 *
 * \remarks
 * This EDDSA implementation utilizes the Ed25519 elliptic curve along with its underlying field arithmetic over the prime field defined by 2^255 - 19.
 * It supports standard digital signature operations including key pair generation, signing, and verification.
 * The design emphasizes constant-time execution to mitigate timing attacks and is suitable for secure applications in modern cryptographic protocols.
 *
 * \section ecdsa_links Reference Links
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Official Ed25519 Documentation</a>
 *  - <a href="https://cr.yp.to/ecdh.html">Curve25519 ECDH Specification</a>
 *  - <a href="https://ed25519.cr.yp.to/ed25519-20110926.pdf">Ed25519 Field Arithmetic Details</a>
 */

#if defined(QSC_EDDSA_S1EC25519)

    /*!
    * \def QSC_EDDSA_SIGNATURE_SIZE
    * \brief The byte size of the signature array
    */
#	define QSC_EDDSA_SIGNATURE_SIZE 64U

    /*!
    * \def QSC_EDDSA_PRIVATEKEY_SIZE
    * \brief The byte size of the secret private-key array
    */
#	define QSC_EDDSA_PRIVATEKEY_SIZE 64U

    /*!
    * \def QSC_EDDSA_PUBLICKEY_SIZE
    * \brief The byte size of the public-key array
    */
#	define QSC_EDDSA_PUBLICKEY_SIZE 32U

    /*!
    * \def QSC_EDDSA_SEED_SIZE
    * \brief The byte size of the random seed array
    */
#   define QSC_EDDSA_SEED_SIZE 32U

    /*!
    * \def QSC_EDDSA_ALGNAME
    * \brief The formal algorithm name
    */
#   define QSC_EDDSA_ALGNAME "EDDSA25519"

#elif defined(QSC_EDDH_S3EC448)

    /*!
     * \def QSC_EDDSA_SIGNATURE_SIZE
     * \brief The Ed448 signature size in bytes (R || S).
     */
#   define QSC_EDDSA_SIGNATURE_SIZE  114U

    /*!
     * \def QSC_EDDSA_PRIVATEKEY_SIZE
     * \brief The Ed448 private-key size in bytes (seed || public key).
     */
#   define QSC_EDDSA_PRIVATEKEY_SIZE 114U

    /*!
     * \def QSC_EDDSA_PUBLICKEY_SIZE
     * \brief The Ed448 public-key size in bytes.
     */
#   define QSC_EDDSA_PUBLICKEY_SIZE  57U

     /*!
     * \def QSC_EDDSA_SEED_SIZE
     * \brief The byte size of the random seed array
     */
#   define QSC_EDDSA_SEED_SIZE 57ULL

     /*!
     * \def QSC_EDDSA_ALGNAME
     * \brief The formal algorithm name
     */
#   define QSC_EDDSA_ALGNAME "EDDSA448"

#else
#   error "No EDDSA parameter set defined. Define QSC_EDDSA_S1EC25519 or QSC_EDDSA_S3EC448."
#endif

/**
* \brief Generates a EDDSA public/private key-pair.
*
* \warning Arrays must be sized to QSC_EDDSA_PUBLICKEY_SIZE and QSC_EDDSA_SECRETKEY_SIZE.
*
* \param publickey: [uint8_t*] Pointer to the public verification-key array
* \param privatekey: [uint8_t*] Pointer to the private signature-key array
* \param rng_generate: [uint8_t*, size_t] Pointer to the random generator
*/
QSC_EXPORT_API void qsc_eddsa_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates a EDDSA public/private key-pair.
*
* \warning Arrays must be sized to QSC_EDDSA_PUBLICKEY_SIZE and QSC_EDDSA_SECRETKEY_SIZE.
*
* \param publickey:	[uint8_t*] Pointer to the public verification-key array
* \param privatekey: [uint8_t*] Pointer to the private signature-key array
* \param seed: [const uint8_t*] Pointer to the random 32-byte seed array
*/
QSC_EXPORT_API void qsc_eddsa_generate_seeded_keypair(uint8_t* publickey, uint8_t* privatekey, const uint8_t* seed);

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \warning Signature array must be sized to the size of the message plus QSC_EDDSA_SIGNATURE_SIZE.
*
* \param signedmsg:	[uint8_t*] Pointer to the signed-message array
* \param smsglen: [size_t*] Pointer to the signed message length
* \param message: [const uint8_t*] Pointer to the message array
* \param msglen: [size_t] The message length
* \param privatekey: [const uint8_t*] Pointer to the private signature-key array
*/
QSC_EXPORT_API void qsc_eddsa_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param message: [uint8_t*] Pointer to the message array to be signed
* \param msglen: [size_t*]Pointer to the message length
* \param signedmsg:	[const uint8_t*] Pointer to the signed message array
* \param smsglen: [size_t] The signed message length
* \param publickey:	[const uint8_t*] Pointer to the public verification-key array
* 
* \return [bool] Returns true for success
*/
QSC_EXPORT_API bool qsc_eddsa_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
