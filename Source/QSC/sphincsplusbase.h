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

#ifndef QSC_SPHINCSPLUSBASE2_H
#define QSC_SPHINCSPLUSBASE2_H

/* \cond */

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/* api.h */

/**
 * \brief Returns the length of a secret key, in bytes
 */
size_t sphincsplus_ref_sign_secretkeybytes(void);

/**
 * \brief Returns the length of a public key, in bytes
 */
size_t sphincsplus_ref_sign_publickeybytes(void);

/**
 * \brief Returns the length of a signature, in bytes
 */
size_t sphincsplus_ref_sign_bytes(void);

/**
 * \brief Returns the length of the seed required to generate a key pair, in bytes
 */
size_t sphincsplus_ref_sign_seedbytes(void);

/**
* \brief Generates a SphincsPlus public/private key-pair from a seed
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param seed: A pointer to the seed array
* \return Returns true for success
*/
bool sphincsplus_ref_generate_seeded_keypair(uint8_t* pk, uint8_t* sk, const uint8_t* seed);

/**
* \brief Generates a SphincsPlus public/private key-pair
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param rng_generate: A pointer to the random generator function
*/
bool sphincsplus_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message and context array as input and returns an array containing the signature followed by the message.
*
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param message: The message to be signed
* \param msglen: The message length
* \param context: [const] The context string
* \param ctxlen: The context length
* \param sk: The private signature key
* \param rng_generate: A pointer to the random generator function
* \return Returns true for success
*/
bool sphincsplus_ref_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* sk, const uint8_t* seed);

/**
* \brief Takes the message as input and returns an array containing the signature
*
* \param signedmsg: The signature
* \param smsglen: The signature length
* \param message: The message to be signed
* \param msglen: The message length
* \param context: [const] The context string
* \param ctxlen: The context length
* \param sk: The private signature key
* \param seed: A pointer to the random seed
* \return Returns true for success
*/
bool sphincsplus_ref_sign_signature(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* sk, const uint8_t* seed);

/**
* \brief Verifies a signature with the public key
*
* \param message: The message to be signed
* \param msglen: The message length
* \param context: [const] The context string
* \param ctxlen: The context length
* \param signedmsg: The signed message
* \param smsglen: The signed message length
* \param pk: The public verification key
* \return Returns true for success
*/
bool sphincsplus_ref_open(uint8_t* message, size_t* msglen, const uint8_t* context, size_t cxtlen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* pk);

/**
* \brief Verifies a signature-message pair with the public key
*
* \param signedmsg: The signature array
* \param smsglen: The length of the signature array
* \param message: The message array
* \param msglen: The length of the message array
* \param context: [const] The context string
* \param ctxlen: The context length
* \param pk: The public verification key
* \return Returns true for success
*/
bool sphincsplus_ref_verify(const uint8_t* signedmsg, size_t smsglen, const uint8_t* message, size_t msglen, const uint8_t* context, size_t ctxlen, const uint8_t* pk);

QSC_CPLUSPLUS_ENABLED_END

/* \endcond */

#endif
