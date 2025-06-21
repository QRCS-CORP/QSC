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
