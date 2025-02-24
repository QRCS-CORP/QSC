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

#ifndef QSC_DILITHIUMBASE_AVX2_H
#define QSC_DILITHIUMBASE_AVX2_H

/* \cond */

#include "common.h"

/**
* \brief Generates a Dilithium public/private key-pair.
* Arrays must be sized to DILITHIUM_PUBLICKEY_SIZE and DILITHIUM_SECRETKEY_SIZE.
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_avx2_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature
*
* \param sig: The signed message
* \param siglen: The signed message length
* \param m: [const] The message to be signed
* \param mlen: The message length
* \param context: [const] The context string
* \param contextlen: The context length
* \param sk: [const] The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_avx2_sign_signature(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message
*
* \param sm: The signed message
* \param smlen: The signed message length
* \param m: [const] The message to be signed
* \param mlen: The message length
* \param sk: [const] The private signature key
* \param rng_generate: The random generator
*/
void qsc_dilithium_avx2_sign(uint8_t* sm, size_t* smlen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param sig: [const] The message to be signed
* \param siglen: The message length
* \param m: [const] The signed message
* \param mlen: The signed message length
* \param context: [const] The context string
* \param contextlen: The context length
* \param pk: [const] The public verification key
* \return Returns true for success
*/
bool qsc_dilithium_avx2_verify(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* context, size_t contextlen, const uint8_t* pk);

/**
* \brief Verifies a signature-message pair with the public key.
*
* \param m: The message to be signed
* \param mlen: The message length
* \param sm: [const] The signed message
* \param smlen: The signed message length
* \param context: [const] The context string
* \param contextlen: The context length
* \param pk: [const] The public verification key
* \return Returns true for success
*/
bool qsc_dilithium_avx2_open(uint8_t* m, size_t* mlen, const uint8_t* sm, size_t smlen, const uint8_t* context, size_t contextlen, const uint8_t* pk);

/* \endcond */

#endif
