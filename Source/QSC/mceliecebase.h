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

#ifndef QSC_MCELIECEBASE_H
#define QSC_MCELIECEBASE_H

#include "qsccommon.h"

 /* \cond NO_DOCUMENT */

QSC_CPLUSPLUS_ENABLED_START

/* operations.h */

/**
* \brief Decapsulates the shared secret for a given cipher-text using a private-key
*
* \param key: [uint8_t*] Pointer to a shared secret key, an array of QSC_MCELIECE_SHAREDSECRET_SIZE constant size
* \param c:	 [const uint8_t*] Pointer to the cipher-text array of QSC_MCELIECE_CIPHERTEXT_SIZE constant size
* \param sk: [const uint8_t*] Pointer to the secret-key array of QSC_MCELIECE_PRIVATEKEY_SIZE constant size
* \return [bool] Returns 0 for success
*/
bool qsc_mceliece_ref_decapsulate(uint8_t* key, const uint8_t* c, const uint8_t* sk);

/**
* \brief Generates cipher-text and encapsulates a shared secret key using a public-key
*
* \param c:	[uint8_t*] Pointer to the cipher-text array
* \param key: [uint8_t*] Pointer to a shared secret, a uint8_t array of QSC_MCELIECE_SHAREDSECRET_SIZE
* \param pk: [const uint8_t*] Pointer to the public-key array
* \param rng_generate: [(bool) uint8_t*, size_t] Pointer to the random generator
* \return [bool] Returns true for success
*/
bool qsc_mceliece_ref_encapsulate(uint8_t* c, uint8_t* key, const uint8_t* pk, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Generates public and private key for the McEliece key encapsulation mechanism
*
* \warning Arrays must be sized to QSC_QSC_MCELIECE_PUBLICKEY_SIZE and QSC_QSC_MCELIECE_SECRETKEY_SIZE.
*
* \param pk: [uint8_t*] Pointer to the output public-key array of QSC_MCELIECE_PUBLICKEY_SIZE constant size
* \param sk: [uint8_t*] Pointer to output private-key array of QSC_MCELIECE_PRIVATEKEY_SIZE constant size
* \param rng_generate: [(bool) uint8_t*, size_t] Pointer to the random generator function
* \return [bool] Returns true for success
*/
bool qsc_mceliece_ref_generate_keypair(uint8_t* pk, uint8_t* sk, bool (*rng_generate)(uint8_t*, size_t));

QSC_CPLUSPLUS_ENABLED_END

/* \cond NO_DOCUMENT */

#endif
