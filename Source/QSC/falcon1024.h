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
#ifndef QSC_FALCON1024_H
#define QSC_FALCON1024_H

/**
* \file falcon1024.h
* \brief Independent legacy Falcon-1024 signature interface.
*
* \details The signature format is the legacy Falcon signed-message format,
* not a claim of FN-DSA/FIPS 206 conformity. Arrays must be sized according
* to the constants below. The algorithm uses randomized signing.
*/

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/** \def QSC_FALCON1024_PRIVATEKEY_SIZE 
* \brief Size in bytes of a Falcon-1024 secret key. 
*/
#define QSC_FALCON1024_PRIVATEKEY_SIZE 2305U

/** \def QSC_FALCON1024_PUBLICKEY_SIZE 
* \brief Size in bytes of a Falcon-1024 public key. 
*/
#define QSC_FALCON1024_PUBLICKEY_SIZE 1793U

/** \def QSC_FALCON1024_SIGNATURE_SIZE 
* \brief Maximum Falcon signed-message overhead (includes nonce and framing), in bytes. 
*/
#define QSC_FALCON1024_SIGNATURE_SIZE 1280U

/** \def QSC_FALCON1024_ALGNAME 
* \brief Legacy Falcon-1024 identifier. 
*/
#define QSC_FALCON1024_ALGNAME "FALCON-1024"

/**
* \brief Generate a randomized Falcon-1024 keypair.
* \param publickey Output array of QSC_FALCON1024_PUBLICKEY_SIZE bytes.
* \param privatekey Output array of QSC_FALCON1024_PRIVATEKEY_SIZE bytes.
* \param rng_generate Non-NULL RNG callback; returns false on failure.
* \return True on success; false on invalid arguments or backend failure.
* \note The caller owns all buffers. No global mutable state is used.
*/
QSC_EXPORT_API bool qsc_falcon1024_generate_keypair(uint8_t* publickey, uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Create a legacy Falcon-1024 signed message.
* \param signedmsg Caller-allocated output of at least msglen + QSC_FALCON1024_SIGNATURE_SIZE bytes.
* \param smsglen Output actual signed-message length in bytes; reset to zero on failure.
* \param message Non-NULL input message buffer containing msglen bytes.
* \param msglen Message length in bytes; the addition of overhead must not overflow size_t.
* \param privatekey Input array of QSC_FALCON1024_PRIVATEKEY_SIZE bytes.
* \param rng_generate Non-NULL RNG callback used for nonce and signing randomness.
* \return True on success; false on malformed key, RNG failure or invalid arguments.
* \note The caller owns the buffers; no global mutable state is used.
*/
QSC_EXPORT_API bool qsc_falcon1024_sign(uint8_t* signedmsg, size_t* smsglen, const uint8_t* message, size_t msglen, const uint8_t* privatekey, bool (*rng_generate)(uint8_t*, size_t));

/**
* \brief Verify and recover a message from a Falcon-1024 signed message.
* \param message Caller-allocated output buffer of at least smsglen bytes.
* \param msglen Output recovered length in bytes; reset to zero on failure.
* \param signedmsg Input signed message of smsglen bytes.
* \param smsglen Input signed-message length.
* \param publickey Input array of QSC_FALCON1024_PUBLICKEY_SIZE bytes.
* \return True on successful verification; false for malformed or invalid signatures.
* \note Message data is only copied on success; no global mutable state is used.
*/
QSC_EXPORT_API bool qsc_falcon1024_verify(uint8_t* message, size_t* msglen, const uint8_t* signedmsg, size_t smsglen, const uint8_t* publickey);

QSC_CPLUSPLUS_ENABLED_END

#endif
