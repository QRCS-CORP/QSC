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

#ifndef QSC_POLY1305_H
#define QSC_POLY1305_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
* \file poly1305.h
* \brief Poly1305 function definitions \n
* Contains the public api and documentation for the Poly1305 implementation.
*
* Poly1305 Examples \n
* \code
*
* uint8_t key[QSC_POLY1305_KEY_SIZE];
* uint8_t mac[QSC_POLY1305_MAC_SIZE];
* uint8_t msg[34];
*
* // simplified
* qsc_poly1305_compute(mac, msg, 34, key);
*
* // long-form
* size_t i;
* qsc_poly1305_state ctx;
*
* qsc_poly1305_initialize(&ctx, key);
*
* for (i = 0; i < 32; i += QSC_POLY1305_BLOCK_SIZE)
* {
*	qsc_poly1305_blockupdate(&ctx, msg + i);
* }
*
* qsc_poly1305_update(&ctx, msg + i, 2);
* qsc_poly1305_finalize(&ctx, mac);
*
* \endcode
* \remarks
* For usage examples, see poly1305_test.h
*/

/*!
* \def QSC_POLY1305_BLOCK_SIZE
* \brief The natural block size of the message input in bytes
*/
#define QSC_POLY1305_BLOCK_SIZE 16

/*!
* \def QSC_POLY1305_KEY_SIZE
* \brief The Poly1305 key size in bytes
*/
#define QSC_POLY1305_KEY_SIZE 32

/*!
* \def QSC_POLY1305_MAC_SIZE
* \brief The Poly1305 MAC code size in bytes
*/
#define QSC_POLY1305_MAC_SIZE 16

/*! 
* \struct qsc_poly1305_state
* \brief Contains the Poly1305 internal state.
*/
QSC_EXPORT_API typedef struct qsc_poly1305_state
{
	uint32_t h[5U];							/*!< The h parameter */
	uint32_t k[4U];							/*!< The k parameter */
	uint32_t r[5U];							/*!< The r parameter */
	uint32_t s[4U];							/*!< The s parameter */
	uint8_t buf[QSC_POLY1305_BLOCK_SIZE];	/*!< The buffer parameter */
	size_t fnl;								/*!< The fnl size */
	size_t rmd;								/*!< The rmd size */
} qsc_poly1305_state;


/**
* \brief Update the poly1305 generator with a single block of message input.
* Absorbs block sized lengths of input message into the ctx.
*
* \warning Message length must be a single 16 byte message block. \n
*
* \param ctx: [struct] The function ctx; must be initialized
* \param message: [const] The input message byte array
*/
QSC_EXPORT_API void qsc_poly1305_blockupdate(qsc_poly1305_state* ctx, const uint8_t* message);

/**
* \brief Compute the MAC code and return the result in the mac byte array.
*
* \warning The output array must be at least 16 bytes in length.
*
* \param output: The output byte array; receives the MAC code
* \param message: [const] The message input byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The 32 byte key array
*/
QSC_EXPORT_API void qsc_poly1305_compute(uint8_t* output, const uint8_t* message, size_t msglen, const uint8_t* key);

/**
* \brief Dispose of the ctx resetting all values to zero.
*
* \param ctx: [struct] The function ctx
*/
QSC_EXPORT_API void qsc_poly1305_dispose(qsc_poly1305_state* ctx);

/**
* \brief Finalize the message ctx and returns the MAC code.
* Absorb the last block of message and create the MAC array. \n
*
* \param ctx: [struct] The function ctx; must be initialized
* \param mac: The MAC byte array; receives the MAC code
*/
QSC_EXPORT_API void qsc_poly1305_finalize(qsc_poly1305_state* ctx, uint8_t* mac);

/**
* \brief Initialize the ctx with the secret key.
*
* \param ctx: [struct] The function ctx
* \param key: [const] The secret key byte array
*/
QSC_EXPORT_API void qsc_poly1305_initialize(qsc_poly1305_state* ctx, const uint8_t key[QSC_POLY1305_KEY_SIZE]);

/**
* \brief Reset the ctx values to zero.
*
* \param ctx The function ctx
*/
QSC_EXPORT_API void qsc_poly1305_reset(qsc_poly1305_state* ctx);

/**
* \brief Update the poly1305 generator with a length of message input.
* Absorbs the input message into the ctx.
*
* \param ctx: [struct] The function ctx; must be initialized
* \param message: [const] The input message byte array
* \param msglen: The number of input message bytes to process
*/
QSC_EXPORT_API void qsc_poly1305_update(qsc_poly1305_state* ctx, const uint8_t* message, size_t msglen);

/**
* \brief Verify a MAC code.
* Tests the code against the message and returns MQC_STATUS_SUCCESS or MQC_STATUS_FAILURE.
*
* \param code: [const] The MAC code byte array
* \param message: [const] The message byte array
* \param msglen: The number of message bytes to process
* \param key: [const] The secret key byte array
* \return Returns success or failure
*/
QSC_EXPORT_API int32_t qsc_poly1305_verify(const uint8_t* code, const uint8_t* message, size_t msglen, const uint8_t* key);

QSC_CPLUSPLUS_ENABLED_END

#endif
