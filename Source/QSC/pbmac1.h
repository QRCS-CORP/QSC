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
 *   algorithms that are standardized or in the public domain, such as AES,
 *   SHA-2, SHA-3, HMAC, PBKDF2, and PBMAC1, which are not proprietary to QRCS.
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

#ifndef QSC_PBMAC1_H
#define QSC_PBMAC1_H

#include "qsccommon.h"
#include "sha2.h"

QSC_CPLUSPLUS_ENABLED_START

/*! 
 * \file pbmac1.h
 * \brief Password-Based Message Authentication Code 1 (PBMAC1) definitions.
 *
 * \details
 * This header defines a QSC implementation of PBMAC1 as specified by RFC 8018
 * and aligned with the PKCS #12 PBMAC1 profile defined by RFC 9879. PBMAC1
 * derives a MAC key from a password and salt using PBKDF2, then authenticates
 * the message using HMAC. This module implements the primitive computation and
 * verification layer; ASN.1 AlgorithmIdentifier encoding and PKCS #12 MacData
 * integration are handled by the PKCS #12 parser/writer layer.
 *
 * The implementation supports PBKDF2-HMAC-SHA2-256, PBKDF2-HMAC-SHA2-384, and
 * PBKDF2-HMAC-SHA2-512, with matching HMAC algorithms for the MAC step.
 *
 * \section pbmac1_links Reference Links:
 * - <a href="https://www.rfc-editor.org/rfc/rfc8018.html">RFC 8018: PKCS #5 Password-Based Cryptography Specification Version 2.1</a>
 * - <a href="https://www.rfc-editor.org/rfc/rfc9879.html">RFC 9879: Use of PBMAC1 in PKCS #12 Syntax</a>
 */

/*! 
 * \def QSC_PBMAC1_256_MAC_SIZE
 * \brief The PBMAC1-HMAC-SHA2-256 MAC size in bytes.
 */
#define QSC_PBMAC1_256_MAC_SIZE 32ULL

/*! 
 * \def QSC_PBMAC1_384_MAC_SIZE
 * \brief The PBMAC1-HMAC-SHA2-384 MAC size in bytes.
 */
#define QSC_PBMAC1_384_MAC_SIZE 48ULL

/*! 
 * \def QSC_PBMAC1_512_MAC_SIZE
 * \brief The PBMAC1-HMAC-SHA2-512 MAC size in bytes.
 */
#define QSC_PBMAC1_512_MAC_SIZE 64ULL

/*! 
 * \def QSC_PBMAC1_MAX_MAC_SIZE
 * \brief The maximum PBMAC1 MAC size in bytes.
 */
#define QSC_PBMAC1_MAX_MAC_SIZE QSC_PBMAC1_512_MAC_SIZE

/*! 
 * \def QSC_PBMAC1_MAX_KEY_SIZE
 * \brief The maximum derived MAC key size in bytes.
 */
#define QSC_PBMAC1_MAX_KEY_SIZE 64ULL

/*! 
 * \def QSC_PBMAC1_MAX_ITERATIONS
 * \brief The implementation safety cap for PBKDF2 iterations.
 */
#define QSC_PBMAC1_MAX_ITERATIONS 10000000ULL

/*! 
 * \enum qsc_pbmac1_hash_type
 * \brief The PBMAC1 SHA-2 digest and HMAC selection.
 */
typedef enum
{
	qsc_pbmac1_hash_none = 0x00U,      /*!< No digest selected. */
	qsc_pbmac1_hash_sha256 = 0x01U,    /*!< PBKDF2-HMAC-SHA2-256 and HMAC-SHA2-256. */
	qsc_pbmac1_hash_sha384 = 0x02U,    /*!< PBKDF2-HMAC-SHA2-384 and HMAC-SHA2-384. */
	qsc_pbmac1_hash_sha512 = 0x03U     /*!< PBKDF2-HMAC-SHA2-512 and HMAC-SHA2-512. */
} qsc_pbmac1_hash_type;

/*! 
 * \struct qsc_pbmac1_keyparams
 * \brief The PBMAC1 key derivation parameters.
 */
QSC_EXPORT_API typedef struct
{
	const uint8_t* password;            /*!< [const] The password byte array. */
	const uint8_t* salt;                /*!< [const] The PBKDF2 salt byte array. */
	size_t passwordlen;                 /*!< The password length in bytes. */
	size_t saltlen;                     /*!< The salt length in bytes. */
	uint64_t iterations;                /*!< The PBKDF2 iteration count. */
	qsc_pbmac1_hash_type hash;          /*!< The SHA-2 digest and HMAC selection. */
	size_t keylen;                      /*!< The derived MAC key length in bytes; use zero for the digest length default. */
} qsc_pbmac1_keyparams;

/*! 
 * \struct qsc_pbmac1_state
 * \brief The PBMAC1 state structure.
 */
QSC_EXPORT_API typedef struct
{
	union
	{
		qsc_hmac256_state h256;           /*!< The HMAC-SHA2-256 state. */
		qsc_hmac384_state h384;           /*!< The HMAC-SHA2-384 state. */
		qsc_hmac512_state h512;           /*!< The HMAC-SHA2-512 state. */
	} state;                            /*!< The selected HMAC state. */
	qsc_pbmac1_hash_type hash;          /*!< The active digest and HMAC selection. */
	bool initialized;                   /*!< The initialized flag. */
} qsc_pbmac1_state;

/**
 * \brief Process a message with PBMAC1 and return the MAC code.
 *
 * \warning The output array must be at least qsc_pbmac1_mac_size(keyparams->hash) bytes in length.
 *
 * \param output: [uint8_t*] The output byte array; receives the MAC code.
 * \param keyparams: [const qsc_pbmac1_keyparams*] Pointer to the PBMAC1 key parameters.
 * \param message: [const uint8_t*] The message input byte array.
 * \param msglen: [size_t] The number of message bytes to process.
 *
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_pbmac1_compute(uint8_t* output, const qsc_pbmac1_keyparams* keyparams, const uint8_t* message, size_t msglen);

/**
 * \brief Derive a PBMAC1 MAC key with PBKDF2.
 *
 * \param output: [uint8_t*] The output byte array; receives the derived key.
 * \param outlen: [size_t] The requested derived key length in bytes.
 * \param keyparams: [const qsc_pbmac1_keyparams*] Pointer to the PBMAC1 key parameters.
 *
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_pbmac1_derive_key(uint8_t* output, size_t outlen, const qsc_pbmac1_keyparams* keyparams);

/**
 * \brief Dispose of a PBMAC1 state.
 *
 * \param ctx: [qsc_pbmac1_state*] Pointer to the PBMAC1 state structure.
 */
QSC_EXPORT_API void qsc_pbmac1_dispose(qsc_pbmac1_state* ctx);

/**
 * \brief Finalize the PBMAC1 state and return the MAC code.
 *
 * \warning Finalize calls dispose on the PBMAC1 state.
 *
 * \param ctx: [qsc_pbmac1_state*] Pointer to the PBMAC1 state structure.
 * \param output: [uint8_t*] The output byte array; receives the MAC code.
 *
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_pbmac1_finalize(qsc_pbmac1_state* ctx, uint8_t* output);

/**
 * \brief Initialize a PBMAC1 state.
 *
 * \param ctx: [qsc_pbmac1_state*] Pointer to the PBMAC1 state structure.
 * \param keyparams: [const qsc_pbmac1_keyparams*] Pointer to the PBMAC1 key parameters.
 *
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_pbmac1_initialize(qsc_pbmac1_state* ctx, const qsc_pbmac1_keyparams* keyparams);

/**
 * \brief Return the MAC output size for a PBMAC1 hash selection.
 *
 * \param hash: [qsc_pbmac1_hash_type] The digest and HMAC selection.
 *
 * \return [size_t] Returns the MAC size in bytes, or zero if the hash is unsupported.
 */
QSC_EXPORT_API size_t qsc_pbmac1_mac_size(qsc_pbmac1_hash_type hash);

/**
 * \brief Update PBMAC1 with message input.
 *
 * \param ctx: [qsc_pbmac1_state*] Pointer to the PBMAC1 state structure.
 * \param message: [const uint8_t*] The input message byte array.
 * \param msglen: [size_t] The number of message bytes to process.
 *
 * \return [bool] Returns true on success.
 */
QSC_EXPORT_API bool qsc_pbmac1_update(qsc_pbmac1_state* ctx, const uint8_t* message, size_t msglen);

/**
 * \brief Verify a PBMAC1 code using a constant-time comparison.
 *
 * \param code: [const uint8_t*] The expected MAC code.
 * \param codelen: [size_t] The expected MAC code length in bytes.
 * \param keyparams: [const qsc_pbmac1_keyparams*] Pointer to the PBMAC1 key parameters.
 * \param message: [const uint8_t*] The message input byte array.
 * \param msglen: [size_t] The number of message bytes to process.
 *
 * \return [bool] Returns true if the MAC code is valid.
 */
QSC_EXPORT_API bool qsc_pbmac1_verify(const uint8_t* code, size_t codelen, const qsc_pbmac1_keyparams* keyparams, const uint8_t* message, size_t msglen);

QSC_CPLUSPLUS_ENABLED_END

#endif
