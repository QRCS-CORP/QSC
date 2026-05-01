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

#ifndef QSC_TLS_RECORD_H
#define QSC_TLS_RECORD_H

#include "tlserrors.h"
#include "tlstypes.h"
#include "tlsstate.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsrecord.h
 * \brief TLS record formatting and protection helpers.
 */

/**
 * \brief Initialize a TLS record protection state.
 *
 * \param state: [struct] The record state to initialize.
 * \param key: [const uint8_t*] The traffic key buffer.
 * \param keylen: [size_t] The traffic key length in bytes.
 * \param iv: [const uint8_t*] The static traffic IV buffer.
 * \param ivlen: [size_t] The static traffic IV length in bytes.
 */
QSC_EXPORT_API void qsc_tls_record_state_initialize(qsc_tls_record_state* state, qsc_tls_cipher_suite suite, const uint8_t* key, 
	size_t keylen, const uint8_t* iv, size_t ivlen);

/**
 * \brief Dispose of a TLS record protection state.
 *
 * \param state: [struct] The record state to clear.
 */
QSC_EXPORT_API void qsc_tls_record_state_dispose(qsc_tls_record_state* state);

/**
 * \brief Install or replace traffic keys on an existing record state, resetting the sequence.
 *
 * \details
 * Intended for epoch transitions (handshake to application keys) and for KeyUpdate. The existing
 * key material is zeroized via qsc_memutils_secure_erase before the new key and IV are installed.
 * Equivalent in effect to qsc_tls_record_state_dispose followed by qsc_tls_record_state_initialize
 * but presented as a single atomic operation so callers cannot observe a partially-cleared state.
 *
 * \param state: [struct*] The record state to update.
 * \param suite: [enum] The cipher suite.
 * \param key: [const uint8_t*] The new traffic key.
 * \param keylen: [size_t] The new key length; must match the suite.
 * \param iv: [const uint8_t*] The new 12-byte static IV.
 * \param ivlen: [size_t] The IV length; must be 12.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_state_install_keys(qsc_tls_record_state* state, qsc_tls_cipher_suite suite, const uint8_t* key, 
	size_t keylen, const uint8_t* iv, size_t ivlen);

/**
 * \brief Read the current sequence number. Returns 0 when state is NULL or uninitialized.
 *
 * \param state: [const struct*] The record state.
 *
 * \return [uint64_t] Current 64-bit sequence counter.
 */
QSC_EXPORT_API uint64_t qsc_tls_record_state_get_sequence(const qsc_tls_record_state* state);

/**
 * \brief Encode a plaintext TLS record.
 *
 * \param output: [uint8_t*] The destination record buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written.
 * \param type: [enum] The outer record content type.
 * \param input: [const uint8_t*] The plaintext payload buffer.
 * \param inlen: [size_t] The plaintext payload length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_encode_plaintext(uint8_t* output, size_t outlen, size_t* written, qsc_tls_record_content_type type, 
	const uint8_t* input, size_t inlen);

/**
 * \brief Decode a plaintext TLS record.
 *
 * \param input: [const uint8_t*] The source record buffer.
 * \param inlen: [size_t] The source buffer length in bytes.
 * \param type: [enum] Receives the decoded outer record content type.
 * \param payload: [const uint8_t**] Receives a pointer to the decoded payload span.
 * \param payloadlen: [size_t*] Receives the decoded payload length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_decode_plaintext(const uint8_t* input, size_t inlen, qsc_tls_record_content_type* type, 
	const uint8_t** payload, size_t* payloadlen);

/**
 * \brief Determine the full span length of a TLS record.
 *
 * \param input: [const uint8_t*] The source buffer.
 * \param inlen: [size_t] The source buffer length in bytes.
 * \param recordlen: [size_t*] Receives the full record span length in bytes.
 * \param complete: [bool*] Receives true if the full record is present in the source buffer.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_try_get_span_length(const uint8_t* input, size_t inlen, size_t* recordlen, bool* complete);

/**
 * \brief Protect a TLSInnerPlaintext payload as a TLSCiphertext record.
 *
 * \param state: [struct] The active write-side record protection state.
 * \param output: [uint8_t*] The destination record buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of bytes written.
 * \param inner_type: [enum] The inner content type trailer.
 * \param input: [const uint8_t*] The plaintext payload buffer.
 * \param inlen: [size_t] The plaintext payload length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_encrypt(qsc_tls_record_state* state, uint8_t* output, size_t outlen, size_t* written, 
	qsc_tls_record_content_type inner_type, const uint8_t* input, size_t inlen);

/**
 * \brief Decrypt a protected TLSCiphertext record.
 *
 * \param state: [struct] The active read-side record protection state.
 * \param output: [uint8_t*] The destination plaintext buffer.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of plaintext bytes written.
 * \param inner_type: [enum] Receives the decoded inner content type.
 * \param input: [const uint8_t*] The protected record buffer.
 * \param inlen: [size_t] The protected record length in bytes.
 *
 * \return Returns a TLS status code.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_record_decrypt(qsc_tls_record_state* state, uint8_t* output, size_t outlen, size_t* written, 
	qsc_tls_record_content_type* inner_type, const uint8_t* input, size_t inlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
