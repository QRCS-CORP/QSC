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

#ifndef QSC_TLS_TRANSCRIPT_H
#define QSC_TLS_TRANSCRIPT_H

#include "qsccommon.h"
#include "tlsstate.h"
#include "tlserrors.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlstranscript.h
 * \brief TLS 1.3 transcript-hash helpers.
 *
 * \details
 * This header exposes the transcript hashing helpers used by the TLS 1.3 handshake layer.
 * The transcript state stores an incremental hash context selected by the negotiated cipher
 * suite hash. Callers update the transcript with serialized handshake bytes and may request
 * digest snapshots without disturbing the active hash state.
 */

/**
 * \brief Initialize a transcript hash state.
 *
 * \param state: [struct*] The transcript state to initialize.
 * \param hash: [enum] The hash algorithm to activate.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_initialize(qsc_tls_transcript_state* state, qsc_tls_hash_algorithm hash);

/**
 * \brief Dispose of a transcript hash state.
 *
 * \details
 * Securely erases the active transcript state and any retained intermediate hash context.
 *
 * \param state: [struct*] The transcript state to clear.
 */
QSC_EXPORT_API void qsc_tls_transcript_dispose(qsc_tls_transcript_state* state);

/**
 * \brief Append serialized handshake bytes to the transcript hash.
 *
 * \param state: [struct*] The active transcript state.
 * \param input: [const uint8_t*] The serialized handshake bytes to append.
 * \param inplen: [size_t] The number of bytes to append.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_update(qsc_tls_transcript_state* state, const uint8_t* input, size_t inplen);

/**
 * \brief Snapshot the current transcript digest without disturbing the ongoing hash state.
 *
 * \details
 * Clones the underlying hash context, finalizes the clone into the caller-supplied output
 * buffer, and leaves the live transcript state unchanged.
 *
 * \param state: [const struct*] The active transcript state.
 * \param output: [uint8_t*] The destination buffer for the transcript digest.
 * \param outlen: [size_t] The destination buffer length in bytes.
 * \param written: [size_t*] Receives the number of digest bytes written.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_snapshot(const qsc_tls_transcript_state* state, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Replace the transcript with the synthetic message_hash form used after HelloRetryRequest.
 *
 * \details
 * Replaces the current transcript contents with the synthetic handshake message defined by
 * RFC 8446 Section 4.4.1, consisting of the message_hash handshake type and the digest of
 * the previous ClientHello.
 *
 * \param state: [struct*] The active transcript state.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_transcript_replace_with_message_hash(qsc_tls_transcript_state* state);

/**
 * \brief Get the digest size in bytes for a TLS transcript hash algorithm.
 *
 * \param hash: [enum] The transcript hash algorithm.
 *
 * \return [size_t] Returns the digest size in bytes, or zero if the algorithm is unsupported.
 */
QSC_EXPORT_API size_t qsc_tls_transcript_digest_size(qsc_tls_hash_algorithm hash);

QSC_CPLUSPLUS_ENABLED_END

#endif
