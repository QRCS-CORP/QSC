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

#ifndef QSC_TLS_SESSION_H
#define QSC_TLS_SESSION_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlslimits.h"
#include "tlstypes.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlssession.h
 * \brief TLS 1.3 session resumption ticket handling.
 *
 * \details
 * MVP stub. Encoders and decoders return qsc_tls_status_not_supported until full resumption support is scheduled in a later milestone.
 *
 * NewSessionTicket body layout per RFC 8446 4.6.1:
 *   uint32 ticket_lifetime;
 *   uint32 ticket_age_add;
 *   opaque ticket_nonce<0..255>;
 *   opaque ticket<1..2^16-1>;
 *   Extension extensions<0..2^16-2>;
 *
 * This module encodes and decodes the body only (not the 4-byte handshake header).
 * Extensions are written as an empty vector; a full implementation would add early_data (max_early_data_size) for 0-RTT-capable tickets.
 *
 * The qsc_tls_session_ticket struct also carries the resumption PSK bytes derived by the peer after receiving the ticket.
 * Those bytes are never encoded on the wire, they're computed locally from resumption_master_secret
 * and the nonce via qsc_tls_keyschedule_derive_resumption_psk.
 */

typedef struct qsc_tls_session_ticket
{
    uint8_t nonce[QSC_TLS_TICKET_NONCE_MAX_SIZE];        /*!< ticket_nonce. */
    uint8_t resumptionsecret[QSC_TLS_HASH_MAX_SIZE];     /*!< PSK derived from resumption master secret. */
    uint8_t ticket[QSC_TLS_TICKET_MAX_SIZE];             /*!< Ticket opaque bytes. */
    uint32_t ageadd;                                     /*!< ticket_age_add. */
    uint32_t lifetime;                                   /*!< ticket_lifetime in seconds. */
    size_t noncelen;                                     /*!< Nonce length. */
    size_t resumptionsecretlen;                          /*!< Length of resumption secret. */
    size_t ticketlen;                                    /*!< Ticket length. */
    qsc_tls_cipher_suite suite;                          /*!< Originating suite. */
} qsc_tls_session_ticket;

/**
 * \brief Encode a TLS session ticket structure.
 *
 * \details
 * Serializes a qsc_tls_session_ticket structure into a compact binary form suitable for storage or transport. 
 * The encoded form contains the ticket identity, nonce, lifetime, age-add value, associated cipher suite, 
 * and the derived resumption secret. All multi-byte fields are encoded in network byte order.
 *
 * The caller is responsible for providing a buffer of sufficient size. 
 * The function does not perform dynamic allocation and will fail if the output buffer is too small to contain the serialized ticket.
 *
 * \param ticket: [const qsc_tls_session_ticket*] Pointer to the session ticket structure to encode.
 * \param output: [uint8_t*] Pointer to the destination buffer that will receive the encoded ticket.
 * \param outlen: [size_t] Size, in bytes, of the destination buffer.
 * \param written: [size_t*] Pointer receiving the number of bytes written to \c output.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_session_ticket_encode(const qsc_tls_session_ticket* ticket, uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Decode a TLS session ticket structure.
 *
 * \details
 * Parses a binary-encoded session ticket and reconstructs the corresponding qsc_tls_session_ticket structure. 
 * The function validates field lengths, ensures internal consistency, and copies all ticket components into the supplied structure.
 *
 * The input buffer must contain a complete and correctly formatted encoded ticket. Partial or malformed input will result in a failure status.
 *
 * \param input: [const uint8_t*] Pointer to the encoded session ticket buffer.
 * \param inplen: [size_t] Length, in bytes, of the encoded ticket buffer.
 * \param ticket: [qsc_tls_session_ticket*] Pointer to the structure that will receive the decoded ticket contents.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_session_ticket_decode(const uint8_t* input, size_t inplen, qsc_tls_session_ticket* ticket);

/**
 * \brief Dispose of a TLS session ticket structure.
 *
 * \details
 * Clears and zeroizes all sensitive fields within a qsc_tls_session_ticket structure, including the resumption secret, 
 * ticket identity, nonce, and any associated metadata. 
 * This function should be called when the ticket is no longer required to prevent retention of sensitive material in memory.
 *
 * The structure remains valid for reuse after disposal but must be reinitialized before use.
 *
 * \param ticket: [qsc_tls_session_ticket*] Pointer to the session ticket structure to dispose.
 */
QSC_EXPORT_API void qsc_tls_session_ticket_dispose(qsc_tls_session_ticket* ticket);

QSC_CPLUSPLUS_ENABLED_END

#endif
