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
 * Implements the RFC 9846 NewSessionTicket message body codec and the local
 * metadata required to offer a ticket safely in a later TLS 1.3 handshake.
 *
 * NewSessionTicket body layout per RFC 9846 Section 4.7.1:
 *   uint32 ticket_lifetime;
 *   uint32 ticket_age_add;
 *   opaque ticket_nonce<0..255>;
 *   opaque ticket<1..2^16-1>;
 *   Extension extensions<0..2^16-1>;
 *
 * This module encodes and decodes the wire message body only. Local metadata
 * such as receipt time, issuance time, SNI, ALPN, cipher suite, and the derived
 * resumption PSK is retained in qsc_tls_session_ticket but is not serialized by
 * qsc_tls_session_ticket_encode().
 */

typedef struct qsc_tls_session_ticket
{
    uint8_t nonce[QSC_TLS_TICKET_NONCE_MAX_SIZE];        /*!< ticket_nonce. */
    uint8_t resumptionsecret[QSC_TLS_HASH_MAX_SIZE];     /*!< PSK derived from the RFC 9846 resumption secret. */
    uint8_t ticket[QSC_TLS_TICKET_MAX_SIZE];             /*!< Opaque PSK identity carried in pre_shared_key. */
    uint8_t servername[QSC_TLS_MAX_HOSTNAME_SIZE];       /*!< SNI name associated with the connection that established the ticket. */
    uint8_t alpn[QSC_TLS_MAX_ALPN_SIZE];                 /*!< ALPN protocol associated with the ticket, when one was negotiated. */
    uint64_t issuetimems;                                /*!< Local server wall-clock time in milliseconds when the ticket was issued. */
    uint64_t receipttimems;                              /*!< Local client wall-clock time in milliseconds when NewSessionTicket was received. */
    uint32_t ageadd;                                     /*!< ticket_age_add. */
    uint32_t lifetime;                                   /*!< ticket_lifetime in seconds. */
    uint32_t maxearlydatasize;                           /*!< Parsed NewSessionTicket max_early_data_size; engine-managed QSC tickets normalize this to zero. */
    size_t noncelen;                                     /*!< Nonce length. */
    size_t resumptionsecretlen;                          /*!< Length of the resumption secret. */
    size_t ticketlen;                                    /*!< Ticket identity length. */
    size_t servernamelen;                                /*!< Length of servername. */
    size_t alpnlen;                                      /*!< Length of alpn. */
    qsc_tls_cipher_suite suite;                          /*!< Originating cipher suite; its KDF hash binds the PSK. */
    uint16_t protocolversion;                            /*!< TLS version associated with the PSK; QSC tickets use TLS 1.3. */
} qsc_tls_session_ticket;

/**
 * \brief Encode a TLS session ticket structure.
 *
 * \details
 * Serializes the RFC 9846 NewSessionTicket message body represented by a qsc_tls_session_ticket.
 * Only wire fields are encoded; local resumption metadata and PSK bytes are intentionally not serialized.
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
 * Parses an RFC 9846 NewSessionTicket message body into a qsc_tls_session_ticket structure.
 * Local-only fields are cleared and must be populated by the caller from the established connection context.
 *
 * The input buffer must contain a complete and correctly formatted encoded ticket. Partial or malformed input will result in a failure status.
 * A structurally valid ticket whose opaque identity exceeds QSC_TLS_TICKET_MAX_SIZE is fully validated and returns qsc_tls_status_not_supported without retaining the oversized identity.
 *
 * \param input: [const uint8_t*] Pointer to the encoded session ticket buffer.
 * \param inplen: [size_t] Length, in bytes, of the encoded ticket buffer.
 * \param ticket: [qsc_tls_session_ticket*] Pointer to the structure that will receive the decoded ticket contents.
 *
 * \return [qsc_tls_status] Returns qsc_tls_status_success on success, qsc_tls_status_not_supported when a valid ticket exceeds local retention capacity, or an error status for malformed input.
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
