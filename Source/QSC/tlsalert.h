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

#ifndef QSC_TLS_ALERT_H
#define QSC_TLS_ALERT_H

#include "qsccommon.h"
#include "tlserrors.h"
#include "tlstypes.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsalert.h
 * \brief TLS alert message encoding and decoding functions.
 *
 * \details
 * This header declares helpers that convert between the compact two-byte TLS
 * alert wire format and the internal alert description enumeration used by the
 * TLS implementation.
 */

/**
 * \brief Decode a TLS alert record payload.
 *
 * \details
 * Parses exactly one standard two-byte TLS alert payload and extracts the alert
 * description field. In TLS 1.3, AlertLevel is a legacy field and is ignored on
 * receipt. Unknown alert-description values are returned to the caller so they
 * can be treated as error alerts as required by RFC 9846.
 *
 * \param input [const uint8_t*] The encoded alert payload.
 * \param inlen [size_t] The length of the encoded input in bytes.
 * \param description [enum*] Receives the decoded TLS alert description.
 *
 * \return [qsc_tls_status] Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_alert_decode(const uint8_t* input, size_t inlen, qsc_tls_alert_description* description);

/**
 * \brief Encode a TLS alert record payload.
 *
 * \details
 * Writes the standard two-byte TLS alert payload to the destination buffer.
 * close_notify and user_canceled are encoded with warning level; all defined
 * error alerts are encoded with fatal level, as required by TLS 1.3.
 *
 * \param output [uint8_t*] The destination buffer receiving the encoded alert payload.
 * \param outlen [size_t] The length of the destination buffer in bytes.
 * \param description [enum] The TLS alert description to encode.
 *
 * \return [qsc_tls_status] Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_alert_encode(uint8_t* output, size_t outlen, qsc_tls_alert_description description);

/**
 * Brief Encode a plaintext TLS alert record.
 *
 * \details
 * Builds the two-byte alert payload and wraps it in a TLSPlaintext record of
 * content type alert. This is used for alert transmission before encrypted
 * traffic keys are available.
 *
 * \param output [uint8_t*] The destination buffer receiving the encoded record.
 * \param outlen [size_t] The length of the destination buffer in bytes.
 * \param written [size_t*] Receives the number of bytes written.
 * \param description [enum] The TLS alert description to encode.
 *
 * 
 * \return [qsc_tls_status] Returns the operation status.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_alert_encode_record(uint8_t* output, size_t outlen, size_t* written, qsc_tls_alert_description description);

/**
 * Brief Map an internal TLS status value to an RFC alert description.
 *
 * \details
 * Converts internal parser, state-machine, and authentication failures to the
 * closest TLS alert description used on the wire. This helper is used when the
 * wrapper layer needs to emit a protocol alert in response to a local failure.
 *
 * \param status [enum] The internal TLS status value.
 *
 * 
 * \return [enum] Returns the mapped TLS alert description.
 */
QSC_EXPORT_API qsc_tls_alert_description qsc_tls_alert_from_status(qsc_tls_status status);

/**
 * \brief Check if alert is close_notify
 *
 * \param description: [enum] Alert description
 *
 * \return: true if close_notify
 */
QSC_EXPORT_API bool qsc_tls_alert_is_close_notify(qsc_tls_alert_description description);

/**
 * \brief Check if alert level is fatal
 *
 * \param level: [uint8_t] Alert level
 *
 * \return: true if fatal
 */
QSC_EXPORT_API bool qsc_tls_alert_is_fatal_level(uint8_t level);

/**
 * \brief Validate alert description
 *
 * \param description: [enum] Alert description
 *
 * \return: true if valid
 */
QSC_EXPORT_API bool qsc_tls_alert_is_valid(qsc_tls_alert_description description);

/**
 * \brief Convert alert description to string (debug only)
 *
 * \param description: [qsc_tls_alert_description] Alert description enumerator
 *
 * \return: const string name
 */
QSC_EXPORT_API const char* qsc_tls_alert_to_string(qsc_tls_alert_description description);

QSC_CPLUSPLUS_ENABLED_END

#endif
