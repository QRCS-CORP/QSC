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

#ifndef QSC_TLS_ERRORS_H
#define QSC_TLS_ERRORS_H

#include "qsccommon.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlserrors.h
 * \brief TLS status code definitions and diagnostic string conversion.
 */

typedef enum qsc_tls_status
{
	qsc_tls_status_success = 0,						/*!< The operation completed successfully. */
	qsc_tls_status_failure = -1,					/*!< A generic TLS processing failure occurred. */
	qsc_tls_status_invalid_input = -2,				/*!< One or more input parameters were null, invalid, or semantically inconsistent. */
	qsc_tls_status_buffer_too_small = -3,			/*!< The supplied output buffer could not hold the encoded or decoded result. */
	qsc_tls_status_invalid_state = -4,				/*!< The object state did not permit the requested TLS operation. */
	qsc_tls_status_invalid_length = -5,				/*!< A parsed, derived, or supplied length field was outside the valid range. */
	qsc_tls_status_not_supported = -6,				/*!< The requested TLS feature, group, suite, or algorithm is not supported. */
	qsc_tls_status_authentication_failure = -7,		/*!< Authentication failed, or a signature, MAC, or certificate validation step failed. */
	qsc_tls_status_invalid_message = -8				/*!< The TLS message was malformed, truncated, or semantically invalid. */
} qsc_tls_status;

/**
 * \brief Convert a TLS status code to a descriptive diagnostic string.
 *
 * \param status: [enum] The TLS status code.
 *
 * \return: A constant descriptive string for the status code.
 */
QSC_EXPORT_API const char* qsc_tls_error_to_string(qsc_tls_status status);

QSC_CPLUSPLUS_ENABLED_END

#endif
