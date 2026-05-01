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

#ifndef QSC_TLS_ECDSA_DER_H
#define QSC_TLS_ECDSA_DER_H

#include "qsccommon.h"
#include "tlserrors.h"

QSC_CPLUSPLUS_ENABLED_START

/**
 * \file tlsecdsader.h
 * \brief RFC 8446 section 4.2.3 ECDSA-Sig-Value DER encoding.
 *
 * TLS 1.3 ECDSA signatures on the wire are DER-encoded as:
 *   ECDSA-Sig-Value ::= SEQUENCE {
 *     r INTEGER,
 *     s INTEGER
 *   }
 * QSC's ecdsa primitive produces raw r||s of fixed width. These helpers
 * convert between the two representations. INTEGER encoding rules (X.690):
 *   - Shortest-form length.
 *   - If the MSB of the first content byte is 1, a leading 0x00 must be
 *     prepended to distinguish positive from negative.
 *   - Leading 0x00 bytes that are not required for disambiguation are
 *     stripped (shortest form).
 */

/**
 * \brief DER-encode a raw r||s ECDSA signature.
 *
 * \param rs: [const uint8_t*] Raw r||s buffer, each component width bytes long.
 * \param componentsize: [size_t] Size of each component in bytes (32 for P-256, 48 for P-384, 66 for P-521).
 * \param output: [uint8_t*] Destination buffer for DER-encoded signature.
 * \param outlen: [size_t] Capacity of output.
 * \param written: [size_t*] On success, receives the DER length (variable, typically 70-72 for P-256).
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_ecdsa_der_encode(const uint8_t* rs, size_t componentsize,
    uint8_t* output, size_t outlen, size_t* written);

/**
 * \brief Decode a DER-encoded ECDSA signature into raw r||s form.
 *
 * \param der: [const uint8_t*] DER-encoded signature.
 * \param derlen: [size_t] DER signature length.
 * \param componentsize: [size_t] Expected size of each component (defines output width).
 * \param output: [uint8_t*] Destination r||s buffer; must be at least 2*componentsize bytes.
 * \param outlen: [size_t] Capacity of output.
 */
QSC_EXPORT_API qsc_tls_status qsc_tls_ecdsa_der_decode(const uint8_t* der, size_t derlen,
    size_t componentsize, uint8_t* output, size_t outlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
