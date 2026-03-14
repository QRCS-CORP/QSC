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

#ifndef QSC_X509_CERT_H
#define QSC_X509_CERT_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_cert.h
 * \brief X.509 certificate parsing helpers for the QSC X.509 layer.
 *
 * \details
 * This header defines the public API used to decode DER encoded X.509
 * certificates into the normalized qsc_x509_certificate structure defined in
 * x509_types.h. The parser stores the original DER certificate pointer and the
 * exact TBSCertificate span from the caller supplied buffer so that the higher
 * verification layer can hash and validate the signed certificate body without
 * re-serialization.
 */

/*!
 * \brief Clears a decoded certificate structure.
 *
 * \param certificate: [qsc_x509_certificate*] The certificate structure.
 */
QSC_EXPORT_API void qsc_x509_certificate_clear(qsc_x509_certificate* certificate);

/*!
 * \brief Decodes a DER encoded X.509 certificate.
 *
 * \param der: [const uint8_t*] The DER encoded certificate.
 * \param derlen: [size_t] The length of the DER certificate in octets.
 * \param certificate: [qsc_x509_certificate*] Receives the decoded certificate.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_decode_der(const uint8_t* der, size_t derlen, qsc_x509_certificate* certificate);

/*!
 * \brief Finds the first raw extension entry of a given type.
 *
 * \param certificate: [const qsc_x509_certificate*] The decoded certificate.
 * \param type: [qsc_x509_extension_type] The extension type to search for.
 *
 * \return [const qsc_x509_extension*] Returns a pointer to the first matching
 * extension, or NULL if the requested extension is not present.
 */
QSC_EXPORT_API const qsc_x509_extension* qsc_x509_certificate_find_extension(const qsc_x509_certificate* certificate, qsc_x509_extension_type type);

QSC_CPLUSPLUS_ENABLED_END

#endif
