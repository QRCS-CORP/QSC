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

#ifndef QSC_X509_TIME_H
#define QSC_X509_TIME_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509time.h
 * \brief X.509 time decoding, parsing, comparison, and validity helpers.
 *
 * \details
 * This header defines the public interface used to decode and manipulate X.509
 * time values and certificate validity intervals. The X.509 time alias is
 * mapped directly to the ASN.1 time representation used by the underlying
 * encoding layer.
 *
 * The interface supports decoding of ASN.1 Time elements, parsing of UTCTime
 * and GeneralizedTime text forms, comparison of normalized time values, basic
 * structural validity checks, and evaluation of whether a certificate validity
 * interval is current at a supplied reference time.
 */

/*!
 * \typedef qsc_x509_time
 * \brief Alias for the normalized ASN.1 time representation used by X.509 helpers.
 *
 * \details
 * The X.509 time type is defined as a direct alias of \ref qsc_asn1_time so
 * that X.509 validity processing and ASN.1 time parsing operate on the same
 * canonical structure.
 */
typedef qsc_asn1_time qsc_x509_time;

/*!
 * \brief Decode an ASN.1 X.509 time element.
 *
 * \details
 * Decodes an ASN.1 time element and normalizes the result into the supplied
 * X.509 time object. The input element may represent either a UTCTime or a
 * GeneralizedTime value.
 *
 * \param out: [struct] The destination decoded time object.
 * \param elem: [const][struct] The ASN.1 element containing the encoded time value.
 *
 * \return Returns true if decoding completed successfully; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_time_decode(qsc_x509_time* out, const qsc_encoding_ber_element* elem);

/*!
 * \brief Parse a UTCTime string.
 *
 * \details
 * Parses a character string encoded in ASN.1 UTCTime textual form and writes
 * the normalized result to the supplied X.509 time object. The accepted form is
 * exactly \c YYMMDDHHMMSSZ as required by DER.
 *
 * \param s: [const] The input UTCTime character buffer.
 * \param len: The length of the input buffer in bytes.
 * \param out: [struct] The destination parsed time object.
 *
 * \return Returns true if parsing completed successfully; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_time_parse_utctime(const char* s, size_t len, qsc_x509_time* out);

/*!
 * \brief Parse a GeneralizedTime string.
 *
 * \details
 * Parses a character string encoded in ASN.1 GeneralizedTime textual form and
 * writes the normalized result to the supplied X.509 time object. The accepted
 * form is exactly \c YYYYMMDDHHMMSSZ as required by DER.
 *
 * \param s: [const] The input GeneralizedTime character buffer.
 * \param len: The length of the input buffer in bytes.
 * \param out: [struct] The destination parsed time object.
 *
 * \return Returns true if parsing completed successfully; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_time_parse_generalizedtime(const char* s, size_t len, qsc_x509_time* out);

/*!
 * \brief Decode a certificate Validity sequence.
 *
 * \details
 * Decodes an ASN.1 Validity sequence and writes the notBefore and notAfter
 * values to the supplied X.509 validity structure. The function accepts only a
 * two-element DER Validity sequence and rejects intervals where \c notBefore is
 * later than \c notAfter.
 *
 * \param validity: [struct] The destination validity object.
 * \param elem: [const][struct] The ASN.1 element containing the encoded Validity sequence.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_validity_decode(qsc_x509_validity* validity, const qsc_encoding_ber_element* elem);

/*!
 * \brief Compare two X.509 time values.
 *
 * \details
 * Performs an ordered comparison of two normalized time values.
 *
 * \param a: [const][struct] The first time value.
 * \param b: [const][struct] The second time value.
 *
 * \return Returns a negative value if \p a is earlier than \p b, zero if the values are equal, 
 * or a positive value if \p a is later than \p b.
 */
QSC_EXPORT_API int32_t qsc_x509_time_compare(const qsc_x509_time* a, const qsc_x509_time* b);

/*!
 * \brief Test whether a normalized X.509 time value is structurally valid.
 *
 * \details
 * Checks that the supplied time object contains a valid normalized calendar and
 * clock representation suitable for X.509 validity evaluation.
 *
 * \param time: [const][struct] The time object to validate.
 *
 * \return Returns true if the time object is valid; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_time_is_valid(const qsc_x509_time* time);

/*!
 * \brief Test whether a validity interval is current at a supplied time.
 *
 * \details
 * Evaluates whether the supplied reference time falls within the certificate
 * validity interval described by the notBefore and notAfter fields.
 *
 * \param validity: [const][struct] The certificate validity interval.
 * \param tnow: [const][struct] The reference time used for evaluation.
 *
 * \return Returns true if the reference time is within the validity interval; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_validity_is_valid(const qsc_x509_validity* validity, const qsc_x509_time* tnow);

QSC_CPLUSPLUS_ENABLED_END

#endif
