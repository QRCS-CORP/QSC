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

#ifndef QSC_X509_NAME_H
#define QSC_X509_NAME_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_name.h
 * \brief Distinguished name parsing and formatting helpers for the QSC X.509 layer.
 *
 * \details
 * This header defines the support functions used to decode and operate on the
 * X.509 Name type. In DER-encoded certificates, the issuer and subject fields
 * are represented as a sequence of relative distinguished names, where each
 * relative distinguished name contains one or more attribute type and value
 * pairs.
 *
 * The implementation in this module decodes the Name structure into the flat
 * qsc_x509_name representation defined in x509_types.h. The parser is strict
 * with respect to the ASN.1 structure expected by X.509, while remaining small
 * and explicit. Multi-valued relative distinguished names are accepted and are
 * appended to the output attribute list in encoded order.
 *
 * The module provides:
 *
 * - Name initialization and clearing helpers.
 * - Conversion of object identifier registry entries to normalized name attribute types.
 * - Parsing of X.509 Name and AttributeTypeAndValue elements.
 * - Simple lookup helpers over decoded distinguished names.
 * - Deterministic comparison of decoded names.
 * - Compact text formatting for diagnostics and logging.
 *
 * The comparison and formatting logic operates on the normalized strings
 * produced by qsc_asn1_decode_string(). It does not implement the full LDAP or
 * RFC 5280 distinguished name canonicalization rules. The functions are
 * intended for a compact certificate validation layer rather than a general
 * directory service implementation.
 */

/*!
 * \brief Clears a decoded distinguished name structure.
 *
 * \param name: [qsc_x509_name*] The decoded distinguished name structure.
 */
QSC_EXPORT_API void qsc_x509_name_clear(qsc_x509_name* name);

/*!
 * \brief Maps an object identifier registry identifier to a normalized distinguished name attribute type.
 *
 * \param id: [qsc_oid_id] The object identifier registry identifier.
 *
 * \return [qsc_x509_name_attribute_type] Returns the mapped distinguished name attribute type.
 */
QSC_EXPORT_API qsc_x509_name_attribute_type qsc_x509_name_attribute_type_from_oid(qsc_oid_id id);

/*!
 * \brief Gets the short display name of a distinguished name attribute type.
 *
 * \param type: [qsc_x509_name_attribute_type] The distinguished name attribute type.
 *
 * \return [const char*] Returns the short display name, or NULL if the type is invalid.
 */
QSC_EXPORT_API const char* qsc_x509_name_attribute_short_name(qsc_x509_name_attribute_type type);

/*!
 * \brief Gets the descriptive registry name of a distinguished name attribute type.
 *
 * \param type: [qsc_x509_name_attribute_type] The distinguished name attribute type.
 *
 * \return [const char*] Returns the descriptive registry name, or NULL if the type is invalid.
 */
QSC_EXPORT_API const char* qsc_x509_name_attribute_long_name(qsc_x509_name_attribute_type type);

/*!
 * \brief Parses an X.509 Name element.
 *
 * \param element: [const qsc_encoding_ber_element*] The ASN.1 element representing the Name value.
 * \param name: [qsc_x509_name*] Receives the decoded distinguished name.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_name_parse(const qsc_encoding_ber_element* element, qsc_x509_name* name);

/*!
 * \brief Finds the first attribute of a given type within a decoded distinguished name.
 *
 * \param name: [const qsc_x509_name*] The decoded distinguished name.
 * \param type: [qsc_x509_name_attribute_type] The requested distinguished name attribute type.
 *
 * \return [const qsc_x509_name_attribute*] Returns a pointer to the first matching attribute, or NULL if no match exists.
 */
QSC_EXPORT_API const qsc_x509_name_attribute* qsc_x509_name_find_first(const qsc_x509_name* name, qsc_x509_name_attribute_type type);

/*!
 * \brief Tests two decoded distinguished names for deterministic equality.
 *
 * \param a: [const qsc_x509_name*] The first decoded distinguished name.
 * \param b: [const qsc_x509_name*] The second decoded distinguished name.
 *
 * \return [bool] Returns true if the decoded distinguished names are equal.
 */
QSC_EXPORT_API bool qsc_x509_name_equals(const qsc_x509_name* a, const qsc_x509_name* b);

/*!
 * \brief Formats a decoded distinguished name as a compact zero-terminated string.
 *
 * \param name: [const qsc_x509_name*] The decoded distinguished name.
 * \param output: [char*] The destination character array.
 * \param otplen: [size_t] The size of the destination character array.
 * \param outlen: [size_t*] Receives the number of characters written excluding the terminating zero.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_name_to_string(const qsc_x509_name* name, char* output, size_t otplen, size_t* outlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
