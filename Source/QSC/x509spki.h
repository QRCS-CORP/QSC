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

#ifndef QSC_X509_SPKI_H
#define QSC_X509_SPKI_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_spki.h
 * \brief SubjectPublicKeyInfo parsing helpers for the QSC X.509 layer.
 *
 * \details
 * This header defines the public API used to decode the X.509
 * SubjectPublicKeyInfo structure and the nested AlgorithmIdentifier structure
 * associated with certificate subject public keys. The functions in this
 * module convert the generic ASN.1 element tree produced by the DER decoder
 * into the normalized qsc_x509_algorithm_identifier and
 * qsc_x509_subject_public_key_info structures defined in x509_types.h.
 *
 * The first implementation pass is intentionally conservative. It is focused on
 * the algorithms and parameter encodings that are commonly encountered in
 * DER-encoded X.509 certificates, with primary emphasis on id-ecPublicKey and
 * named curve parameters used by elliptic curve certificates. The API also
 * recognizes common RSA identifiers so that the wider certificate layer can
 * classify unsupported subject public key types without misidentifying them.
 */

/*!
 * \brief Decodes an AlgorithmIdentifier structure.
 *
 * \param element: [const qsc_encoding_ber_element*] The ASN.1 SEQUENCE element
 * containing the AlgorithmIdentifier structure.
 * \param algorithm: [qsc_x509_algorithm_identifier*] Receives the decoded
 * algorithm identifier data.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_algorithm_identifier_decode(const qsc_encoding_ber_element* element, qsc_x509_algorithm_identifier* algorithm);

/*!
 * \brief Decodes a SubjectPublicKeyInfo structure.
 *
 * \param element: [const qsc_encoding_ber_element*] The ASN.1 SEQUENCE element
 * containing the SubjectPublicKeyInfo structure.
 * \param spki: [qsc_x509_subject_public_key_info*] Receives the decoded subject
 * public key information.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_subject_public_key_info_decode(const qsc_encoding_ber_element* element, qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Tests whether a decoded subject public key is encoded as an
 * uncompressed elliptic curve point.
 *
 * \param spki: [const qsc_x509_subject_public_key_info*] The decoded subject
 * public key information.
 *
 * \return [bool] Returns true if the key is an uncompressed elliptic curve
 * point.
 */
QSC_EXPORT_API bool qsc_x509_spki_is_uncompressed_ec_point(const qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Gets the expected field element size in octets for a named curve.
 *
 * \param curve: [qsc_x509_named_curve] The named curve identifier.
 *
 * \return [size_t] Returns the coordinate size in octets, or zero if the curve
 * is not recognized.
 */
QSC_EXPORT_API size_t qsc_x509_named_curve_coordinate_size(qsc_x509_named_curve curve);

/*!
 * \brief Extracts affine x and y coordinates from an uncompressed elliptic
 * curve point.
 *
 * \param spki: [const qsc_x509_subject_public_key_info*] The decoded subject
 * public key information.
 * \param x: [uint8_t*] Receives the x coordinate octets.
 * \param xlen: [size_t] The size of the x output array in octets.
 * \param y: [uint8_t*] Receives the y coordinate octets.
 * \param ylen: [size_t] The size of the y output array in octets.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_spki_get_ec_coordinates(const qsc_x509_subject_public_key_info* spki, uint8_t* x, size_t xlen, uint8_t* y, size_t ylen);

QSC_CPLUSPLUS_ENABLED_END

#endif
