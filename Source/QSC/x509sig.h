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

#ifndef QSC_X509_SIG_H
#define QSC_X509_SIG_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_sig.h
 * \brief X.509 signature algorithm and signature value helpers.
 *
 * \details
 * This header defines the public API used to decode certificate and
 * TBSCertificate signature AlgorithmIdentifier structures, classify the
 * associated public key and hash functions, and decode signature values in the
 * forms commonly used by DER-encoded X.509 certificates.
 *
 * The first implementation pass is focused on RSA and ECDSA algorithm
 * identifiers. ECDSA signature values are decoded from the DER SEQUENCE of
 * INTEGER values into fixed-width big-endian buffers suitable for conversion
 * into the internal verification format used by the higher verification layer.
 * RSA signature values are exposed as raw BIT STRING octets.
 */

/*!
 * \def QSC_X509_MAX_SIGNATURE_COMPONENT_SIZE
 * \brief The maximum size in bytes of an ECDSA signature component.
 *
 * \details
 * ECDSA signatures encoded in X.509 certificates are represented as a
 * DER sequence containing two INTEGER values, r and s. After decoding,
 * these values are stored in fixed-width buffers inside the
 * qsc_x509_ecdsa_signature structure.
 *
 * The maximum component size must accommodate the largest supported
 * elliptic curve scalar size. The current X.509 implementation supports
 * the following NIST curves:
 *
 * - prime256v1 (P-256)  -> 32 bytes
 * - secp384r1 (P-384)   -> 48 bytes
 * - secp521r1 (P-521)   -> 66 bytes
 *
 * P-521 requires ceil(521 / 8) = 66 bytes to represent a scalar value,
 * therefore the maximum signature component size is defined as 66 bytes.
 *
 * This value is used to size the r and s buffers in the
 * qsc_x509_ecdsa_signature structure and ensures that signatures for
 * all supported curves can be decoded without dynamic allocation.
 */
#define QSC_X509_MAX_SIGNATURE_COMPONENT_SIZE 66U

/*!
 * \brief The decoded ECDSA signature value.
 *
 * \remarks
 * The r and s arrays are stored as unsigned big-endian integers, left padded
 * with zero octets to the width implied by the named curve.
 */
typedef struct qsc_x509_ecdsa_signature_t
{
	uint8_t r[QSC_X509_MAX_SIGNATURE_COMPONENT_SIZE];
	uint8_t s[QSC_X509_MAX_SIGNATURE_COMPONENT_SIZE];
	size_t length;
} qsc_x509_ecdsa_signature;

/*!
 * \brief Decodes a signature AlgorithmIdentifier structure.
 *
 * \param element: [const qsc_encoding_ber_element*] The ASN.1 SEQUENCE element
 * containing the AlgorithmIdentifier structure.
 * \param algorithm: [qsc_x509_algorithm_identifier*] Receives the decoded
 * algorithm identifier.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_signature_algorithm_decode(const qsc_encoding_ber_element* element, qsc_x509_algorithm_identifier* algorithm);

/*!
 * \brief Compares two decoded algorithm identifiers for semantic equality.
 *
 * \param left: [const qsc_x509_algorithm_identifier*] The left algorithm value.
 * \param right: [const qsc_x509_algorithm_identifier*] The right algorithm value.
 *
 * \return [bool] Returns true if the two algorithm identifiers are equivalent.
 */
QSC_EXPORT_API bool qsc_x509_signature_algorithm_equal(const qsc_x509_algorithm_identifier* left, const qsc_x509_algorithm_identifier* right);

/*!
 * \brief Decodes a certificate signature BIT STRING as a raw octet sequence.
 *
 * \param element: [const qsc_encoding_ber_element*] The BIT STRING element
 * containing the signature value.
 * \param signature: [uint8_t*] Receives the raw signature octets.
 * \param signaturelen: [size_t] The size of the output array in octets.
 * \param outlen: [size_t*] Receives the number of octets written.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_signature_value_decode_raw(const qsc_encoding_ber_element* element, uint8_t* signature, size_t signaturelen, size_t* outlen);

/*!
 * \brief Decodes a certificate ECDSA signature BIT STRING.
 *
 * \param element: [const qsc_encoding_ber_element*] The BIT STRING element
 * containing the DER-encoded ECDSA signature value.
 * \param curve: [qsc_x509_named_curve] The named curve associated with the
 * signing key.
 * \param signature: [qsc_x509_ecdsa_signature*] Receives the decoded signature
 * components.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_signature_value_decode_ecdsa(const qsc_encoding_ber_element* element, qsc_x509_named_curve curve, qsc_x509_ecdsa_signature* signature);

/*!
 * \brief Gets the expected maximum signature component size in octets for a
 * named curve.
 *
 * \param curve: [qsc_x509_named_curve] The named curve identifier.
 *
 * \return [size_t] Returns the signature component size in octets, or zero if
 * the curve is not recognized.
 */
QSC_EXPORT_API size_t qsc_x509_signature_component_size(qsc_x509_named_curve curve);

QSC_CPLUSPLUS_ENABLED_END

#endif
