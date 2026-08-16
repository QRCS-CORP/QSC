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
 * \file x509sig.h
 * \brief X.509 signature algorithm and signature value helpers.
 *
 * \details
 * This header defines the public API used to decode certificate, CRL, and CSR
 * signature AlgorithmIdentifier structures, compare decoded signature algorithms,
 * classify supported signature families, and decode signature values from the
 * BIT STRING form used in DER encoded X.509 objects.
 *
 * The module supports the classical ECDSA families used elsewhere in the QSC
 * tree and the pure ML-DSA signature identifiers used by the post-quantum path.
 * ECDSA signatures are decoded from the DER SEQUENCE of INTEGER values into
 * fixed-width big-endian component arrays. ML-DSA signatures are treated as raw
 * opaque octet strings carried directly in the BIT STRING payload. The helper
 * routines in this module are validation-oriented and do not allocate memory or
 * retain references into caller-owned ASN.1 buffers.
 */

/*!
 * \def QSC_X509_MAX_SIGNATURE_COMPONENT_SIZE
 * \brief The maximum size in bytes of an ECDSA signature component.
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
 * \brief Tests whether a decoded signature algorithm is an ECDSA variant.
 *
 * \param algorithm: [qsc_x509_signature_algorithm] The decoded signature algorithm.
 *
 * \return [bool] Returns true for ECDSA-with-SHA1/SHA256/SHA384/SHA512.
 */
QSC_EXPORT_API bool qsc_x509_signature_algorithm_is_ecdsa(qsc_x509_signature_algorithm algorithm);

/*!
 * \brief Tests whether a decoded signature algorithm is an ML-DSA variant.
 *
 * \param algorithm: [qsc_x509_signature_algorithm] The decoded signature algorithm.
 *
 * \return [bool] Returns true for ML-DSA-44, ML-DSA-65, or ML-DSA-87.
 */
QSC_EXPORT_API bool qsc_x509_signature_algorithm_is_ml_dsa(qsc_x509_signature_algorithm algorithm);

/*!
 * \brief Tests whether a decoded signature algorithm is compatible with the
 * supplied subject public key information.
 *
 * \param algorithm: [qsc_x509_signature_algorithm] The decoded signature algorithm.
 * \param spki: [const qsc_x509_subject_public_key_info*] The public key information.
 *
 * \return [bool] Returns true if the signature algorithm and SPKI describe a
 * compatible signing primitive and parameter set.
 */
QSC_EXPORT_API bool qsc_x509_signature_algorithm_matches_spki(qsc_x509_signature_algorithm algorithm, const qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Gets the expected raw signature size in octets for a signature
 * algorithm.
 *
 * \details
 * For ECDSA this returns the size of the raw concatenated r || s form used by
 * the internal QSC verification path. For ML-DSA this returns the compiled
 * signature size when available. For unknown or unsupported algorithms, zero is
 * returned.
 *
 * \param algorithm: [qsc_x509_signature_algorithm] The decoded signature algorithm.
 * \param curve: [qsc_x509_named_curve] The named curve for ECDSA signatures.
 *
 * \return [size_t] Returns the expected raw signature size in octets, or zero.
 */
QSC_EXPORT_API size_t qsc_x509_signature_expected_size(qsc_x509_signature_algorithm algorithm, qsc_x509_named_curve curve);

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
QSC_EXPORT_API qsc_asn1_status qsc_x509_signature_value_decode_raw(const qsc_encoding_ber_element* element, 
	uint8_t* signature, size_t signaturelen, size_t* outlen);

/*!
 * \brief Decodes a certificate ECDSA signature BIT STRING.
 *
 * \param element: [const qsc_encoding_ber_element*] The BIT STRING element
 * containing the DER encoded ECDSA signature value.
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
