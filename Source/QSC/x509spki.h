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
 * \file x509spki.h
 * \brief X.509 AlgorithmIdentifier and SubjectPublicKeyInfo decoding, initialization, and validation interface.
 *
 * \details
 * This header defines helper functions used to decode, initialize, validate,
 * and query X.509 AlgorithmIdentifier and SubjectPublicKeyInfo objects. The
 * interface supports classical elliptic-curve public keys together with
 * post-quantum ML-DSA and ML-KEM parameter sets carried through OID-driven
 * algorithm identifiers and raw public-key payloads.
 *
 * The decoding functions operate on ASN.1 BER/DER elements and populate the
 * normalized X.509 type-layer structures. The initialization functions provide
 * canonical construction helpers for EC, ML-DSA, and ML-KEM SPKI objects.
 * Additional query helpers expose named-curve coordinate sizing, public-key
 * sizing, algorithm classification, and coordinate extraction for uncompressed
 * EC points.
 */

/*!
 * \brief Decode an AlgorithmIdentifier object.
 *
 * \details
 * Parses an ASN.1 DER encoded AlgorithmIdentifier sequence and populates the
 * normalized qsc_x509_algorithm_identifier structure.
 *
 * \param element: [const][struct] The ASN.1 element containing the AlgorithmIdentifier sequence.
 * \param algorithm: [struct] The destination algorithm identifier object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_algorithm_identifier_decode(const qsc_encoding_ber_element* element, qsc_x509_algorithm_identifier* algorithm);


/*!
 * brief Validate a normalized AlgorithmIdentifier object.
 *
 * \details
 * Performs strict OID-driven validation of an AlgorithmIdentifier, including
 * parameter presence or absence rules, named-curve consistency, and ML-DSA or
 * ML-KEM parameter-set consistency. This helper is intended for callers that
 * need to validate decoded algorithm metadata independently of a full SPKI
 * decode.
 *
 * \param algorithm: [const][struct] The algorithm identifier object to validate.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_algorithm_identifier_validate(const qsc_x509_algorithm_identifier* algorithm);

/*!
 * \brief Decode a SubjectPublicKeyInfo object.
 *
 * \details
 * Parses an ASN.1 DER encoded SubjectPublicKeyInfo sequence and populates the
 * normalized qsc_x509_subject_public_key_info structure with the decoded
 * algorithm identifier and subject public key bytes.
 *
 * \param element: [const][struct] The ASN.1 element containing the SubjectPublicKeyInfo sequence.
 * \param spki: [struct] The destination subject public key information object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_subject_public_key_info_decode(const qsc_encoding_ber_element* element, qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Validate a normalized SubjectPublicKeyInfo object.
 *
 * \details
 * Performs structural and algorithm-specific validation of the supplied SPKI
 * object, including parameter-set and public-key size consistency checks where
 * applicable.
 *
 * \param spki: [const][struct] The subject public key information object to validate.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_spki_validate(const qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Test whether an SPKI contains an uncompressed EC point.
 *
 * \details
 * Evaluates the subject public key payload and associated algorithm metadata to
 * determine whether the encoded elliptic-curve public key uses the standard
 * uncompressed point format.
 *
 * \param spki: [const][struct] The subject public key information object to inspect.
 *
 * \return Returns true if the SPKI contains an uncompressed EC point; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_spki_is_uncompressed_ec_point(const qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Get the coordinate size for a named elliptic curve.
 *
 * \details
 * Returns the coordinate width in bytes for the supplied named curve. This
 * helper is used when validating or extracting affine coordinates from EC
 * public keys.
 *
 * \param curve: [enum] The named elliptic curve identifier.
 *
 * \return Returns the coordinate size in bytes, or zero if the curve is unsupported.
 */
QSC_EXPORT_API size_t qsc_x509_named_curve_coordinate_size(qsc_x509_named_curve curve);

/*!
 * \brief Get the encoded public-key size for a named elliptic curve.
 *
 * \details
 * Returns the expected byte length of an uncompressed EC public key for the
 * supplied named curve.
 *
 * \param curve: [enum] The named elliptic curve identifier.
 *
 * \return Returns the encoded public-key size in bytes, or zero if the curve is unsupported.
 */
QSC_EXPORT_API size_t qsc_x509_named_curve_public_key_size(qsc_x509_named_curve curve);

/*!
 * \brief Extract affine EC coordinates from an SPKI object.
 *
 * \details
 * Reads the uncompressed elliptic-curve public-key payload from the supplied
 * SPKI object and writes the affine x and y coordinates to the caller-supplied
 * output buffers.
 *
 * \param spki: [const][struct] The subject public key information object containing the EC public key.
 * \param x: The destination buffer receiving the x-coordinate bytes.
 * \param xlen: The capacity of the x-coordinate buffer in bytes.
 * \param y: The destination buffer receiving the y-coordinate bytes.
 * \param ylen: The capacity of the y-coordinate buffer in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_spki_get_ec_coordinates(const qsc_x509_subject_public_key_info* spki, uint8_t* x, size_t xlen, uint8_t* y, size_t ylen);

/*!
 * \brief Initialize an AlgorithmIdentifier object.
 *
 * \details
 * Resets the supplied algorithm identifier object to a clean default state.
 *
 * \param algorithm: [struct] The algorithm identifier object to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_algorithm_identifier_initialize(qsc_x509_algorithm_identifier* algorithm);

/*!
 * \brief Initialize a SubjectPublicKeyInfo object.
 *
 * \details
 * Resets the supplied subject public key information object to a clean default
 * state.
 *
 * \param spki: [struct] The subject public key information object to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_subject_public_key_info_initialize(qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Get the expected public-key size for a PQC parameter set.
 *
 * \details
 * Returns the implementation-defined public-key size associated with the
 * supplied ML-DSA or ML-KEM parameter set.
 *
 * \param parameterset: [enum] The post-quantum parameter-set identifier.
 *
 * \return Returns the expected public-key size in bytes, or zero if the parameter set is unsupported.
 */
QSC_EXPORT_API size_t qsc_x509_pqc_public_key_size(qsc_x509_pqc_parameter_set parameterset);

/*!
 * \brief Test whether an AlgorithmIdentifier denotes ML-DSA.
 *
 * \details
 * Examines the object identifier and parameter-set metadata in the supplied
 * algorithm identifier and reports whether it represents an ML-DSA algorithm.
 *
 * \param algorithm: [const][struct] The algorithm identifier to inspect.
 *
 * \return Returns true if the algorithm identifier represents ML-DSA; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_algorithm_identifier_is_mldsa(const qsc_x509_algorithm_identifier* algorithm);

/*!
 * \brief Test whether an AlgorithmIdentifier denotes ML-KEM.
 *
 * \details
 * Examines the object identifier and parameter-set metadata in the supplied
 * algorithm identifier and reports whether it represents an ML-KEM algorithm.
 *
 * \param algorithm: [const][struct] The algorithm identifier to inspect.
 *
 * \return Returns true if the algorithm identifier represents ML-KEM; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_algorithm_identifier_is_mlkem(const qsc_x509_algorithm_identifier* algorithm);

/*!
 * \brief Initialize an AlgorithmIdentifier for ML-DSA.
 *
 * \details
 * Populates the supplied algorithm identifier object with the OID and
 * parameter-set metadata corresponding to the selected ML-DSA parameter set.
 *
 * \param algorithm: [struct] The algorithm identifier object to initialize.
 * \param parameterset: [enum] The ML-DSA parameter-set identifier.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_algorithm_identifier_initialize_mldsa(qsc_x509_algorithm_identifier* algorithm, qsc_x509_pqc_parameter_set parameterset);

/*!
 * \brief Initialize an AlgorithmIdentifier for ML-KEM.
 *
 * \details
 * Populates the supplied algorithm identifier object with the OID and
 * parameter-set metadata corresponding to the selected ML-KEM parameter set.
 *
 * \param algorithm: [struct] The algorithm identifier object to initialize.
 * \param parameterset: [enum] The ML-KEM parameter-set identifier.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_algorithm_identifier_initialize_mlkem(qsc_x509_algorithm_identifier* algorithm, qsc_x509_pqc_parameter_set parameterset);

/*!
 * \brief Initialize an SPKI object for an elliptic-curve public key.
 *
 * \details
 * Populates the supplied SubjectPublicKeyInfo object using the selected named
 * curve and the supplied EC public-key bytes.
 *
 * \param spki: [struct] The destination subject public key information object.
 * \param curve: [enum] The named elliptic curve identifier.
 * \param publickey: [const] The raw encoded EC public-key bytes.
 * \param publickeylen: The length of the public key in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_spki_initialize_ec(qsc_x509_subject_public_key_info* spki, qsc_x509_named_curve curve, const uint8_t* publickey, size_t publickeylen);

/*!
 * \brief Initialize an SPKI object for an ML-DSA public key.
 *
 * \details
 * Populates the supplied SubjectPublicKeyInfo object using the selected
 * ML-DSA parameter set and the supplied public-key bytes. This helper accepts
 * only the ML-DSA parameter set supported by the current build.
 *
 * \param spki: [struct] The destination subject public key information object.
 * \param parameterset: [enum] The ML-DSA parameter-set identifier.
 * \param publickey: [const] The raw ML-DSA public-key bytes.
 * \param publickeylen: The length of the public key in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_spki_initialize_ml_dsa(qsc_x509_subject_public_key_info* spki, qsc_x509_pqc_parameter_set parameterset, const uint8_t* publickey, size_t publickeylen);

/*!
 * \brief Initialize an SPKI object for an ML-KEM public key.
 *
 * \details
 * Populates the supplied SubjectPublicKeyInfo object using the selected
 * ML-KEM parameter set and the supplied public-key bytes. This helper accepts
 * only the ML-KEM parameter set supported by the current build.
 *
 * \param spki: [struct] The destination subject public key information object.
 * \param parameterset: [enum] The ML-KEM parameter-set identifier.
 * \param publickey: [const] The raw ML-KEM public-key bytes.
 * \param publickeylen: The length of the public key in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_spki_initialize_ml_kem(qsc_x509_subject_public_key_info* spki, qsc_x509_pqc_parameter_set parameterset, const uint8_t* publickey, size_t publickeylen);

QSC_CPLUSPLUS_ENABLED_END

#endif
