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

#ifndef QSC_X509_WRITE_H
#define QSC_X509_WRITE_H

#include "qsccommon.h"
#include "x509crl.h"
#include "x509crlwrite.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509write.h
 * \brief ASN.1 DER writing helpers for X.509 primitive values, composite objects, SPKI objects, and extension payloads.
 *
 * \details
 * This header defines the low-level encoding interface used to serialize ASN.1
 * DER objects required by the X.509 writer layer. The routines in this layer
 * emit DER definite-length encodings only and reject malformed parameter
 * combinations that would produce non-canonical output. The functions declared here
 * support primitive TLV emission, construction of common ASN.1 string and time
 * types, explicit and raw tagged-object encoding, and serialization of
 * normalized X.509 structures such as AlgorithmIdentifier, Name, Validity,
 * GeneralName, SubjectPublicKeyInfo, Extension, and Extensions. When an
 * output buffer is not supplied, or when the supplied buffer is too small, the
 * encoder updates \p outputlen with the required DER size and returns
 * QSC_ASN1_STATUS_BUFFER_TOO_SMALL. This enables a consistent two-pass sizing
 * and encoding pattern across the writer interface.
 *
 * The interface also provides specialized helpers for writing public-key
 * algorithm identifiers, elliptic-curve and post-quantum SubjectPublicKeyInfo
 * objects, and commonly used certificate extension payloads.
 */

/*!
 * \brief Write an ASN.1 DER length field.
 *
 * \details
 * Encodes the supplied content length using DER definite-length form and writes
 * the result to the output buffer.
 *
 * \param length: The content length to encode.
 * \param output: The destination buffer receiving the encoded length field.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_length(size_t length, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER tag field.
 *
 * \details
 * Encodes the supplied tag class, constructed flag, and tag number as a DER
 * tag field and writes the result to the output buffer.
 *
 * \param tagclass: The ASN.1 tag class.
 * \param constructed: Indicates whether the encoded object is constructed.
 * \param tagnumber: The ASN.1 tag number.
 * \param output: The destination buffer receiving the encoded tag field.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_tag(uint8_t tagclass, bool constructed, uint32_t tagnumber, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER INTEGER object.
 *
 * \details
 * Encodes the supplied integer value bytes as a DER INTEGER object.
 *
 * \param value: [const] The integer value bytes in big-endian form.
 * \param valuelen: The length of the integer value in bytes.
 * \param output: The destination buffer receiving the DER INTEGER object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_integer(const uint8_t* value, size_t valuelen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER BOOLEAN object.
 *
 * \param value: The boolean value to encode.
 * \param output: The destination buffer receiving the DER BOOLEAN object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_boolean(bool value, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER NULL object.
 *
 * \param output: The destination buffer receiving the DER NULL object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_null(uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER OBJECT IDENTIFIER object.
 *
 * \param oid: [const][struct] The object identifier to encode.
 * \param output: The destination buffer receiving the DER OBJECT IDENTIFIER object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_oid(const qsc_asn1_oid* oid, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER OCTET STRING object.
 *
 * \param value: [const] The octet-string contents.
 * \param valuelen: The length of the octet-string contents in bytes.
 * \param output: The destination buffer receiving the DER OCTET STRING object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_octet_string(const uint8_t* value, size_t valuelen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER BIT STRING object.
 *
 * \details
 * Encodes the supplied bit-string contents together with the number of unused
 * bits in the final content octet.
 *
 * \param value: [const] The bit-string contents.
 * \param valuelen: The length of the bit-string contents in bytes.
 * \param unusedbits: The number of unused bits in the final content octet.
 * \param output: The destination buffer receiving the DER BIT STRING object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_bit_string(const uint8_t* value, size_t valuelen, uint8_t unusedbits, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER UTF8String object.
 *
 * \param value: [const] The UTF-8 string bytes.
 * \param valuelen: The length of the string in bytes.
 * \param output: The destination buffer receiving the DER UTF8String object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_utf8_string(const char* value, size_t valuelen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER PrintableString object.
 *
 * \param value: [const] The PrintableString bytes.
 * \param valuelen: The length of the string in bytes.
 * \param output: The destination buffer receiving the DER PrintableString object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_printable_string(const char* value, size_t valuelen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER IA5String object.
 *
 * \param value: [const] The IA5String bytes.
 * \param valuelen: The length of the string in bytes.
 * \param output: The destination buffer receiving the DER IA5String object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_ia5_string(const char* value, size_t valuelen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER UTCTime object.
 *
 * \param value: [const][struct] The time value to encode.
 * \param output: The destination buffer receiving the DER UTCTime object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_utctime(const qsc_asn1_time* value, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER GeneralizedTime object.
 *
 * \param value: [const][struct] The time value to encode.
 * \param output: The destination buffer receiving the DER GeneralizedTime object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_generalized_time(const qsc_asn1_time* value, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER SEQUENCE object from pre-encoded contents.
 *
 * \param content: [const] The pre-encoded content bytes.
 * \param contentlen: The length of the content in bytes.
 * \param output: The destination buffer receiving the DER SEQUENCE object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_sequence(const uint8_t* content, size_t contentlen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ASN.1 DER SET object from pre-encoded contents.
 *
 * \param content: [const] The pre-encoded content bytes.
 * \param contentlen: The length of the content in bytes.
 * \param output: The destination buffer receiving the DER SET object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_set(const uint8_t* content, size_t contentlen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an explicitly tagged ASN.1 DER object from pre-encoded contents.
 *
 * \param tagnumber: The explicit context-specific tag number.
 * \param content: [const] The pre-encoded inner contents.
 * \param contentlen: The length of the inner contents in bytes.
 * \param output: The destination buffer receiving the explicitly tagged object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_explicit(uint32_t tagnumber, const uint8_t* content, size_t contentlen, 
	uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a raw ASN.1 DER object from tag metadata and pre-encoded contents.
 *
 * \param tagclass: The ASN.1 tag class.
 * \param constructed: Indicates whether the encoded object is constructed.
 * \param tagnumber: The ASN.1 tag number.
 * \param content: [const] The pre-encoded content bytes.
 * \param contentlen: The length of the content in bytes.
 * \param output: The destination buffer receiving the encoded object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_raw(uint8_t tagclass, bool constructed, uint32_t tagnumber, 
	const uint8_t* content, size_t contentlen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an AlgorithmIdentifier object for a signature algorithm.
 *
 * \details
 * Encodes the canonical AlgorithmIdentifier corresponding to the supplied
 * normalized X.509 signature algorithm selector.
 *
 * \param signature: [enum] The signature algorithm selector.
 * \param output: The destination buffer receiving the DER AlgorithmIdentifier object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_algorithm_identifier_for_signature(qsc_x509_signature_algorithm signature,
	uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an AlgorithmIdentifier object for a public-key algorithm.
 *
 * \details
 * Encodes the canonical AlgorithmIdentifier corresponding to the supplied
 * public-key algorithm selector and associated curve or PQC parameter set.
 *
 * \param publickey: [enum] The public-key algorithm selector.
 * \param curve: [enum] The named elliptic curve when applicable.
 * \param pqcparameter: [enum] The post-quantum parameter set when applicable.
 * \param output: The destination buffer receiving the DER AlgorithmIdentifier object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_algorithm_identifier_for_public_key(qsc_x509_public_key_algorithm publickey, 
	qsc_x509_named_curve curve, qsc_x509_pqc_parameter_set pqcparameter, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an elliptic-curve SubjectPublicKeyInfo object.
 *
 * \param curve: [enum] The named elliptic curve identifier.
 * \param publickey: [const] The encoded EC public-key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param output: The destination buffer receiving the DER SubjectPublicKeyInfo object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_spki_ec(qsc_x509_named_curve curve, const uint8_t* publickey,
	size_t publickeylen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ML-DSA SubjectPublicKeyInfo object.
 *
 * \param parameterset: [enum] The ML-DSA parameter-set identifier.
 * \param publickey: [const] The ML-DSA public-key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param output: The destination buffer receiving the DER SubjectPublicKeyInfo object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_spki_ml_dsa(qsc_x509_pqc_parameter_set parameterset, 
	const uint8_t* publickey, size_t publickeylen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ML-KEM SubjectPublicKeyInfo object.
 *
 * \param parameterset: [enum] The ML-KEM parameter-set identifier.
 * \param publickey: [const] The ML-KEM public-key bytes.
 * \param publickeylen: The length of the public key in bytes.
 * \param output: The destination buffer receiving the DER SubjectPublicKeyInfo object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_spki_ml_kem(qsc_x509_pqc_parameter_set parameterset, const uint8_t* publickey, 
	size_t publickeylen, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a normalized AlgorithmIdentifier object.
 *
 * \param algorithm: [const][struct] The algorithm identifier to encode.
 * \param output: The destination buffer receiving the DER AlgorithmIdentifier object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_algorithm_identifier(const qsc_x509_algorithm_identifier* algorithm, 
	uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a normalized X.509 Name object.
 *
 * \param name: [const][struct] The distinguished name to encode.
 * \param output: The destination buffer receiving the DER Name object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_name(const qsc_x509_name* name, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a normalized X.509 Validity object.
 *
 * \param validity: [const][struct] The validity interval to encode.
 * \param output: The destination buffer receiving the DER Validity object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_validity(const qsc_x509_validity* validity, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a normalized GeneralName object.
 *
 * \param name: [const][struct] The general name to encode.
 * \param output: The destination buffer receiving the DER GeneralName object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_general_name(const qsc_x509_general_name* name, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a normalized SubjectPublicKeyInfo object.
 *
 * \param spki: [const][struct] The subject public key information object to encode.
 * \param output: The destination buffer receiving the DER SubjectPublicKeyInfo object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_spki(const qsc_x509_subject_public_key_info* spki, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a normalized X.509 Extension object.
 *
 * \param extension: [const][struct] The extension object to encode.
 * \param output: The destination buffer receiving the DER Extension object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_extension(const qsc_x509_extension* extension, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a normalized Extensions collection.
 *
 * \param extensions: [const][struct] The extension set to encode.
 * \param output: The destination buffer receiving the DER Extensions object.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_extensions(const qsc_x509_extensions* extensions, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a BasicConstraints extension payload.
 *
 * \param basicconstraints: [const][struct] The Basic Constraints value to encode.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_basic_constraints(const qsc_x509_basic_constraints* basicconstraints, 
	uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a KeyUsage extension payload.
 *
 * \param keyusage: [const][struct] The Key Usage value to encode.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_key_usage(const qsc_x509_key_usage* keyusage, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an ExtendedKeyUsage extension payload.
 *
 * \param extendedkeyusage: [const][struct] The Extended Key Usage value to encode.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_extended_key_usage(const qsc_x509_extended_key_usage* extendedkeyusage, 
	uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a SubjectKeyIdentifier extension payload.
 *
 * \param subjectkeyidentifier: [const][struct] The Subject Key Identifier value to encode.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_subject_key_identifier(const qsc_x509_subject_key_identifier* subjectkeyidentifier, 
	uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an AuthorityKeyIdentifier extension payload.
 *
 * \param authoritykeyidentifier: [const][struct] The Authority Key Identifier value to encode.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_authority_key_identifier(const qsc_x509_authority_key_identifier* authoritykeyidentifier, 
	uint8_t* output, size_t* outputlen);

/*!
 * \brief Write a SubjectAltName extension payload.
 *
 * \param subjectaltname: [const][struct] The Subject Alternative Name value to encode.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_subject_alt_name(const qsc_x509_subject_alt_name* subjectaltname, uint8_t* output, size_t* outputlen);

/*!
 * \brief Write an IssuerAltName extension payload.
 *
 * \param issueraltname: [const][struct] The Issuer Alternative Name value to encode.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_write_issuer_alt_name(const qsc_x509_issuer_alt_name* issueraltname, uint8_t* output, size_t* outputlen);
/**
 * \brief Sets the Authority Key Identifier (AKI) extension in the CRL builder.
 *
 * \details
 * This function assigns a fully populated Authority Key Identifier structure to the CRL builder.
 * The AKI extension identifies the public key corresponding to the private key used to sign the CRL,
 * and is typically derived from the issuer certificate. When present, it enables relying parties to
 * match the CRL to the correct issuer certificate during validation.
 *
 * The provided structure must be fully initialized by the caller. At minimum, the key identifier
 * field should be present and contain the issuer's key identifier. Optional fields such as issuer
 * name and serial number may also be included if required.
 *
 * If this function is not called, and no AKI is otherwise set, the CRL will be generated without
 * an Authority Key Identifier extension.
 *
 * \param builder:                 [struct] Pointer to the CRL builder instance.
 * \param authoritykeyidentifier:  [const struct] Pointer to a populated AKI structure.
 *
 * \return Returns QSC_ASN1_STATUS_SUCCESS on success or QSC_ASN1_STATUS_INVALID_INPUT if parameters are invalid.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_set_authority_key_identifier(qsc_x509_crl_builder* builder, const qsc_x509_authority_key_identifier* authoritykeyidentifier);

/**
 * \brief Sets the CRL Number extension in the CRL builder.
 *
 * \details
 * This function assigns a CRL Number extension to the CRL builder. The CRL Number is a monotonically
 * increasing integer used to identify and order CRLs issued by a given authority. It is encoded as a
 * DER INTEGER within the extension value.
 *
 * The caller provides the CRL number as a big-endian byte array. The value is normalized during
 * encoding to ensure proper ASN.1 INTEGER representation, including removal of leading zeros and
 * insertion of a leading 0x00 byte if required to enforce a positive integer.
 *
 * The \p critical flag determines whether the extension is marked critical in the CRL. In most
 * deployments, CRL Number is non-critical.
 *
 * If this function is not called, the CRL will be generated without a CRL Number extension.
 *
 * \param builder:   [struct] Pointer to the CRL builder instance.
 * \param value:     [const] Pointer to the big-endian CRL number byte array.
 * \param valuelen:  [size_t] Length of the CRL number in bytes.
 * \param critical:  [bool] Set to true to mark the extension as critical.
 *
 * \return Returns QSC_ASN1_STATUS_SUCCESS on success, QSC_ASN1_STATUS_INVALID_INPUT if parameters are invalid, 
 * QSC_ASN1_STATUS_OUT_OF_RANGE if the value length exceeds supported limits.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_set_crl_number(qsc_x509_crl_builder* builder, const uint8_t* value, size_t valuelen, bool critical);

/**
 * \brief Computes the Authority Key Identifier (AKI) from an issuer certificate.
 *
 * \details
 * This function derives an Authority Key Identifier structure from the provided issuer certificate.
 * The AKI is constructed according to standard X.509 practices:
 *
 * - If the issuer certificate contains a Subject Key Identifier (SKI) extension, that value is used
 *   directly as the key identifier.
 * - If no SKI is present, the key identifier is derived from the issuer's Subject Public Key
 *   Information (SPKI), typically using a SHA-1 hash over the public key bit string as specified
 *   in RFC 5280.
 *
 * The resulting structure is fully populated with the key identifier and marked as present. The
 * caller may then pass the result to
 * qsc_x509_crl_builder_set_authority_key_identifier() to include the extension in a CRL.
 *
 * This function does not modify the CRL builder directly.
 *
 * \param issuer:                   [const struct] Pointer to the issuer certificate.
 * \param authoritykeyidentifier:  [struct] Pointer to the output AKI structure.
 *
 * \return Returns QSC_ASN1_STATUS_SUCCESS on success, QSC_ASN1_STATUS_INVALID_INPUT if parameters are invalid
 *  or QSC_ASN1_STATUS_FAILURE if AKI derivation fails.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_compute_authority_key_identifier_from_issuer(const qsc_x509_certificate* issuer, qsc_x509_authority_key_identifier* authoritykeyidentifier);

QSC_CPLUSPLUS_ENABLED_END

#endif
