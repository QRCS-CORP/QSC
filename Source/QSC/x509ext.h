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

#ifndef QSC_X509_EXT_H
#define QSC_X509_EXT_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * brief Initialize a normalized extension entry.
 *
 * \param ext: [struct] The extension object to initialize.
 */
QSC_EXPORT_API void qsc_x509_extension_initialize(qsc_x509_extension* ext);

/*!
 * brief Initialize a normalized extension set.
 *
 * \param extensions: [struct] The extension set object to initialize.
 */
QSC_EXPORT_API void qsc_x509_extensions_initialize(qsc_x509_extensions* extensions);

/*!
 * brief Validate a normalized extension entry.
 *
 * \details
 * Performs structural and payload-adjacent validation on a decoded extension
 * entry. This routine does not replace object-level certificate, CSR, or CRL
 * policy validation, but it rejects malformed critical fields, missing
 * extnValue content, and inconsistent normalized state.
 *
 * \param ext: [const][struct] The decoded extension entry.
 *
 * 
eturn [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_extension_validate(const qsc_x509_extension* ext);

/*!
 * brief Validate a normalized extension set.
 *
 * \details
 * Performs set-level structural checks such as duplicate extension rejection
 * and consistency checks across already-decoded typed extension state.
 *
 * \param extensions: [const][struct] The decoded extension set.
 *
 * 
eturn [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_extensions_validate(const qsc_x509_extensions* extensions);

/*!
 * \file x509ext.h
 * \brief X.509 certificate extension decoding, encoding, representation, and query interface.
 *
 * \details
 * This header defines the public interface used to decode, encode, represent,
 * and query X.509 certificate extensions. Extensions are carried in the
 * TBSCertificate extensions field as DER encoded Extension sequences identified
 * by object identifiers. The interface normalizes outer Extension objects into
 * qsc_x509_extension and qsc_x509_extensions containers and provides typed
 * decoders and encoders for commonly used extension payloads.
 *
 * Supported typed extension payloads include Basic Constraints, Key Usage,
 * Extended Key Usage, Subject Key Identifier, Authority Key Identifier,
 * Subject Alternative Name, and Issuer Alternative Name. Unknown or otherwise
 * unsupported extensions may still be preserved in normalized form through the
 * generic extension containers defined in the X.509 type layer.
 *
 * The decoder interface expects extension payload decoding functions to receive
 * the contents of the extnValue OCTET STRING, not the full outer Extension
 * sequence. The encoder interface produces DER payloads suitable for placement
 * inside an Extension extnValue OCTET STRING by the surrounding certificate or
 * CSR writer.
 */

/*!
 * \brief Decode a single X.509 Extension sequence.
 *
 * \details
 * Parses an ASN.1 DER encoded Extension object and converts it to the
 * normalized qsc_x509_extension representation. The decoded extension includes
 * the extension object identifier, the optional critical flag, and the raw
 * extnValue OCTET STRING contents.
 *
 * The ASN.1 definition is:
 *
 * Extension ::= SEQUENCE {
 *     extnID      OBJECT IDENTIFIER,
 *     critical    BOOLEAN DEFAULT FALSE,
 *     extnValue   OCTET STRING
 * }
 *
 * This function does not interpret the inner extnValue payload beyond
 * extracting it from the outer OCTET STRING wrapper. Typed interpretation is
 * performed by the extension-specific decode routines declared below.
 *
 * \param element: [const][struct] The ASN.1 sequence element containing the encoded Extension structure.
 * \param ext: [struct] The destination normalized extension object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_extension_decode(const qsc_encoding_ber_element* element, qsc_x509_extension* ext);

/*!
 * \brief Decode an X.509 Extensions sequence.
 *
 * \details
 * Parses an ASN.1 Extensions container and decodes each contained Extension
 * entry into the normalized qsc_x509_extensions output structure.
 *
 * The ASN.1 definition is:
 *
 * Extensions ::= SEQUENCE OF Extension
 *
 * Each entry is first normalized by qsc_x509_extension_decode. Typed payload
 * interpretation, when required, is then performed separately by the
 * extension-specific decode functions.
 *
 * \param element: [const][struct] The ASN.1 sequence element containing the Extensions collection.
 * \param extensions: [struct] The destination normalized extension set.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_extensions_decode(const qsc_encoding_ber_element* element, qsc_x509_extensions* extensions);

/*!
 * \brief Decode a BasicConstraints extension payload.
 *
 * \details
 * Parses the DER encoded extnValue contents of a BasicConstraints extension and
 * writes the result to the supplied qsc_x509_basic_constraints structure.
 *
 * The ASN.1 definition is:
 *
 * BasicConstraints ::= SEQUENCE {
 *     cA                BOOLEAN DEFAULT FALSE,
 *     pathLenConstraint INTEGER OPTIONAL
 * }
 *
 * The cA field indicates whether the subject may act as a certification
 * authority. The optional pathLenConstraint limits the number of non-self-issued
 * CA certificates that may follow this certificate in a certification path.
 *
 * \param data: [const] The DER encoded BasicConstraints payload.
 * \param datalen: The length of the encoded payload in bytes.
 * \param bc: [struct] The destination Basic Constraints object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_basic_constraints_decode(const uint8_t* data, size_t datalen, qsc_x509_basic_constraints* bc);

/*!
 * \brief Decode a KeyUsage extension payload.
 *
 * \details
 * Parses the DER encoded extnValue contents of a KeyUsage extension and
 * converts the BIT STRING representation into the implementation-defined usage
 * mask stored in the caller supplied output variable.
 *
 * The ASN.1 definition is:
 *
 * KeyUsage ::= BIT STRING
 *
 * \param data: [const] The DER encoded KeyUsage payload.
 * \param datalen: The length of the encoded payload in bytes.
 * \param usage: The destination usage bit mask.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_key_usage_decode(const uint8_t* data, size_t datalen, uint16_t* usage);

/*!
 * \brief Decode an ExtendedKeyUsage extension payload.
 *
 * \details
 * Parses the DER encoded extnValue contents of an ExtendedKeyUsage extension
 * and records the contained key purpose identifiers.
 *
 * The ASN.1 definition is:
 *
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 *
 * \param data: [const] The DER encoded Extended Key Usage payload.
 * \param datalen: The length of the encoded payload in bytes.
 * \param eku: [struct] The destination Extended Key Usage object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_extended_key_usage_decode(const uint8_t* data, size_t datalen, qsc_x509_extended_key_usage* eku);

/*!
 * \brief Decode a SubjectKeyIdentifier extension payload.
 *
 * \details
 * Parses the DER encoded extnValue contents of a SubjectKeyIdentifier extension
 * and copies the identifier bytes to the supplied output structure.
 *
 * The ASN.1 definition is:
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 *
 * \param data: [const] The DER encoded Subject Key Identifier payload.
 * \param datalen: The length of the encoded payload in bytes.
 * \param ski: [struct] The destination Subject Key Identifier object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_subject_key_identifier_decode(const uint8_t* data, size_t datalen, qsc_x509_subject_key_identifier* ski);

/*!
 * \brief Decode an AuthorityKeyIdentifier extension payload.
 *
 * \details
 * Parses the DER encoded extnValue contents of an AuthorityKeyIdentifier
 * extension and extracts the supported authority key identifier fields.
 *
 * The ASN.1 definition is:
 *
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
 * }
 *
 * \param data: [const] The DER encoded Authority Key Identifier payload.
 * \param datalen: The length of the encoded payload in bytes.
 * \param aki: [struct] The destination Authority Key Identifier object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_authority_key_identifier_decode(const uint8_t* data, size_t datalen, qsc_x509_authority_key_identifier* aki);

/*!
 * \brief Encode a BasicConstraints extension payload.
 *
 * \details
 * Serializes a qsc_x509_basic_constraints object into the DER representation of
 * a BasicConstraints extension payload suitable for placement inside extnValue.
 *
 * \param bc: [const][struct] The source Basic Constraints object.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_basic_constraints_encode(const qsc_x509_basic_constraints* bc, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode a KeyUsage extension payload.
 *
 * \details
 * Serializes a qsc_x509_key_usage object into the DER representation of a
 * KeyUsage extension payload.
 *
 * \param keyusage: [const][struct] The source Key Usage object.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_key_usage_encode(const qsc_x509_key_usage* keyusage, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode an ExtendedKeyUsage extension payload.
 *
 * \details
 * Serializes a qsc_x509_extended_key_usage object into the DER representation
 * of an ExtendedKeyUsage extension payload.
 *
 * \param eku: [const][struct] The source Extended Key Usage object.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_extended_key_usage_encode(const qsc_x509_extended_key_usage* eku, uint8_t* output, size_t* outputlen);

/*!
 * \brief Test whether an Extended Key Usage set contains a requested usage bit.
 *
 * \details
 * Evaluates the supplied implementation-defined bit mask against the decoded
 * or constructed Extended Key Usage object and reports whether the requested
 * usage is present.
 *
 * \param eku: [const][struct] The Extended Key Usage object to inspect.
 * \param bitmask: The implementation-defined usage bit mask to test.
 *
 * \return Returns true if the requested usage is present; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_ext_has_eku(const qsc_x509_extended_key_usage* eku, uint32_t bitmask);

/*!
 * \brief Encode a SubjectKeyIdentifier extension payload.
 *
 * \details
 * Serializes a qsc_x509_subject_key_identifier object into the DER
 * representation of a SubjectKeyIdentifier extension payload.
 *
 * \param ski: [const][struct] The source Subject Key Identifier object.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_subject_key_identifier_encode(const qsc_x509_subject_key_identifier* ski, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode an AuthorityKeyIdentifier extension payload.
 *
 * \details
 * Serializes a qsc_x509_authority_key_identifier object into the DER
 * representation of an AuthorityKeyIdentifier extension payload.
 *
 * \param aki: [const][struct] The source Authority Key Identifier object.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_authority_key_identifier_encode(const qsc_x509_authority_key_identifier* aki, uint8_t* output, size_t* outputlen);

/*!
 * \brief Decode a SubjectAltName extension payload.
 *
 * \details
 * Parses the DER encoded extnValue contents of a Subject Alternative Name
 * extension and records the supported GeneralName entries.
 *
 * \param data: [const] The DER encoded Subject Alternative Name payload.
 * \param datalen: The length of the encoded payload in bytes.
 * \param san: [struct] The destination Subject Alternative Name object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_subject_alt_name_decode(const uint8_t* data, size_t datalen, qsc_x509_subject_alt_name* san);

/*!
 * \brief Encode a SubjectAltName extension payload.
 *
 * \details
 * Serializes a qsc_x509_subject_alt_name object into the DER representation of
 * a Subject Alternative Name extension payload.
 *
 * \param san: [const][struct] The source Subject Alternative Name object.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_subject_alt_name_encode(const qsc_x509_subject_alt_name* san, uint8_t* output, size_t* outputlen);

/*!
 * \brief Decode an IssuerAltName extension payload.
 *
 * \details
 * Parses the DER encoded extnValue contents of an Issuer Alternative Name
 * extension and records the supported GeneralName entries.
 *
 * \param data: [const] The DER encoded Issuer Alternative Name payload.
 * \param datalen: The length of the encoded payload in bytes.
 * \param ian: [struct] The destination Issuer Alternative Name object.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_issuer_alt_name_decode(const uint8_t* data, size_t datalen, qsc_x509_issuer_alt_name* ian);

/*!
 * \brief Encode an IssuerAltName extension payload.
 *
 * \details
 * Serializes a qsc_x509_issuer_alt_name object into the DER representation of
 * an Issuer Alternative Name extension payload.
 *
 * \param ian: [const][struct] The source Issuer Alternative Name object.
 * \param output: The destination buffer receiving the DER payload.
 * \param outputlen: The input capacity of the output buffer and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_issuer_alt_name_encode(const qsc_x509_issuer_alt_name* ian, uint8_t* output, size_t* outputlen);

/*!
 * \brief Add a DNS name entry to a Subject Alternative Name object.
 *
 * \details
 * Appends a dNSName GeneralName entry to the supplied Subject Alternative Name
 * container.
 *
 * \param san: [struct] The Subject Alternative Name object to update.
 * \param dnsname: [const] The DNS host name string.
 * \param dnsnamelen: The length of the DNS host name string in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_subject_alt_name_add_dns(qsc_x509_subject_alt_name* san, const char* dnsname, size_t dnsnamelen);

/*!
 * \brief Add an IP address entry to a Subject Alternative Name object.
 *
 * \details
 * Appends an iPAddress GeneralName entry to the supplied Subject Alternative
 * Name container.
 *
 * \param san: [struct] The Subject Alternative Name object to update.
 * \param address: [const] The binary IP address.
 * \param addresslen: The length of the binary IP address in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_subject_alt_name_add_ip(qsc_x509_subject_alt_name* san, const uint8_t* address, size_t addresslen);

QSC_CPLUSPLUS_ENABLED_END

#endif
