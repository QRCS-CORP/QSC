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
 * \file x509_ext.h
 * \brief X.509 certificate extension parsing and representation.
 *
 * \details
 * This module defines the structures and functions used to decode,
 * represent, and query X.509 certificate extensions. Extensions are
 * encoded in DER format within the TBSCertificate structure and are
 * identified by object identifiers (OIDs).
 *
 * The implementation parses extension values into strongly typed
 * containers for commonly used extensions, while preserving raw
 * extension data for unsupported or unknown extension types.
 *
 * Supported extensions include:
 *
 * - BasicConstraints
 * - KeyUsage
 * - ExtendedKeyUsage
 * - SubjectKeyIdentifier
 * - AuthorityKeyIdentifier
 * - SubjectAltName
 * - IssuerAltName
 *
 * The extension parser is strict and validates DER encoding and
 * extension structure during decoding.
 */

 /*!
  * \brief Decode a single X.509 Extension structure.
  *
  * \details
  * Parses an ASN.1 DER encoded Extension sequence and converts it to the
  * normalized qsc_x509_extension representation. An X.509 extension has
  * the form:
  *
  * Extension ::= SEQUENCE {
  *     extnID      OBJECT IDENTIFIER,
  *     critical    BOOLEAN DEFAULT FALSE,
  *     extnValue   OCTET STRING
  * }
  *
  * The function decodes the extension object identifier, the optional
  * critical flag, and the raw extension value octet string. The extnValue
  * field is not interpreted by this function beyond extraction from the
  * outer OCTET STRING container.
  *
  * This function is used when iterating the certificate Extensions
  * sequence and is the common entry point for all per-extension decoding.
  *
  * \param element: [const qsc_encoding_ber_element*] The ASN.1 SEQUENCE
  * element containing the encoded Extension structure.
  * \param ext: [qsc_x509_extension*] The output extension structure.
  *
  * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
  */
	QSC_EXPORT_API qsc_asn1_status qsc_x509_extension_decode(const qsc_encoding_ber_element* element, qsc_x509_extension* ext);

/*!
 * \brief Decode an X.509 Extensions sequence.
 *
 * \details
 * Parses the ASN.1 Extensions container and decodes each contained
 * Extension entry into the qsc_x509_extensions output structure.
 *
 * The ASN.1 definition is:
 *
 * Extensions ::= SEQUENCE OF Extension
 *
 * Each extension is decoded using qsc_x509_extension_decode. Supported
 * extensions may then be further interpreted by the extension-specific
 * decode functions defined in this module.
 *
 * \param element: [const qsc_encoding_ber_element*] The ASN.1 SEQUENCE
 * containing the Extensions collection.
 * \param extensions: [qsc_x509_extensions*] The output extension set.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_extensions_decode(const qsc_encoding_ber_element* element, qsc_x509_extensions* extensions);

/*!
 * \brief Decode the BasicConstraints extension value.
 *
 * \details
 * Parses the DER encoded extnValue contents of the BasicConstraints
 * extension and writes the decoded values to the output structure.
 *
 * The ASN.1 definition is:
 *
 * BasicConstraints ::= SEQUENCE {
 *     cA                      BOOLEAN DEFAULT FALSE,
 *     pathLenConstraint       INTEGER OPTIONAL
 * }
 *
 * The cA field indicates whether the certificate may act as a
 * certification authority. The optional pathLenConstraint limits the
 * number of non-self-issued CA certificates that may follow this
 * certificate in a certification path.
 *
 * The input data must point to the decoded contents of the extension
 * OCTET STRING, not the full outer Extension structure.
 *
 * \param data: [const uint8_t*] The DER encoded BasicConstraints value.
 * \param datalen: [size_t] The length of the encoded extension value in bytes.
 * \param bc: [qsc_x509_basic_constraints*] The output constraints structure.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_basic_constraints_decode(const uint8_t* data, size_t datalen, qsc_x509_basic_constraints* bc);

/*!
 * \brief Decode the KeyUsage extension value.
 *
 * \details
 * Parses the DER encoded extnValue contents of the KeyUsage extension
 * and converts the BIT STRING contents into the implementation-defined
 * usage bit mask.
 *
 * The ASN.1 definition is:
 *
 * KeyUsage ::= BIT STRING
 *
 * The resulting mask identifies the permitted public key usages, such
 * as digital signature, key encipherment, certificate signing, and CRL
 * signing.
 *
 * The input data must point to the decoded contents of the extension
 * OCTET STRING, not the full outer Extension structure.
 *
 * \param data: [const uint8_t*] The DER encoded KeyUsage value.
 * \param datalen: [size_t] The length of the encoded extension value in bytes.
 * \param usage: [uint16_t*] The output usage bit mask.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_key_usage_decode(const uint8_t* data, size_t datalen, uint16_t* usage);

/*!
 * \brief Decode the ExtendedKeyUsage extension value.
 *
 * \details
 * Parses the DER encoded extnValue contents of the ExtendedKeyUsage
 * extension and records the contained key purpose identifiers.
 *
 * The ASN.1 definition is:
 *
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 *
 * This extension restricts the purposes for which the certified public
 * key may be used, such as server authentication, client
 * authentication, code signing, or time stamping.
 *
 * The input data must point to the decoded contents of the extension
 * OCTET STRING, not the full outer Extension structure.
 *
 * \param data: [const uint8_t*] The DER encoded ExtendedKeyUsage value.
 * \param datalen: [size_t] The length of the encoded extension value in bytes.
 * \param eku: [qsc_x509_extended_key_usage*] The output EKU structure.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_extended_key_usage_decode(const uint8_t* data, size_t datalen, qsc_x509_extended_key_usage* eku);

/*!
 * \brief Decode the SubjectKeyIdentifier extension value.
 *
 * \details
 * Parses the DER encoded extnValue contents of the SubjectKeyIdentifier
 * extension and copies the contained key identifier bytes to the output
 * structure.
 *
 * The ASN.1 definition is:
 *
 * SubjectKeyIdentifier ::= OCTET STRING
 *
 * This identifier is typically derived from the subject public key and
 * is used to associate certificates and authority key identifiers
 * within a certification path.
 *
 * The input data must point to the decoded contents of the extension
 * OCTET STRING, not the full outer Extension structure.
 *
 * \param data: [const uint8_t*] The DER encoded SubjectKeyIdentifier value.
 * \param datalen: [size_t] The length of the encoded extension value in bytes.
 * \param ski: [qsc_x509_subject_key_identifier*] The output key identifier structure.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_subject_key_identifier_decode(const uint8_t* data, size_t datalen, qsc_x509_subject_key_identifier* ski);

/*!
 * \brief Decode the AuthorityKeyIdentifier extension value.
 *
 * \details
 * Parses the DER encoded extnValue contents of the
 * AuthorityKeyIdentifier extension and extracts the authority key
 * identifier fields supported by the implementation.
 *
 * The ASN.1 definition is:
 *
 * AuthorityKeyIdentifier ::= SEQUENCE {
 *     keyIdentifier             [0] KeyIdentifier           OPTIONAL,
 *     authorityCertIssuer       [1] GeneralNames            OPTIONAL,
 *     authorityCertSerialNumber [2] CertificateSerialNumber OPTIONAL
 * }
 *
 * This extension is used to identify the public key corresponding to
 * the private key that signed the certificate. It is commonly matched
 * against the SubjectKeyIdentifier of the issuer certificate.
 *
 * The input data must point to the decoded contents of the extension
 * OCTET STRING, not the full outer Extension structure.
 *
 * \param data: [const uint8_t*] The DER encoded AuthorityKeyIdentifier value.
 * \param datalen: [size_t] The length of the encoded extension value in bytes.
 * \param aki: [qsc_x509_authority_key_identifier*] The output authority key identifier structure.
 *
 * \return [qsc_asn1_status] Returns QSC_ASN1_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_ext_authority_key_identifier_decode(const uint8_t* data, size_t datalen, qsc_x509_authority_key_identifier* aki);

QSC_CPLUSPLUS_ENABLED_END

#endif
