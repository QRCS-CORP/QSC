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

#ifndef QSC_X509_CERTWRITE_H
#define QSC_X509_CERTWRITE_H

#include "qsccommon.h"
#include "x509cert.h"
#include "x509csr.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509certwrite.h
 * \brief X.509 certificate builder, issuance policy, signing, and PEM encoding interface.
 *
 * \details
 * This header exposes the public certificate construction interface used to assemble
 * a qsc_x509_certificate_builder instance and encode it as a TBSCertificate DER object
 * or as a complete signed X.509 certificate. The interface supports direct field-based
 * certificate construction, CSR-assisted issuance, extension filtering under issuer
 * policy, automatic issuer and key identifier derivation, profile application and
 * validation, and final PEM conversion of a DER-encoded certificate.
 *
 * The builder operates on externally defined X.509 object types declared in the
 * associated X.509 headers. Callers initialize a builder, populate mandatory and
 * optional certificate fields, optionally apply issuance policy or predefined profile
 * constraints, and then either encode the TBSCertificate or sign the certificate
 * through a caller-supplied signing callback.
 */

/*!
 * \def QSC_X509_CERT_ISSUANCE_PROPAGATE_SUBJECT_ALT_NAME
 * \brief Permit propagation of the Subject Alternative Name extension from a CSR.
 *
 * \details
 * When this policy flag is enabled, a requested Subject Alternative Name extension
 * contained in a certificate signing request may be copied into the certificate
 * builder during CSR-based issuance processing.
 */
#define QSC_X509_CERT_ISSUANCE_PROPAGATE_SUBJECT_ALT_NAME 0x00000001U

/*!
 * \def QSC_X509_CERT_ISSUANCE_PROPAGATE_EXTENDED_KEY_USAGE
 * \brief Permit propagation of the Extended Key Usage extension from a CSR.
 *
 * \details
 * When this policy flag is enabled, requested extended key purpose identifiers
 * present in a CSR may be transferred into the issued certificate.
 */
#define QSC_X509_CERT_ISSUANCE_PROPAGATE_EXTENDED_KEY_USAGE 0x00000002U

/*!
 * \def QSC_X509_CERT_ISSUANCE_PROPAGATE_SUBJECT_KEY_IDENTIFIER
 * \brief Permit propagation of a Subject Key Identifier from a CSR.
 *
 * \details
 * This flag allows an SKI requested in the CSR to be accepted during issuance.
 * In stricter issuance models, the issuer may instead compute and apply the
 * identifier independently.
 */
#define QSC_X509_CERT_ISSUANCE_PROPAGATE_SUBJECT_KEY_IDENTIFIER 0x00000004U

/*!
 * \def QSC_X509_CERT_ISSUANCE_PROPAGATE_UNKNOWN_NON_CRITICAL
 * \brief Permit propagation of unknown non-critical CSR extensions.
 *
 * \details
 * This flag relaxes extension filtering by allowing unrecognized extensions,
 * provided they are non-critical, to be copied from the CSR into the issued
 * certificate.
 */
#define QSC_X509_CERT_ISSUANCE_PROPAGATE_UNKNOWN_NON_CRITICAL 0x00000008U

/*!
 * \def QSC_X509_CERT_ISSUANCE_PROPAGATE_DEFAULT
 * \brief Default CSR extension propagation policy.
 *
 * \details
 * This macro combines the default allowed CSR extension classes for issuance.
 * The default policy permits propagation of Subject Alternative Name and
 * Extended Key Usage.
 */
#define QSC_X509_CERT_ISSUANCE_PROPAGATE_DEFAULT (QSC_X509_CERT_ISSUANCE_PROPAGATE_SUBJECT_ALT_NAME | QSC_X509_CERT_ISSUANCE_PROPAGATE_EXTENDED_KEY_USAGE)

/*!
 * \def QSC_X509_CERT_PROFILE_NONE
 * \brief No predefined issuance profile.
 *
 * \details
 * Indicates that no built-in profile constraints are requested.
 */
#define QSC_X509_CERT_PROFILE_NONE 0U

/*!
 * \def QSC_X509_CERT_PROFILE_ROOT_CA
 * \brief Predefined root CA certificate profile.
 *
 * \details
 * Selects the built-in root certification authority issuance profile.
 */
#define QSC_X509_CERT_PROFILE_ROOT_CA 1U

/*!
 * \def QSC_X509_CERT_PROFILE_INTERMEDIATE_CA
 * \brief Predefined intermediate CA certificate profile.
 *
 * \details
 * Selects the built-in intermediate certification authority issuance profile.
 */
#define QSC_X509_CERT_PROFILE_INTERMEDIATE_CA 2U

/*!
 * \def QSC_X509_CERT_PROFILE_TLS_SERVER
 * \brief Predefined TLS server certificate profile.
 *
 * \details
 * Selects the built-in end-entity TLS server issuance profile.
 */
#define QSC_X509_CERT_PROFILE_TLS_SERVER 3U

/*!
 * \def QSC_X509_CERT_PROFILE_TLS_CLIENT
 * \brief Predefined TLS client certificate profile.
 *
 * \details
 * Selects the built-in end-entity TLS client issuance profile.
 */
#define QSC_X509_CERT_PROFILE_TLS_CLIENT 4U

/*!
 * \brief Initialize a certificate builder instance.
 *
 * \details
 * Resets the builder to a clean default state suitable for certificate
 * construction. This function shall be called before any other builder
 * mutator is used on the object.
 *
 * \param builder: [struct] The certificate builder to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_certificate_builder_initialize(qsc_x509_certificate_builder* builder);

/*!
 * \brief Clear a certificate builder instance.
 *
 * \details
 * Clears all builder state and releases or resets any internally held
 * certificate-construction data. This function is used to erase or
 * reinitialize a builder after use.
 *
 * \param builder: [struct] The certificate builder to clear.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_certificate_builder_clear(qsc_x509_certificate_builder* builder);

/*!
 * \brief Set the certificate serial number.
 *
 * \details
 * Assigns the serial number that will be encoded into the certificate.
 * The caller supplies the serial number as a raw byte string.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param serialnumber: [const] The serial number byte array.
 * \param serialnumberlen: The length of the serial number in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or the
 * operation failure condition.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_serial(qsc_x509_certificate_builder* builder, const uint8_t* serialnumber, size_t serialnumberlen);

/*!
 * \brief Set the issuer distinguished name.
 *
 * \details
 * Copies the issuer name into the builder for later certificate encoding.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param issuer: [const][struct] The issuer distinguished name.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_issuer(qsc_x509_certificate_builder* builder, const qsc_x509_name* issuer);

/*!
 * \brief Set the subject distinguished name.
 *
 * \details
 * Copies the subject name into the builder for later certificate encoding.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param subject: [const][struct] The subject distinguished name.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_subject(qsc_x509_certificate_builder* builder, const qsc_x509_name* subject);

/*!
 * \brief Set the certificate validity interval.
 *
 * \details
 * Copies the not-before and not-after validity values into the builder. The interval is rejected when notBefore is later than notAfter.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param validity: [const][struct] The validity interval to apply.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_validity(qsc_x509_certificate_builder* builder, const qsc_x509_validity* validity);

/*!
 * \brief Set the subject public key information.
 *
 * \details
 * Assigns the SubjectPublicKeyInfo structure that identifies the public-key
 * algorithm and embeds the subject public key value.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param spki: [const][struct] The subject public key information structure.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_spki(qsc_x509_certificate_builder* builder, const qsc_x509_subject_public_key_info* spki);

/*!
 * \brief Set the certificate signature algorithm identifier.
 *
 * \details
 * Assigns the outer certificate signature algorithm identifier and the
 * corresponding TBSCertificate signature field used during signing.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param signaturealgorithm: [const][struct] The signature algorithm identifier.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_signature_algorithm(qsc_x509_certificate_builder* builder, const qsc_x509_algorithm_identifier* signaturealgorithm);

/*!
 * \brief Set the Basic Constraints extension content.
 *
 * \details
 * Applies a Basic Constraints extension definition to the builder.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param basicconstraints: [const][struct] The Basic Constraints value.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_basic_constraints(qsc_x509_certificate_builder* builder, const qsc_x509_basic_constraints* basicconstraints);

/*!
 * \brief Set the Key Usage extension content.
 *
 * \details
 * Applies a Key Usage extension definition to the builder.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param keyusage: [const][struct] The Key Usage value.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_key_usage(qsc_x509_certificate_builder* builder, const qsc_x509_key_usage* keyusage);

/*!
 * \brief Set the Extended Key Usage extension content.
 *
 * \details
 * Applies an Extended Key Usage extension definition to the builder.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param extendedkeyusage: [const][struct] The Extended Key Usage value.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_extended_key_usage(qsc_x509_certificate_builder* builder, const qsc_x509_extended_key_usage* extendedkeyusage);

/*!
 * \brief Set the Subject Key Identifier extension content.
 *
 * \details
 * Applies a Subject Key Identifier extension to the builder.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param subjectkeyidentifier: [const][struct] The Subject Key Identifier value.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_subject_key_identifier(qsc_x509_certificate_builder* builder, const qsc_x509_subject_key_identifier* subjectkeyidentifier);

/*!
 * \brief Set the Authority Key Identifier extension content.
 *
 * \details
 * Applies an Authority Key Identifier extension to the builder.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param authoritykeyidentifier: [const][struct] The Authority Key Identifier value.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_authority_key_identifier(qsc_x509_certificate_builder* builder, const qsc_x509_authority_key_identifier* authoritykeyidentifier);

/*!
 * \brief Add a DNS subject alternative name entry.
 *
 * \details
 * Appends a dNSName general-name entry to the Subject Alternative Name
 * extension content held by the builder.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param dnsname: [const] The DNS host name string.
 * \param dsnamelen: The length of the DNS host name string in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_add_subject_alt_name_dns(qsc_x509_certificate_builder* builder, const char* dnsname, size_t dsnamelen);

/*!
 * \brief Add an IP-address subject alternative name entry.
 *
 * \details
 * Appends an iPAddress general-name entry to the Subject Alternative Name
 * extension content held by the builder.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param address: [const] The binary IP address.
 * \param addresslen: The length of the IP address in bytes.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_add_subject_alt_name_ip(qsc_x509_certificate_builder* builder, const uint8_t* address, size_t addresslen);

/*!
 * \brief Add a raw extension to the builder.
 *
 * \details
 * Appends a caller-supplied extension object to the set of certificate
 * extensions being assembled by the builder.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param extension: [const][struct] The extension to add.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_add_extension(qsc_x509_certificate_builder* builder, const qsc_x509_extension* extension);

/*!
 * \brief Encode the TBSCertificate portion as DER.
 *
 * \details
 * Serializes the builder contents into the DER representation of the
 * TBSCertificate structure without applying a signature. The caller may pass
 * a null output buffer to query the required size through \p outputlen.
 *
 * \param builder: [const][struct] The source certificate builder.
 * \param output: The destination buffer receiving the DER encoding.
 * \param outputlen: The input capacity of \p output and, on success, the
 * number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_encode_tbs_der(const qsc_x509_certificate_builder* builder, uint8_t* output, size_t* outputlen);

/*!
 * \brief Sign and encode a complete certificate.
 *
 * \details
 * Encodes the TBSCertificate, invokes the caller-supplied signing callback
 * to produce the certificate signature, and then emits the final DER-encoded
 * Certificate structure.
 *
 * \param builder: [const][struct] The source certificate builder.
 * \param signcallback: The signing callback used to produce the certificate signature.
 * \param context: The opaque caller-defined signing context passed to the callback.
 * \param output: The destination buffer receiving the DER certificate.
 * \param outputlen: The input capacity of \p output and, on success, the
 * number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_sign(const qsc_x509_certificate_builder* builder, qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen);

/*!
 * \brief Validate a certificate signing request for issuance use.
 *
 * \details
 * Performs structural and issuance-related validation of a CSR before its
 * contents are used to generate a certificate.
 *
 * \param csr: [const][struct] The certificate signing request to validate.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_cert_issuance_validate_csr(const qsc_x509_csr* csr);

/*!
 * \brief Filter CSR-requested extensions under issuer policy.
 *
 * \details
 * Examines the requested CSR extensions and emits only those extensions
 * permitted by the supplied policy flag mask.
 *
 * \param csr: [const][struct] The source certificate signing request.
 * \param policyflags: The CSR extension propagation policy bitmask.
 * \param filteredextensions: [struct] The destination filtered extension set.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_cert_issuance_filter_requested_extensions(const qsc_x509_csr* csr, uint32_t policyflags, qsc_x509_extensions* filteredextensions);

/*!
 * \brief Apply CSR-requested extensions to a certificate builder.
 *
 * \details
 * Filters and copies CSR extensions into the certificate builder according
 * to the supplied issuance policy flags.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param csr: [const][struct] The source certificate signing request.
 * \param policyflags: The CSR extension propagation policy bitmask.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_cert_issuance_apply_csr_extensions(qsc_x509_certificate_builder* builder, const qsc_x509_csr* csr, uint32_t policyflags);

/*!
 * \brief Set the issuer name from an issuer certificate.
 *
 * \details
 * Extracts the issuer certificate subject name and applies it as the issuer
 * distinguished name of the certificate being built.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param issuer: [const][struct] The issuer certificate.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_set_issuer_from_certificate(qsc_x509_certificate_builder* builder, const qsc_x509_certificate* issuer);

/*!
 * \brief Compute a Subject Key Identifier from subject public key information.
 *
 * \details
 * Derives an SKI value from the supplied SubjectPublicKeyInfo structure and
 * stores the result in the destination identifier object.
 *
 * \param spki: [const][struct] The subject public key information source.
 * \param subjectkeyidentifier: [struct] The destination Subject Key Identifier.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_compute_subject_key_identifier(const qsc_x509_subject_public_key_info* spki, qsc_x509_subject_key_identifier* subjectkeyidentifier);

/*!
 * \brief Compute an Authority Key Identifier from an issuer certificate.
 *
 * \details
 * Derives an AKI value from the issuer certificate information and stores the
 * result in the destination identifier object.
 *
 * \param issuer: [const][struct] The issuer certificate.
 * \param authoritykeyidentifier: [struct] The destination Authority Key Identifier.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_compute_authority_key_identifier(const qsc_x509_certificate* issuer, qsc_x509_authority_key_identifier* authoritykeyidentifier);

/*!
 * \brief Apply generated key identifiers to the builder.
 *
 * \details
 * Computes and assigns identifier extensions derived from the subject public
 * key and, when supplied, the issuer certificate.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param issuer: [const][struct] The optional issuer certificate used for AKI derivation.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_apply_generated_identifiers(qsc_x509_certificate_builder* builder, const qsc_x509_certificate* issuer);

/*!
 * \brief Apply a predefined certificate profile to the builder.
 *
 * \details
 * Adjusts builder state to conform to a named built-in issuance profile such
 * as root CA, intermediate CA, TLS server, or TLS client.
 *
 * \param builder: [struct] The destination certificate builder.
 * \param profile: The predefined profile selector.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_apply_profile(qsc_x509_certificate_builder* builder, uint32_t profile);

/*!
 * \brief Validate builder contents against a predefined profile.
 *
 * \details
 * Checks whether the populated builder state is consistent with the selected
 * certificate profile and, when applicable, with the supplied issuer certificate.
 *
 * \param builder: [const][struct] The source certificate builder.
 * \param issuer: [const][struct] The optional issuer certificate.
 * \param profile: The predefined profile selector.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_builder_validate_profile(const qsc_x509_certificate_builder* builder, const qsc_x509_certificate* issuer, uint32_t profile);

/*!
 * \brief Encode a DER certificate into PEM.
 *
 * \details
 * Converts a DER-encoded certificate into the textual PEM representation,
 * including the BEGIN CERTIFICATE and END CERTIFICATE encapsulation markers.
 *
 * \param der: [const] The DER-encoded certificate input.
 * \param derlen: The length of the DER input in bytes.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of \p output and, on success, the
 * number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_certificate_encode_pem(const uint8_t* der, size_t derlen, char* output, size_t* outputlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
