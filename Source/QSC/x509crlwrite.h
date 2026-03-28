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

#ifndef QSC_X509_CRLWRITE_H
#define QSC_X509_CRLWRITE_H

#include "qsccommon.h"
#include "x509crl.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509crlwrite.h
 * \brief X.509 certificate revocation list builder, signing, and PEM encoding interface.
 *
 * \details
 * This header declares the public interface used to construct, validate,
 * encode, sign, and PEM-convert X.509 Certificate Revocation Lists (CRLs).
 * The builder stores the issuer name, update times, signature algorithm,
 * optional CRL extensions, and a bounded list of revoked certificate entries.
 *
 * The interface supports generation of the TBSCertList DER payload, final
 * CertificateList signing through a caller supplied signing callback, and
 * conversion of either a DER encoded CRL or a decoded CRL object into PEM.
 */

/*!
 * \def QSC_X509_CRL_WRITE_MAX
 * \brief The maximum number of octets used by the CRL writer scratch buffers.
 *
 * \details
 * This constant defines the fixed upper bound used by internal CRL writing
 * routines when assembling temporary DER encodings during CRL generation.
 */
#define QSC_X509_CRL_WRITE_MAX 8192U

/*!
 * \struct qsc_x509_crl_builder
 * \brief A mutable certificate revocation list builder.
 *
 * \details
 * This structure stores the input state required to assemble an X.509 CRL.
 * The builder contains the CRL version, issuer distinguished name, update
 * time window, signature algorithm identifier, optional extension set, and
 * a bounded collection of revoked certificate entries.
 */
typedef struct qsc_x509_crl_builder_t
{
    uint32_t version;                                       /*!< The CRL version number. Version 2 is encoded as value 1 in DER. */
    qsc_x509_name issuer;                                   /*!< The CRL issuer distinguished name. */
    qsc_x509_validity validity;                             /*!< This update and next update times. */
    qsc_x509_algorithm_identifier signaturealgorithm;       /*!< The signature AlgorithmIdentifier. */
    qsc_x509_extensions extensions;                         /*!< Optional CRL extension set. */
    qsc_x509_crl_entry entries[QSC_X509_CRL_REVOKED_MAX];   /*!< Revoked certificate entries. */
    size_t entrycount;                                      /*!< The number of active revoked entries. */
} qsc_x509_crl_builder;

/*!
 * \brief Initialize a CRL builder.
 *
 * \details
 * Resets the CRL builder to a clean default state suitable for CRL
 * construction. This function shall be called before any other builder
 * mutator is used on the object.
 *
 * \param builder: [struct] The CRL builder to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_crl_builder_initialize(qsc_x509_crl_builder* builder);

/*!
 * \brief Clear a CRL builder.
 *
 * \details
 * Clears all builder state and resets any accumulated CRL construction data.
 * This function is used to erase or reinitialize a builder after use.
 *
 * \param builder: [struct] The CRL builder to clear.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_crl_builder_clear(qsc_x509_crl_builder* builder);

/*!
 * \brief Set the CRL issuer distinguished name.
 *
 * \details
 * Copies the issuer name into the builder for subsequent TBSCertList or
 * CertificateList encoding.
 *
 * \param builder: [struct] The destination CRL builder.
 * \param issuer: [const][struct] The issuer distinguished name.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_set_issuer(qsc_x509_crl_builder* builder, const qsc_x509_name* issuer);

/*!
 * \brief Set the CRL update times.
 *
 * \details
 * Assigns the thisUpdate and nextUpdate values that define the CRL validity
 * interval. The interval is rejected when thisUpdate is later than nextUpdate.
 *
 * \param builder: [struct] The destination CRL builder.
 * \param thisupdate: [const][struct] The CRL thisUpdate time.
 * \param nextupdate: [const][struct] The CRL nextUpdate time.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_set_update_times(qsc_x509_crl_builder* builder, const qsc_asn1_time* thisupdate, const qsc_asn1_time* nextupdate);

/*!
 * \brief Set the CRL signature algorithm identifier.
 *
 * \details
 * Assigns the AlgorithmIdentifier used in the TBSCertList signature field and
 * the outer CertificateList signature field when the CRL is signed.
 *
 * \param builder: [struct] The destination CRL builder.
 * \param signaturealgorithm: [const][struct] The signature AlgorithmIdentifier.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_set_signature_algorithm(qsc_x509_crl_builder* builder, const qsc_x509_algorithm_identifier* signaturealgorithm);

/*!
 * \brief Validate the builder issuer against an issuer certificate.
 *
 * \details
 * Checks that the builder issuer state is compatible with the supplied issuer
 * certificate before CRL signing or issuance.
 *
 * \param builder: [const][struct] The source CRL builder.
 * \param issuer: [const][struct] The issuer certificate expected to sign the CRL.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating validation success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_validate_issuer(const qsc_x509_crl_builder* builder, const qsc_x509_certificate* issuer);

/*!
 * \brief Add a revoked certificate entry by serial number.
 *
 * \details
 * Appends a revoked-certificate entry to the builder using the supplied
 * serial number and revocation date. Leading zero octets in the supplied serial
 * number are normalized before storage, and duplicate serial numbers are rejected.
 *
 * \param builder: [struct] The destination CRL builder.
 * \param serialnumber: [const] The revoked certificate serial number.
 * \param serialnumberlen: The length of the serial number in bytes.
 * \param revocationdate: [const][struct] The revocation date for the entry.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_add_revoked_serial(qsc_x509_crl_builder* builder, const uint8_t* serialnumber, size_t serialnumberlen, const qsc_asn1_time* revocationdate);

/*!
 * \brief Add a CRL extension to the builder.
 *
 * \details
 * Appends a caller supplied extension object to the set of CRL extensions
 * being assembled by the builder. Duplicate extension types or duplicate
 * extension object identifiers are rejected.
 *
 * \param builder: [struct] The destination CRL builder.
 * \param extension: [const][struct] The extension to add.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_add_extension(qsc_x509_crl_builder* builder, const qsc_x509_extension* extension);

/*!
 * \brief Encode the TBSCertList portion as DER.
 *
 * \details
 * Serializes the builder contents into the DER representation of the
 * TBSCertList structure without applying a signature. The caller may pass a
 * null output buffer to query the required size through \p outputlen.
 *
 * \param builder: [const][struct] The source CRL builder.
 * \param output: The destination buffer receiving the DER encoding.
 * \param outputlen: The input capacity of \p output and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_encode_tbs_der(const qsc_x509_crl_builder* builder, uint8_t* output, size_t* outputlen);

/*!
 * \brief Sign and encode a complete CRL.
 *
 * \details
 * Encodes the TBSCertList, invokes the caller supplied signing callback to
 * produce the CRL signature, and emits the final DER encoded CertificateList
 * structure.
 *
 * \param builder: [const][struct] The source CRL builder.
 * \param signcallback: The signing callback used to produce the CRL signature.
 * \param context: Caller defined opaque signing context passed to the callback.
 * \param output: The destination buffer receiving the DER encoded CRL.
 * \param outputlen: The input capacity of \p output and, on success, the number of bytes written.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_builder_sign(const qsc_x509_crl_builder* builder, qsc_x509_certificate_sign_callback signcallback, void* context, uint8_t* output, size_t* outputlen);

/*!
 * \brief Encode a DER CRL into PEM.
 *
 * \details
 * Converts a DER encoded CRL into textual PEM form including the BEGIN X509
 * CRL and END X509 CRL encapsulation markers.
 *
 * \param der: [const] The DER encoded CRL input.
 * \param derlen: The length of the DER input in bytes.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of \p output and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_der_encode_pem(const uint8_t* der, size_t derlen, char* output, size_t* outputlen);

/*!
 * \brief Encode a decoded CRL object into PEM.
 *
 * \details
 * Serializes a decoded CRL object and converts it into textual PEM form.
 * This function provides object-to-PEM conversion for CRL instances already
 * held in decoded representation.
 *
 * \param crl: [const][struct] The decoded CRL object.
 * \param output: The destination character buffer receiving the PEM text.
 * \param outputlen: The input capacity of \p output and, on success, the number of characters written.
 *
 * \return [enum] Returns a qsc_asn1_status code indicating success or failure.
 */
QSC_EXPORT_API qsc_asn1_status qsc_x509_crl_encode_pem(const qsc_x509_crl* crl, char* output, size_t* outputlen);

QSC_CPLUSPLUS_ENABLED_END

#endif
