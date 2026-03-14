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

#ifndef QSC_X509_VERIFY_H
#define QSC_X509_VERIFY_H

#include "qsccommon.h"
#include "x509types.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509_verify.h
 * \brief X.509 certificate verification helpers for the QSC X.509 layer.
 *
 * \details
 * This header defines the public API used to perform semantic checks over
 * decoded X.509 certificate objects. The verification layer is intentionally
 * split into two parts:
 *
 * 1. Structure and policy checks implemented entirely within the X.509 layer.
 * 2. Cryptographic signature verification delegated through a caller supplied
 *    callback so that the final binding can be aligned to the exact QSC
 *    asymmetric verification API selected by the integrator.
 *
 * The first pass implements the core rules needed for leaf and intermediate
 * certificate processing:
 *
 * - TBSCertificate and outer signature algorithm consistency checks.
 * - Validity interval evaluation.
 * - Issuer and subject name linkage checks.
 * - basicConstraints and keyUsage checks for certification authorities.
 * - AuthorityKeyIdentifier and SubjectKeyIdentifier linkage checks when both
 *   are present.
 * - Self-issued and self-signed classification.
 * - Ordered certificate path verification against a caller supplied trust store.
 */

/*!
 * \brief X.509 verification status codes.
 */
typedef enum qsc_x509_verify_status_t
{
	QSC_X509_VERIFY_STATUS_SUCCESS = 0,					/*!< Verification completed successfully. */
	QSC_X509_VERIFY_STATUS_INVALID_INPUT = 1,           /*!< One or more input arguments were invalid. */
	QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE = 2,     /*!< The certificate structure is malformed or incomplete. */
	QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH = 3,      /*!< The TBSCertificate and outer signature algorithms are inconsistent. */
	QSC_X509_VERIFY_STATUS_EXPIRED = 4,                 /*!< The certificate is not valid at the supplied evaluation time. */
	QSC_X509_VERIFY_STATUS_NOT_YET_VALID = 5,           /*!< The certificate validity interval has not begun. */
	QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH = 6,         /*!< The issuer and subject linkage failed. */
	QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH = 7, /*!< The authority and subject key identifiers did not match. */
	QSC_X509_VERIFY_STATUS_NOT_CA = 8,                  /*!< The issuer certificate is not a valid certification authority. */
	QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED = 9,    /*!< The certification path exceeded the issuer path length constraint. */
	QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED = 10,     /*!< The issuer keyUsage extension does not permit certificate signing. */
	QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED = 11,     /*!< Cryptographic signature verification failed. */
	QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND = 12,        /*!< No matching trust anchor was found in the trust store. */
	QSC_X509_VERIFY_STATUS_UNSUPPORTED = 13,            /*!< The requested operation or algorithm is not supported. */
	QSC_X509_VERIFY_STATUS_CALLBACK_FAILURE = 14        /*!< The caller supplied verification callback reported failure. */
} qsc_x509_verify_status;

/*!
 * \brief A caller supplied certificate signature verification callback.
 *
 * \details
 * The callback is invoked after the X.509 layer has completed structural
 * checks and algorithm consistency checks. The callback must verify the
 * signature over certificate->tbsdata using the issuer subject public key and
 * the signature metadata stored in the decoded certificate objects.
 *
 * \param certificate: [const qsc_x509_certificate*] The certificate being verified.
 * \param issuer: [const qsc_x509_certificate*] The certificate supplying the issuer public key.
 * \param state: [void*] Optional caller supplied context pointer.
 *
 * \return [bool] Returns true if the certificate signature is valid.
 */
typedef bool (*qsc_x509_signature_verify_callback)(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, void* state);

/*!
 * \brief Tests whether a decoded certificate is self-issued.
 *
 * \param certificate: [const qsc_x509_certificate*] The certificate object.
 *
 * \return [bool] Returns true if issuer and subject are equal.
 */
QSC_EXPORT_API bool qsc_x509_certificate_is_self_issued(const qsc_x509_certificate* certificate);

/*!
 * \brief Tests whether a decoded certificate is self-signed.
 *
 * \param certificate: [const qsc_x509_certificate*] The certificate object.
 * \param callback: [qsc_x509_signature_verify_callback] The signature verification callback.
 * \param state: [void*] Optional caller supplied callback state.
 *
 * \return [bool] Returns true if the certificate is self-issued and the
 * signature callback validates the certificate.
 */
QSC_EXPORT_API bool qsc_x509_certificate_is_self_signed(const qsc_x509_certificate* certificate, qsc_x509_signature_verify_callback callback, void* state);

/*!
 * \brief Tests whether a decoded certificate is a certification authority.
 *
 * \param certificate: [const qsc_x509_certificate*] The certificate object.
 *
 * \return [bool] Returns true if the certificate is permitted to sign child certificates.
 */
QSC_EXPORT_API bool qsc_x509_certificate_is_ca(const qsc_x509_certificate* certificate);

/*!
 * \brief Checks the internal signature algorithm consistency of a certificate.
 *
 * \param certificate: [const qsc_x509_certificate*] The certificate object.
 *
 * \return [qsc_x509_verify_status] Returns QSC_X509_VERIFY_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_algorithms(const qsc_x509_certificate* certificate);

/*!
 * \brief Checks a certificate validity interval against an evaluation time.
 *
 * \param certificate: [const qsc_x509_certificate*] The certificate object.
 * \param now: [const qsc_asn1_time*] The evaluation time.
 *
 * \return [qsc_x509_verify_status] Returns QSC_X509_VERIFY_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_validity(const qsc_x509_certificate* certificate, const qsc_asn1_time* now);

/*!
 * \brief Checks whether an issuer certificate can issue a given subject certificate.
 *
 * \param issuer: [const qsc_x509_certificate*] The issuer certificate.
 * \param subject: [const qsc_x509_certificate*] The subject certificate.
 * \param remainingdepth: [size_t] The remaining number of non-self-issued CA certificates below the issuer.
 *
 * \return [qsc_x509_verify_status] Returns QSC_X509_VERIFY_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_issuer(const qsc_x509_certificate* issuer, const qsc_x509_certificate* subject, size_t remainingdepth);

/*!
 * \brief Verifies a single certificate signature and issuer linkage.
 *
 * \param certificate: [const qsc_x509_certificate*] The certificate being verified.
 * \param issuer: [const qsc_x509_certificate*] The issuer certificate.
 * \param now: [const qsc_asn1_time*] The evaluation time.
 * \param callback: [qsc_x509_signature_verify_callback] The signature verification callback.
 * \param state: [void*] Optional caller supplied callback state.
 *
 * \return [qsc_x509_verify_status] Returns QSC_X509_VERIFY_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_verify(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state);

/*!
 * \brief Verifies an ordered certificate chain against a trust store.
 *
 * \details
 * The chain must be ordered from leaf certificate at index zero to the highest
 * untrusted intermediate at index count - 1. The trust store is searched for a
 * trust anchor that can issue the final certificate in the chain.
 *
 * \param chain: [const qsc_x509_chain*] The ordered certificate chain.
 * \param store: [const qsc_x509_store*] The trust anchor store.
 * \param now: [const qsc_asn1_time*] The evaluation time.
 * \param callback: [qsc_x509_signature_verify_callback] The signature verification callback.
 * \param state: [void*] Optional caller supplied callback state.
 *
 * \return [qsc_x509_verify_status] Returns QSC_X509_VERIFY_STATUS_SUCCESS on success.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_chain_verify(const qsc_x509_chain* chain, const qsc_x509_store* store, const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state);

QSC_CPLUSPLUS_ENABLED_END

#endif
