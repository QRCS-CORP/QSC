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
#include "x509time.h"
#include "x509rev.h"

QSC_CPLUSPLUS_ENABLED_START

/*!
 * \file x509verify.h
 * \brief X.509 certificate and certification-path verification interface.
 *
 * \details
 * This header defines the status codes, callback types, verification-purpose selectors, option container, 
 * and helper functions used to validate X.509 certificates and certification chains. 
 * The interface supports algorithm consistency checks, validity-window evaluation, issuer relationship checks,
 * name and endpoint validation, CA and key-usage policy enforcement, signature verification through a caller-supplied callback, 
 * and optional revocation processing through the revocation subsystem.
 */

/*!
 * \enum qsc_x509_verify_status
 * \brief Certificate and chain verification result codes.
 */
typedef enum qsc_x509_verify_status_t
{
    QSC_X509_VERIFY_STATUS_SUCCESS = 0,                         /*!< Verification completed successfully. */
    QSC_X509_VERIFY_STATUS_INVALID_INPUT = 1,                   /*!< An input parameter was invalid. */
    QSC_X509_VERIFY_STATUS_INVALID_CERTIFICATE = 2,             /*!< The certificate structure was malformed or internally inconsistent. */
    QSC_X509_VERIFY_STATUS_ALGORITHM_MISMATCH = 3,              /*!< The certificate signature algorithm metadata was inconsistent or incompatible. */
    QSC_X509_VERIFY_STATUS_EXPIRED = 4,                         /*!< The certificate was expired at the evaluation time. */
    QSC_X509_VERIFY_STATUS_NOT_YET_VALID = 5,                   /*!< The certificate was not yet valid at the evaluation time. */
    QSC_X509_VERIFY_STATUS_ISSUER_MISMATCH = 6,                 /*!< The issuer certificate did not match the subject certificate issuer fields. */
    QSC_X509_VERIFY_STATUS_KEY_IDENTIFIER_MISMATCH = 7,         /*!< Authority and subject key identifiers did not match as required. */
    QSC_X509_VERIFY_STATUS_NOT_CA = 8,                          /*!< A certificate expected to act as a CA was not authorized as a certification authority. */
    QSC_X509_VERIFY_STATUS_PATH_LENGTH_EXCEEDED = 9,            /*!< A certification path length constraint was exceeded. */
    QSC_X509_VERIFY_STATUS_KEY_USAGE_REJECTED = 10,             /*!< Key usage or related policy constraints rejected the requested operation. */
    QSC_X509_VERIFY_STATUS_SIGNATURE_REJECTED = 11,             /*!< The certificate or chain signature verification failed. */
    QSC_X509_VERIFY_STATUS_TRUST_NOT_FOUND = 12,                /*!< No suitable trust anchor was found. */
    QSC_X509_VERIFY_STATUS_UNSUPPORTED = 13,                    /*!< A required algorithm, extension, or feature was unsupported. */
    QSC_X509_VERIFY_STATUS_CALLBACK_FAILURE = 14,               /*!< A caller-supplied callback failed to execute successfully. */
    QSC_X509_VERIFY_STATUS_UNSUPPORTED_CRITICAL_EXTENSION = 15, /*!< The certificate contained an unsupported critical extension. */
    QSC_X509_VERIFY_STATUS_PURPOSE_REJECTED = 16,               /*!< The certificate was not authorized for the requested verification purpose. */
    QSC_X509_VERIFY_STATUS_REVOKED = 17,                        /*!< The certificate was determined to be revoked. */
    QSC_X509_VERIFY_STATUS_REVOCATION_UNKNOWN = 18,             /*!< Certificate revocation status could not be determined. */
    QSC_X509_VERIFY_STATUS_CHAIN_LOOP = 19,                     /*!< A loop was detected during certification path processing. */
    QSC_X509_VERIFY_STATUS_NAME_MISMATCH = 20                   /*!< The certificate identity did not match the requested hostname or address. */
} qsc_x509_verify_status;

/*!
 * \typedef qsc_x509_signature_verify_callback
 * \brief Caller-supplied certificate signature verification callback.
 *
 * \details
 * This callback performs cryptographic verification of a subject certificate
 * signature using the supplied issuer certificate and caller-defined state.
 *
 * \param certificate: [const][struct] The certificate whose signature is to be verified.
 * \param issuer: [const][struct] The issuer certificate providing the verification key.
 * \param state: Caller-defined opaque verification context.
 *
 * \return Returns true if the certificate signature is valid; otherwise returns false.
 */
typedef bool (*qsc_x509_signature_verify_callback)(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, void* state);

/*!
 * \enum qsc_x509_verify_purpose
 * \brief Certificate usage-purpose selectors.
 */
typedef enum qsc_x509_verify_purpose_t
{
    QSC_X509_VERIFY_PURPOSE_GENERIC = 0,                        /*!< Apply generic certificate validation without a specialized application usage requirement. */
    QSC_X509_VERIFY_PURPOSE_TLS_SERVER = 1,                     /*!< Validate the certificate for use as a TLS server certificate. */
    QSC_X509_VERIFY_PURPOSE_TLS_CLIENT = 2                      /*!< Validate the certificate for use as a TLS client certificate. */
} qsc_x509_verify_purpose;

/*!
 * \struct qsc_x509_verify_options
 * \brief Optional controls for extended certificate and chain verification.
 *
 * \details
 * This structure carries the requested application purpose, optional
 * revocation-checking configuration, and a policy flag controlling whether
 * unsupported critical extensions cause verification failure.
 */
typedef struct qsc_x509_verify_options_t
{
    qsc_x509_verify_purpose purpose;                            /*!< The requested certificate usage purpose. */
    const qsc_x509_revocation_options* revocation;              /*!< Optional revocation-checking configuration, or NULL when revocation processing is not requested. */
    bool rejectunsupportedcriticalextensions;                   /*!< Reject certificates containing unsupported critical extensions when set to true. */
} qsc_x509_verify_options;

/*!
 * \brief Initialize a verification options structure.
 *
 * \details
 * Resets the verification options object to a clean default state suitable for
 * subsequent policy configuration.
 *
 * \param options: [struct] The verification options structure to initialize.
 *
 * \return [void] This function does not return a value.
 */
QSC_EXPORT_API void qsc_x509_verify_options_initialize(qsc_x509_verify_options* options);

/*!
 * \brief Test whether a certificate is self-issued.
 *
 * \details
 * Determines whether the certificate subject and issuer names are equivalent,
 * indicating that the certificate is self-issued.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 *
 * \return Returns true if the certificate is self-issued; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_is_self_issued(const qsc_x509_certificate* certificate);

/*!
 * \brief Test whether a certificate is self-signed.
 *
 * \details
 * Determines whether the certificate is self-issued and whether its signature
 * validates under its own subject public key through the caller-supplied
 * verification callback.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 * \param callback: The caller-supplied signature verification callback.
 * \param state: Caller-defined opaque verification context.
 *
 * \return Returns true if the certificate is self-signed; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_is_self_signed(const qsc_x509_certificate* certificate, qsc_x509_signature_verify_callback callback, void* state);

/*!
 * \brief Test whether a certificate is authorized to act as a CA.
 *
 * \details
 * Evaluates the Basic Constraints and related policy indicators to determine
 * whether the certificate may act as a certification authority.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 *
 * \return Returns true if the certificate is a CA certificate; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_is_ca(const qsc_x509_certificate* certificate);

/*!
 * \brief Test whether a certificate allows TLS server authentication.
 *
 * \details
 * Evaluates the certificate key usage and extended key usage constraints for
 * TLS server-auth applicability.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 *
 * \return Returns true if the certificate permits TLS server authentication; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_allows_server_auth(const qsc_x509_certificate* certificate);

/*!
 * \brief Test whether a certificate allows TLS client authentication.
 *
 * \details
 * Evaluates the certificate key usage and extended key usage constraints for
 * TLS client-auth applicability.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 *
 * \return Returns true if the certificate permits TLS client authentication; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_certificate_allows_client_auth(const qsc_x509_certificate* certificate);

/*!
 * \brief Check RFC-aligned certificate structural invariants.
 *
 * \details
 * Validates certificate-local structural rules that do not require issuer,
 * trust-store, or time context. This includes version and extension
 * compatibility, empty-subject handling, CA and key-usage coherence, and
 * subject public-key algorithm suitability.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_structure(const qsc_x509_certificate* certificate);

/*!
 * \brief Check certificate algorithm consistency.
 *
 * \details
 * Validates the internal consistency of certificate signature algorithm
 * metadata, signature encoding constraints, and related algorithm fields.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_algorithms(const qsc_x509_certificate* certificate);

/*!
 * \brief Check certificate validity at a supplied time.
 *
 * \details
 * Evaluates the certificate notBefore and notAfter fields relative to the
 * supplied evaluation time.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 * \param ascnow: [const][struct] The evaluation time.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_validity(const qsc_x509_certificate* certificate, const qsc_asn1_time* ascnow);

/*!
 * \brief Check certificate suitability for a requested purpose.
 *
 * \details
 * Evaluates the certificate against the requested application purpose,
 * including usage and purpose constraints where applicable.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 * \param purpose: [enum] The requested verification purpose.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_purpose(const qsc_x509_certificate* certificate, qsc_x509_verify_purpose purpose);

/*!
 * \brief Check whether a certificate matches a hostname.
 *
 * \details
 * Evaluates the certificate identity information against the supplied DNS host
 * name.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 * \param hostname: [const] The hostname to match.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_hostname(const qsc_x509_certificate* certificate, const char* hostname);

/*!
 * \brief Check whether a certificate matches an IP address.
 *
 * \details
 * Evaluates the certificate identity information against the supplied binary IP
 * address.
 *
 * \param certificate: [const][struct] The certificate to inspect.
 * \param address: [const] The binary IP address to match.
 * \param addresslen: The length of the IP address in bytes.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_ip_address(const qsc_x509_certificate* certificate, const uint8_t* address, size_t addresslen);

/*!
 * \brief Check whether one certificate may issue another.
 *
 * \details
 * Evaluates issuer-subject name relationships, CA status, path-length
 * constraints, and related issuer policy requirements. Authority key
 * identifiers are path-construction hints and are not treated as independent
 * certificate-validity requirements by this function.
 *
 * \param issuer: [const][struct] The candidate issuer certificate.
 * \param subject: [const][struct] The candidate subject certificate.
 * \param remainingdepth: The remaining allowable certification-path depth.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_check_issuer(const qsc_x509_certificate* issuer, const qsc_x509_certificate* subject, size_t remainingdepth);

/*!
 * \brief Verify a certificate against its issuer.
 *
 * \details
 * Performs core certificate validation, including algorithm checks, validity
 * checks, issuer relationship validation, and cryptographic signature
 * verification through the supplied callback.
 *
 * \param certificate: [const][struct] The certificate to verify.
 * \param issuer: [const][struct] The issuer certificate.
 * \param now: [const][struct] The evaluation time.
 * \param callback: The caller-supplied signature verification callback.
 * \param state: Caller-defined opaque verification context.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_verify(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer, const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state);

/*!
 * \brief Test whether a chain terminates at a trusted anchor.
 *
 * \details
 * Determines whether the supplied certification chain is anchored in the
 * provided trust store.
 *
 * \param chain: [const][struct] The certification chain to inspect.
 * \param store: [const][struct] The trust store containing candidate anchors.
 *
 * \return Returns true if the chain is trust-anchored; otherwise returns false.
 */
QSC_EXPORT_API bool qsc_x509_chain_is_anchored(const qsc_x509_chain* chain, const qsc_x509_store* store);

/*!
 * \brief Verify a certification chain.
 *
 * \details
 * Performs ordered validation of the certificates in the chain, checks that
 * the path terminates at a trust anchor in the supplied store, and applies
 * cryptographic signature verification through the caller-supplied callback.
 *
 * \param chain: [const][struct] The certification chain to verify.
 * \param store: [const][struct] The trust store containing candidate anchors.
 * \param now: [const][struct] The evaluation time.
 * \param callback: The caller-supplied signature verification callback.
 * \param state: Caller-defined opaque verification context.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_chain_verify(const qsc_x509_chain* chain, const qsc_x509_store* store, const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state);

/*!
 * \brief Verify a certificate against its issuer using extended options.
 *
 * \details
 * Performs certificate verification with additional policy controls, including
 * requested purpose validation, optional revocation processing, and optional
 * unsupported-critical-extension rejection.
 *
 * \param certificate: [const][struct] The certificate to verify.
 * \param issuer: [const][struct] The issuer certificate.
 * \param now: [const][struct] The evaluation time.
 * \param callback: The caller-supplied signature verification callback.
 * \param state: Caller-defined opaque verification context.
 * \param options: [const][struct] Optional extended verification controls.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_certificate_verify_ex(const qsc_x509_certificate* certificate, const qsc_x509_certificate* issuer,
    const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state, const qsc_x509_verify_options* options);

/*!
 * \brief Verify a certification chain using extended options.
 *
 * \details
 * Performs certification-path verification with additional policy controls,
 * including requested purpose validation, optional revocation processing, and
 * optional unsupported-critical-extension rejection.
 *
 * \param chain: [const][struct] The certification chain to verify.
 * \param store: [const][struct] The trust store containing candidate anchors.
 * \param now: [const][struct] The evaluation time.
 * \param callback: The caller-supplied signature verification callback.
 * \param state: Caller-defined opaque verification context.
 * \param options: [const][struct] Optional extended verification controls.
 *
 * \return [enum] Returns a qsc_x509_verify_status code.
 */
QSC_EXPORT_API qsc_x509_verify_status qsc_x509_chain_verify_ex(const qsc_x509_chain* chain, const qsc_x509_store* store,
    const qsc_asn1_time* now, qsc_x509_signature_verify_callback callback, void* state, const qsc_x509_verify_options* options);

QSC_CPLUSPLUS_ENABLED_END

#endif
